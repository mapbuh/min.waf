import pytest

from classes.Config import Config
from classes.HttpHeaders import HttpHeaders
from classes.RequestInspector import RequestInspector


@pytest.fixture
def config(monkeypatch) -> Config:
    monkeypatch.setattr("classes.Config.BotWhitelist.load", lambda *args: None)
    return Config("test.conf")


def inspect(config: Config, chunks: list[bytes]) -> tuple[bool, HttpHeaders]:
    http_headers = HttpHeaders(ip="10.0.0.1", host="example.com", path="/upload.php")
    inspector = RequestInspector(config, http_headers)
    for chunk in chunks:
        if not inspector.feed(chunk):
            return False, http_headers
    return True, http_headers


def multipart_head(extra: bytes = b'') -> bytes:
    return (
        b'POST /upload.php HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Type: multipart/form-data; boundary=xyz\r\n'
        + extra +
        b'\r\n'
    )


def part(name: bytes, value: bytes) -> bytes:
    return b'--xyz\r\nContent-Disposition: form-data; name="' + name + b'"\r\n\r\n' + value + b'\r\n'


def in_chunks(data: bytes, size: int = 8192) -> list[bytes]:
    return [data[i:i + size] for i in range(0, len(data), size)]


def test_clean_multipart_upload_passes(config):
    # file data past max_inspect_size is not matched, only part headers are
    body = part(b'title', b'hello') + part(b'file', b'A' * 100_000 + b'\r\nexec(1)\r\n') + b'--xyz--\r\n'
    clean, http_headers = inspect(config, in_chunks(multipart_head() + body))
    assert clean
    assert http_headers.status == HttpHeaders.STATUS_NEUTRAL


def test_upload_progress_field_is_blocked(config):
    body = part(b'PHP_SESSION_UPLOAD_PROGRESS', b'1')
    clean, http_headers = inspect(config, [multipart_head() + body])
    assert not clean
    assert http_headers.status == HttpHeaders.STATUS_BAD


def test_upload_progress_field_after_padding_is_blocked(config):
    body = part(b'pad', b'A' * 100_000) + part(b'PHP_SESSION_UPLOAD_PROGRESS', b'1')
    clean, http_headers = inspect(config, in_chunks(multipart_head() + body))
    assert not clean
    assert 'multipart header' in http_headers.ban_reason


def test_folded_upload_progress_field_is_blocked(config):
    body = b'--xyz\r\nContent-Disposition: form-data; name="PHP_SESSION_UP\r\nLOAD_PROGRESS"\r\n\r\n1\r\n'
    clean, _ = inspect(config, [multipart_head() + body])
    assert not clean


def test_chunked_split_signature_is_blocked(config):
    config.config.set('main', 'multipart_block_chunked', 'False')
    head = multipart_head(b'Transfer-Encoding: chunked\r\n')
    field = part(b'PHP_SESSION_UPLOAD_PROGRESS', b'1')
    split = field.index(b'_UPLOAD')
    body = b''
    for piece in (field[:split], field[split:]):
        body += b'%x\r\n' % len(piece) + piece + b'\r\n'
    body += b'0\r\n\r\n'
    clean, _ = inspect(config, [head, body])
    assert not clean


def test_chunked_non_multipart_signature_is_blocked(config):
    head = b'POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n'
    body = b'4\r\nshel\r\n6\r\nl_exec\r\n2\r\n(1\r\n0\r\n\r\n'
    clean, _ = inspect(config, [head + body])
    assert not clean


def test_large_non_multipart_body_is_not_inspected_past_limit(config):
    head = b'POST / HTTP/1.1\r\nHost: example.com\r\n\r\n'
    body = b'A' * 100_000 + b'exec('
    clean, _ = inspect(config, in_chunks(head + body))
    assert clean


def test_whitelisted_request_passes(config):
    http_headers = HttpHeaders(ip="10.0.0.1")
    http_headers.status = HttpHeaders.STATUS_GOOD
    inspector = RequestInspector(config, http_headers)
    assert inspector.feed(multipart_head() + part(b'PHP_SESSION_UPLOAD_PROGRESS', b'1'))


def test_chunked_multipart_is_blocked(config):
    head = multipart_head(b'Transfer-Encoding: chunked\r\n')
    field = part(b'title', b'hello')
    body = b'%x\r\n' % len(field) + field + b'\r\n0\r\n\r\n'
    clean, http_headers = inspect(config, [head, body])
    assert not clean
    assert http_headers.ban_reason == "Chunked multipart request"


def test_chunked_multipart_passes_when_allowed(config):
    config.config.set('main', 'multipart_block_chunked', 'False')
    head = multipart_head(b'Transfer-Encoding: chunked\r\n')
    field = part(b'title', b'hello')
    body = b'%x\r\n' % len(field) + field + b'\r\n0\r\n\r\n'
    clean, _ = inspect(config, [head, body])
    assert clean


def test_too_many_parts_is_blocked(config):
    body = part(b'a[]', b'1') * 1001
    clean, http_headers = inspect(config, in_chunks(multipart_head() + body))
    assert not clean
    assert http_headers.ban_reason == "Too many multipart parts: 1001 > 1000"


def test_parts_limit_can_be_disabled(config):
    config.config.set('main', 'multipart_max_parts', '0')
    body = part(b'a[]', b'1') * 1001 + b'--xyz--\r\n'
    clean, _ = inspect(config, in_chunks(multipart_head() + body))
    assert clean


def test_too_many_part_headers_is_blocked(config):
    body = b'--xyz\r\nContent-Disposition: form-data; name="a"\r\n' + b'A: 1\r\n' * 16
    clean, http_headers = inspect(config, in_chunks(multipart_head() + body, 100))
    assert not clean
    assert http_headers.ban_reason == "Too many multipart headers in a part: 17 > 16"


def test_deep_nesting_is_blocked(config):
    body = part(b'a' + b'[]' * 17, b'1')
    clean, http_headers = inspect(config, [multipart_head() + body])
    assert not clean
    assert http_headers.ban_reason == "Too many multipart nesting in a part header: 17 > 16"


def test_too_many_empty_files_is_blocked(config):
    empty = b'--xyz\r\nContent-Disposition: form-data; name="f[]"; filename=""\r\n\r\n\r\n'
    clean, _ = inspect(config, [multipart_head() + empty * 20 + b'--xyz--\r\n'])
    assert clean
    clean, http_headers = inspect(config, [multipart_head() + empty * 21])
    assert not clean
    assert http_headers.ban_reason == "Too many multipart empty file parts: 21 > 20"


def test_limits_apply_past_max_inspect_size(config):
    body = part(b'file', b'A' * 100_000) + part(b'a' + b'[]' * 17, b'1')
    clean, _ = inspect(config, in_chunks(multipart_head() + body))
    assert not clean


def test_long_part_header_is_blocked(config):
    body = part(b'A' * 9000, b'1')
    clean, http_headers = inspect(config, in_chunks(multipart_head() + body))
    assert not clean
    assert http_headers.ban_reason.startswith("Multipart header longer than")


def test_quoted_boundary_is_used(config):
    head = (
        b'POST /upload.php HTTP/1.1\r\n'
        b'Content-Type: multipart/form-data; boundary="xyz"\r\n'
        b'\r\n'
    )
    clean, _ = inspect(config, [head + part(b'a' + b'[]' * 17, b'1')])
    assert not clean


def test_whitelisted_request_skips_limits(config):
    http_headers = HttpHeaders(ip="10.0.0.1")
    http_headers.status = HttpHeaders.STATUS_GOOD
    inspector = RequestInspector(config, http_headers)
    assert inspector.feed(multipart_head(b'Transfer-Encoding: chunked\r\n') + part(b'a' + b'[]' * 17, b'1'))


def urlencoded_head() -> bytes:
    return (
        b'POST / HTTP/1.1\r\n'
        b'Host: example.com\r\n'
        b'Content-Type: application/x-www-form-urlencoded\r\n'
        b'\r\n'
    )


def test_long_urlencoded_array_name_is_blocked(config):
    # the name runs far past max_inspect_size
    body = b'a=1&name[' + b'x' * 100_000 + b']=1'
    clean, http_headers = inspect(config, in_chunks(urlencoded_head() + body))
    assert not clean
    assert http_headers.ban_reason.startswith("Urlencoded array field name too long: ")


def test_long_urlencoded_plain_value_passes(config):
    body = b'name[x]=' + b'x' * 100_000
    clean, _ = inspect(config, in_chunks(urlencoded_head() + body))
    assert clean


def test_long_urlencoded_array_name_passes_when_disabled(config):
    config.config.set('main', 'urlencoded_max_name_length', '0')
    body = b'name[' + b'x' * 100_000
    clean, _ = inspect(config, in_chunks(urlencoded_head() + body))
    assert clean


def test_long_array_name_without_urlencoded_type_passes(config):
    head = b'POST / HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n'
    clean, _ = inspect(config, in_chunks(head + b'[' + b'x' * 100_000))
    assert clean


@pytest.mark.parametrize('filename', [b'<?php phpinfo(); ?>.jpg', b'a|O:8:"stdClass":0:{}', b'x|c:3:"Foo"'])
def test_harmful_upload_filename_is_blocked(config, filename):
    body = (
        part(b'pad', b'A' * 100_000)
        + b'--xyz\r\nContent-Disposition: form-data; name="f"; filename="' + filename + b'"\r\n\r\ndata\r\n'
    )
    clean, http_headers = inspect(config, in_chunks(multipart_head() + body))
    assert not clean
    assert 'upload filename' in http_headers.ban_reason


def test_harmless_upload_filename_passes(config):
    body = b'--xyz\r\nContent-Disposition: form-data; name="f"; filename="a|b.txt"\r\n\r\n<?php echo 1;\r\n--xyz--\r\n'
    clean, _ = inspect(config, [multipart_head() + body])
    assert clean
