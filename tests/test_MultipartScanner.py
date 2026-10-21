from classes.MultipartScanner import MultipartScanner


BODY = (
    b'--xyz\r\n'
    b'Content-Disposition: form-data; name="a"\r\n'
    b'\r\n'
    b'value\r\n'
    b'--xyz\r\n'
    b'content-disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
    b'\r\n'
    b'1\r\n'
    b'--xyz--\r\n'
)


def feed_bytewise(scanner: MultipartScanner, data: bytes) -> list[bytes]:
    headers: list[bytes] = []
    for i in range(len(data)):
        headers += scanner.feed(data[i:i + 1])
    return headers


def test_finds_part_headers():
    assert MultipartScanner().feed(BODY) == [
        b'Content-Disposition: form-data; name="a"',
        b'content-disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"',
    ]


def test_finds_part_headers_split_across_feeds():
    assert feed_bytewise(MultipartScanner(), BODY) == MultipartScanner().feed(BODY)


def test_folded_header_is_joined_like_php():
    body = (
        b'--xyz\n'
        b'Content-Disposition: form-data; name="PHP_SESSION_UP\n'
        b'LOAD_PROGRESS"\n'
        b'\n'
    )
    headers = MultipartScanner().feed(body)
    assert b'name="PHP_SESSION_UPLOAD_PROGRESS"' in headers[-1]
    headers = feed_bytewise(MultipartScanner(), body)
    assert b'name="PHP_SESSION_UPLOAD_PROGRESS"' in headers[-1]


def test_whitespace_continuation_with_colon():
    body = b'Content-Disposition: form-data;\r\n\tname="x:PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    assert b'\tname="x:PHP_SESSION_UPLOAD_PROGRESS"' in MultipartScanner().feed(body)[-1]


def test_header_after_large_padding():
    padding = b'--xyz\r\nContent-Disposition: form-data; name="pad"\r\n\r\n' + b'A' * 100_000 + b'\r\n'
    tail = b'--xyz\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    scanner = MultipartScanner()
    headers: list[bytes] = []
    data = padding + tail
    for i in range(0, len(data), 8192):
        headers += scanner.feed(data[i:i + 8192])
    assert headers[-1] == b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'


def test_ignores_other_lines():
    body = b'Content-Type: text/plain\r\nX-Content-Disposition: no\r\n\r\nContent-Disposition without colon\r\n'
    assert MultipartScanner().feed(body) == []
