import pytest

from classes.Config import Config
from classes.HttpHeaders import HttpHeaders
from classes.ResponseInspector import ResponseInspector


@pytest.fixture
def config(monkeypatch) -> Config:
    monkeypatch.setattr("classes.Config.BotWhitelist.load", lambda *args: None)
    return Config("test.conf")


HEAD = b'HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=%s; path=/\r\nContent-Length: 2\r\n\r\n'


def run(config: Config, chunks: list[bytes]) -> tuple[bool, bytes, HttpHeaders]:
    http_headers = HttpHeaders(ip="10.0.0.1")
    inspector = ResponseInspector(config, http_headers)
    released = b''
    for chunk in chunks + [b'']:
        clean, out = inspector.feed(chunk)
        if not clean:
            return False, released, http_headers
        released += out
    return True, released, http_headers


def test_clean_response_is_released_whole(config):
    response = HEAD % b'abc123,-' + b'ok'
    clean, released, _ = run(config, [response[i:i + 5] for i in range(0, len(response), 5)])
    assert clean
    assert released == response


def test_head_is_held_until_complete(config):
    inspector = ResponseInspector(config, HttpHeaders())
    assert inspector.feed(b'HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=a') == (True, b'')
    assert inspector.feed(b'bc\r\n\r\nok') == (True, b'HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=abc\r\n\r\nok')
    assert inspector.feed(b'more') == (True, b'more')


def test_long_session_cookie_is_dropped(config):
    clean, released, http_headers = run(config, [HEAD % (b'a' * 257) + b'ok'])
    assert not clean
    assert released == b''
    assert http_headers.status == HttpHeaders.STATUS_BAD
    assert http_headers.ban_reason == "Session cookie phpsessid too long: 257 > 256"


def test_encoded_session_cookie_is_dropped(config):
    clean, _, http_headers = run(config, [HEAD % b'ab%00%ffcd' + b'ok'])
    assert not clean
    assert "invalid characters" in http_headers.ban_reason


def test_oversized_head_is_checked_without_its_end(config):
    # a leaked cookie bigger than max_head is still caught from the held part
    head = b'HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=' + b'a' * 70_000
    clean, released, _ = run(config, [head[i:i + 8192] for i in range(0, len(head), 8192)])
    assert not clean
    assert released == b''


def test_other_cookies_are_ignored(config):
    response = b'HTTP/1.1 200 OK\r\nSet-Cookie: other=' + b'%' * 500 + b'\r\n\r\nok'
    assert run(config, [response])[:2] == (True, response)


def test_session_cookie_name_is_configurable(config):
    config.config.set('main', 'session_cookies', '\nMYSESS')
    response = (HEAD % (b'a' * 300)).replace(b'PHPSESSID', b'mysess')
    assert not run(config, [response])[0]
    assert run(config, [HEAD % (b'a' * 300)])[0]


def test_interim_response_does_not_hide_final_head(config):
    response = b'HTTP/1.1 100 Continue\r\n\r\n' + HEAD % (b'a' * 300)
    clean, released, _ = run(config, [response])
    assert not clean
    assert released == b''


def test_interim_response_is_released_early(config):
    inspector = ResponseInspector(config, HttpHeaders())
    assert inspector.feed(b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200') == (True, b'HTTP/1.1 100 Continue\r\n\r\n')


def test_whitelisted_request_passes(config):
    http_headers = HttpHeaders()
    http_headers.status = HttpHeaders.STATUS_GOOD
    inspector = ResponseInspector(config, http_headers)
    response = HEAD % (b'a' * 300)
    assert inspector.feed(response) == (True, response)


def test_disabled_length_check(config):
    config.config.set('main', 'session_cookie_max_length', '0')
    assert run(config, [HEAD % (b'a' * 300)])[0]
