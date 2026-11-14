import pytest
from unittest.mock import MagicMock
from classes.Proxy import Proxy
from classes.Config import Config
from classes.HttpHeaders import HttpHeaders
from classes.RunTimeStats import RunTimeStats


REQUEST = b'GET / HTTP/1.1\r\nHost: test\r\n\r\n'


class DummySocket:
    def __init__(self):
        self.closed = False
        self.setblocking_called = False
        self.sent = b''

    def sendall(self, data):
        self.sent += data

    def setblocking(self, flag):
        self.setblocking_called = True

    def close(self):
        self.closed = True

    def fileno(self):
        return -1 if self.closed else 10


@pytest.fixture
def proxy(monkeypatch: pytest.MonkeyPatch) -> Proxy:
    monkeypatch.setattr("classes.Config.BotWhitelist.load", lambda *args: {})
    config = Config("test.conf")
    config.config.set('main', 'ip_blacklist', '')
    instance = Proxy.__new__(Proxy)
    instance.config = config
    instance.rts = RunTimeStats(config)
    monkeypatch.setattr(instance, "read_headers", lambda *a, **kw: REQUEST)
    monkeypatch.setattr(instance, "parse_headers", lambda *a, **kw: HttpHeaders(ip="127.0.0.1"))
    return instance


def test_proxy_handle_client_basic(proxy: Proxy, monkeypatch: pytest.MonkeyPatch):
    upstream = DummySocket()
    forward = MagicMock()
    monkeypatch.setattr("classes.Proxy.Checks.headers", lambda *a, **kw: True)
    monkeypatch.setattr("classes.Proxy.RequestInspector.feed", lambda *a, **kw: True)
    monkeypatch.setattr(proxy, "connect_upstream", lambda headers: upstream)
    monkeypatch.setattr(proxy, "forward", forward)

    dummy_socket = DummySocket()
    proxy.proxy_handle_client(dummy_socket, ("127.0.0.1", 12345))
    assert dummy_socket.setblocking_called
    forward.assert_called_once()
    assert forward.call_args.args[1] is dummy_socket
    assert forward.call_args.args[3] is upstream
    assert forward.call_args.args[5] == REQUEST
    # both sockets are closed once the relay is done
    assert dummy_socket.closed
    assert upstream.closed


@pytest.mark.parametrize("headers_clean, content_clean", [(False, True), (True, False)])
def test_proxy_handle_client_ban(proxy: Proxy, monkeypatch: pytest.MonkeyPatch, headers_clean, content_clean):
    ban = MagicMock()
    connect_upstream = MagicMock()
    monkeypatch.setattr("classes.Proxy.Checks.headers", lambda *a, **kw: headers_clean)
    monkeypatch.setattr("classes.Proxy.RequestInspector.feed", lambda *a, **kw: content_clean)
    monkeypatch.setattr(proxy, "ban", ban)
    monkeypatch.setattr(proxy, "connect_upstream", connect_upstream)

    monkeypatch.setattr(Proxy, "linger_close", staticmethod(lambda sock: sock.close()))
    dummy_socket = DummySocket()
    proxy.proxy_handle_client(dummy_socket, ("127.0.0.1", 12345))
    assert dummy_socket.sent == Proxy.forbidden
    ban.assert_called_once()
    assert ban.call_args.args[0] == "127.0.0.1"
    connect_upstream.assert_not_called()
    assert dummy_socket.closed  # a rejected request is closed without forwarding


def test_parse_headers_complex():
    request = (
        b"GET /today HTTP/3\r\n"
        b"Host: offnews.bg:443\r\n"
        b"X-Real-IP: 1.2.3.4\r\n"
        b"MinWaf-Dest: http://127.0.0.1:8080\r\n"
        b"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0\r\n"
        b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        b"Referer: https://offnews.bg/\r\n"
        b"Connection: keep-alive\r\n"
        b"Cookie: a=b; X=Y\r\n"
        b"Priority: u=0, i\r\n"
        b"\r\n"
    )
    proxy = Proxy.__new__(Proxy)
    headers = proxy.parse_headers(DummySocket(), request)
    assert (headers.method, headers.path, headers.proto) == ("GET", "/today", "HTTP/3")
    assert headers.host == "offnews.bg"
    assert headers.ip == "1.2.3.4"
    assert (headers.upstream_host, headers.upstream_port) == ("127.0.0.1", 8080)
    assert headers.ua.startswith("Mozilla/5.0 (X11")
    assert headers.referer == "https://offnews.bg/"


def test_parse_headers_invalid_values():
    request = b"GET / HTTP/1.1\r\nX-Real-IP: not-an-ip\r\nMinWaf-Dest: app:99999\r\n\r\n"
    headers = Proxy.__new__(Proxy).parse_headers(DummySocket(), request)
    assert headers.ip == ""
    assert (headers.upstream_host, headers.upstream_port) == ("app", 80)


def test_parse_headers_lowercase_names():
    # header names are case-insensitive per RFC 9110
    request = (
        b"GET /today HTTP/1.1\r\n"
        b"host: offnews.bg\r\n"
        b"x-real-ip: 1.2.3.4\r\n"
        b"minwaf-dest: 127.0.0.1:8080\r\n"
        b"user-agent: python-requests\r\n"
        b"referer: https://offnews.bg/\r\n"
        b"\r\n"
    )
    headers = Proxy.__new__(Proxy).parse_headers(DummySocket(), request)
    assert headers.host == "offnews.bg"
    assert headers.ip == "1.2.3.4"
    assert (headers.upstream_host, headers.upstream_port) == ("127.0.0.1", 8080)
    assert headers.ua == "python-requests"
    assert headers.referer == "https://offnews.bg/"


def test_close_after_response_replaces_connection_headers():
    request = (
        b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n'
        b'keep-alive: timeout=5\r\nX-Real-IP: 1.2.3.4\r\n\r\nbody'
    )
    assert Proxy.close_after_response(request) == (
        b'GET / HTTP/1.1\r\nHost: example.com\r\nX-Real-IP: 1.2.3.4\r\nConnection: close\r\n\r\nbody'
    )


def test_close_after_response_adds_connection_close():
    assert Proxy.close_after_response(b'GET / HTTP/1.0\r\nHost: a\r\n\r\n') == (
        b'GET / HTTP/1.0\r\nHost: a\r\nConnection: close\r\n\r\n'
    )
    # bare LF requests keep their line endings
    assert Proxy.close_after_response(b'GET / HTTP/1.0\nHost: a\n\n') == (
        b'GET / HTTP/1.0\nHost: a\nConnection: close\n\n'
    )


def test_close_after_response_keeps_upgrades_and_partial_heads():
    upgrade = b'GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
    assert Proxy.close_after_response(upgrade) == upgrade
    partial = b'GET / HTTP/1.1\r\nConnection: keep-alive\r\n'
    assert Proxy.close_after_response(partial) == partial


@pytest.mark.parametrize('response, status', [
    (b'HTTP/1.1 200 OK\r\n', 200),
    (b'HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n', 200),  # no reason phrase
    (b'HTTP/1.0 404\n', 404),
    (b'HTTP/2 302 Found\r\n', 302),
    (b'HTTP/1.1 abc OK\r\n', -1),
    (b'garbage\r\n', -1),
    (b'HTTP/1.1 200 OK', None),  # status line not complete yet
    # interim responses are skipped until the final one arrives
    (b'HTTP/1.1 100 Continue\r\n\r\n', None),
    (b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\n', 201),
    (b'HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 404 Not Found\r\n', 404),
    (b'HTTP/1.1 101 Switching Protocols\r\n\r\n', 101),
])
def test_response_status(response, status):
    assert Proxy.response_status(response) == status


def test_response_status_gives_up_after_max_head():
    from classes.ResponseInspector import ResponseInspector
    response = b'HTTP/1.1 100 Continue\r\n' + b'X: y\r\n' * (ResponseInspector.max_head // 6 + 1)
    assert Proxy.response_status(response) == -1
