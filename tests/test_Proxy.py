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
    # Monkeypatch mode_honeypot property to always return False
    monkeypatch.setattr(type(proxy.config), "mode_honeypot", property(lambda self: False))
    ban = MagicMock()
    connect_upstream = MagicMock()
    monkeypatch.setattr("classes.Proxy.Checks.headers", lambda *a, **kw: headers_clean)
    monkeypatch.setattr("classes.Proxy.RequestInspector.feed", lambda *a, **kw: content_clean)
    monkeypatch.setattr(proxy, "ban", ban)
    monkeypatch.setattr(proxy, "connect_upstream", connect_upstream)

    dummy_socket = DummySocket()
    proxy.proxy_handle_client(dummy_socket, ("127.0.0.1", 12345))
    ban.assert_called_once()
    assert ban.call_args.args[0] == "127.0.0.1"
    connect_upstream.assert_not_called()
    assert dummy_socket.closed  # Should close if not forward and not honeypot


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
