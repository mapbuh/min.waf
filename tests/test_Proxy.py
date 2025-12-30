import pytest
import socket
from unittest.mock import MagicMock
from classes.Proxy import Proxy
from classes.Config import Config
from classes.RunTimeStats import RunTimeStats


class DummySocket(socket.socket):
    def __init__(self, recv_data):
        self._recv_data = recv_data
        self._recv_calls = 0
        self.closed = False
        self.setblocking_called = False

    def recv(self, bufsize):
        if self._recv_calls < len(self._recv_data):
            data = self._recv_data[self._recv_calls]
            self._recv_calls += 1
            return data
        return b''

    def setblocking(self, flag):
        self.setblocking_called = True

    def close(self):
        self.closed = True

    def fileno(self):
        return 10

def test_proxy_handle_client_basic(monkeypatch: pytest.MonkeyPatch):
    config = Config("test.conf")
    rts = RunTimeStats(config)
    proxy = Proxy.__new__(Proxy)
    proxy.config = config
    proxy.rts = rts

    # Patch dependencies
    monkeypatch.setattr("classes.Proxy.Checks.headers", lambda *a, **kw: True)
    monkeypatch.setattr("classes.Proxy.Checks.content", lambda *a, **kw: True)
    monkeypatch.setattr("classes.Proxy.Proxy.connect_upstream", lambda self, headers: DummySocket([b'']))
    monkeypatch.setattr("classes.Proxy.Proxy.forward", lambda *a, **kw: None)
    monkeypatch.setattr("classes.Proxy.Proxy.read_headers", lambda *a, **kw: None)
    monkeypatch.setattr("classes.Proxy.Proxy.parse_headers", lambda *a, **kw: MagicMock(ip="127.0.0.1"))

    dummy_socket = DummySocket([b'GET / HTTP/1.1\r\nHost: test\r\n\r\n', b''])
    proxy.proxy_handle_client(dummy_socket, ("127.0.0.1", 12345))
    assert dummy_socket.setblocking_called
    assert dummy_socket.closed is False  # Should not close if forward is True

def test_proxy_handle_client_ban(monkeypatch):

    config = Config("test.conf")
    rts = RunTimeStats(config)
    proxy = Proxy.__new__(Proxy)
    proxy.config = config
    proxy.rts = rts
    # Monkeypatch mode_honeypot property to always return False
    monkeypatch.setattr(type(config), "mode_honeypot", property(lambda self: False))

    # Patch dependencies to force ban
    monkeypatch.setattr("classes.Proxy.Checks.headers", lambda *a, **kw: False)
    monkeypatch.setattr("classes.Proxy.Checks.content", lambda *a, **kw: False)
    monkeypatch.setattr("classes.Proxy.Proxy.ban", lambda *a, **kw: None)
    monkeypatch.setattr("classes.Proxy.Proxy.read_headers", lambda *a, **kw: None)
    monkeypatch.setattr("classes.Proxy.Proxy.parse_headers", lambda *a, **kw: MagicMock(ip="127.0.0.1"))

    dummy_socket = DummySocket([b'GET / HTTP/1.1\r\nHost: test\r\n\r\n', b''])
    proxy.proxy_handle_client(dummy_socket, ("127.0.0.1", 12345))
    assert dummy_socket.closed  # Should close if not forward and not honeypot

def test_proxy_handle_client_complex(monkeypatch: pytest.MonkeyPatch):
    request: list[bytes] = [
        b"GET /today HTTP/3\r\n",
        b"Host: offnews.bg\r\n",
        b"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0\r\n",
        b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
        b"Accept-Language: en-US,en;q=0.7,bg;q=0.3\r\n",
        b"Accept-Encoding: gzip, deflate, br, zstd\r\n",
        b"DNT: 1\r\n",
        b"Alt-Used: offnews.bg\r\n",
        b"Connection: keep-alive\r\n",
        b"Cookie: a=b; X=Y\r\n",
        b"Upgrade-Insecure-Requests: 1\r\n",
        b"Sec-Fetch-Dest: document\r\n",
        b"Sec-Fetch-Mode: navigate\r\n",
        b"Sec-Fetch-Site: none\r\n",
        b"Sec-Fetch-User: ?1\r\n",
        b"Priority: u=0, i\r\n",
        b"\r\n"
    ]
    dummy_socket = DummySocket(request)
    proxy = Proxy.__new__(Proxy)
    config = Config("test.conf")
    rts = RunTimeStats(config)
    proxy.config = config
    proxy.rts = rts
    proxy.proxy_handle_client(dummy_socket, ("127.0.0.1", 12345))