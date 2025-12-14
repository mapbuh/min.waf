import socket
from typing import Any
import pytest
from unittest.mock import MagicMock
from classes.Proxy import Proxy
from classes.Config import Config
from classes.RunTimeStats import RunTimeStats


class TestMinProxy:
    @pytest.fixture
    def config(self):
        return Config("test.conf")

    @pytest.fixture
    def rts(self, config: Config):
        return RunTimeStats(config)

    @pytest.fixture
    def proxy(self, config: Config, rts: RunTimeStats):
        # Avoid running __init__ loop
        instance = Proxy.__new__(Proxy)
        instance.config = config
        instance.rts = rts
        return instance

    def test_proxy_handle_client_basic(self, proxy: Proxy, monkeypatch: pytest.MonkeyPatch):

        class DummySocket(socket.socket):
            def __init__(self, request: bytes):
                self.request = request
                self.recv_calls = 0
                self.closed = False

            def recv(self, buff_size: int, flags: int = 0) -> bytes:
                self.recv_calls += 1

                if self.recv_calls == 1:
                    return self.request
                return b''

            def close(self):
                self.closed = True

            def fileno(self):
                return 10

        class UpstreamSocket:
            def __init__(self, *args: Any, **kwargs: Any):
                self.closed = False

            def sendall(self, data: bytes):
                pass

            def close(self):
                self.closed = True

            def connect(self, addr: tuple[str, int]):
                print(f"Connecting to {addr}")

            def fileno(self) -> int:
                return 11

            def recv(self, buff_size: int) -> bytes:
                return b'123'

            def send(self, data: bytes) -> int:
                return len(data)

        dummy_socket = DummySocket(b'GET / HTTP/1.1\r\nX-Real-IP: 1.2.3.4\r\nHost: example.com\r\n\r\n')
        proxy.proxy_handle_client(dummy_socket, ('127.0.0.1', 12345))
        assert dummy_socket.recv_calls > 0
        assert dummy_socket.closed

        dummy_socket = DummySocket(
            b'GET / HTTP/1.1\r\n'
            b'X-Real-IP: 1.2.3.4\r\n'
            b'Host: example.com\r\n'
            b'MinWaf-Dest: localhost:12346\r\n'
        )
        # Monkeypatch socket.socket to use UpstreamSocket for upstream connections
        monkeypatch.setattr('socket.socket', UpstreamSocket)

    def test_init_socket_loop(self, config: Config, rts: RunTimeStats, monkeypatch: pytest.MonkeyPatch):
        # Patch socket to avoid real network
        mock_socket = MagicMock()
        monkeypatch.setattr(socket, "socket", lambda *a: mock_socket)
        mock_socket.accept.side_effect = KeyboardInterrupt  # Stop after one loop
        # Should not raise
        Proxy(config, rts, lambda: None, lambda: None)
