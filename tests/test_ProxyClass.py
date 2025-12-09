import pytest
import socket
from unittest.mock import MagicMock, patch
from classes.Proxy import Proxy
from classes.Config import Config
from classes.RunTimeStats import RunTimeStats

class TestMinProxy:
    @pytest.fixture
    def config(self):
        return Config("test.conf")

    @pytest.fixture
    def rts(self, config):
        return RunTimeStats(config)

    @pytest.fixture
    def proxy(self, config, rts):
        # Avoid running __init__ loop
        instance = Proxy.__new__(Proxy)
        instance.config = config
        instance.rts = rts
        return instance

    def test_proxy_handle_client_basic(self, proxy, monkeypatch):
        class DummySocket:
            def __init__(self):
                self._recv_calls = 0
                self.closed = False
            def recv(self, buff_size):
                self._recv_calls += 1
                if self._recv_calls == 1:
                    return b'GET / HTTP/1.1\r\nHost: test\r\n\r\n'
                return b''
            def close(self):
                self.closed = True
            def fileno(self):
                return 1
        dummy_socket = DummySocket()
        monkeypatch.setattr('classes.Proxy.Config.inspect_packets', False)
        monkeypatch.setattr('classes.Proxy.LogLine', lambda data: None)
        monkeypatch.setattr('classes.Proxy.Nginx.process_line', lambda *a, **kw: None)
        proxy.proxy_handle_client(dummy_socket, ('127.0.0.1', 12345))
        assert dummy_socket._recv_calls > 0
        assert dummy_socket.closed

    def test_init_socket_loop(self, config, rts, monkeypatch):
        # Patch socket to avoid real network
        mock_socket = MagicMock()
        monkeypatch.setattr('socket.socket', lambda *a, **kw: mock_socket)
        mock_socket.accept.side_effect = KeyboardInterrupt  # Stop after one loop
        # Should not raise
        Proxy(config, rts)
