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
#        class DummyNginxSocket:
#            def __init__(self):
#                self.closed = False
#            def sendall(self, data):
#                pass
#            def close(self):
#                self.closed = True
#        monkeypatch.setattr('classes.Proxy.Nginx.create_nginx_socket', lambda self,

        class DummySocket:
            def __init__(self, request: bytes):
                self.request = request
                self._recv_calls = 0
                self.closed = False

            def recv(self, buff_size):
                self._recv_calls += 1

                if self._recv_calls == 1:
                    return self.request
                return b''
            def close(self):
                self.closed = True
            def fileno(self):
                return 10
            
        class UpstreamSocket:
            def __init__(self, *args, **kwargs):
                self.closed = False
            def sendall(self, data):
                pass
            def close(self):
                self.closed = True
            def connect(self, addr):
                print(f"Connecting to {addr}")
            def fileno(self):
                return 11
            def recv(self, buff_size):
                return b'123'
            def send(self, data):
                return b'321'


        dummy_socket = DummySocket(b'GET / HTTP/1.1\r\nX-Real-IP: 1.2.3.4\r\nHost: example.com\r\n\r\n')
        proxy.proxy_handle_client(dummy_socket, ('127.0.0.1', 12345))
        assert dummy_socket._recv_calls > 0
        assert dummy_socket.closed

        dummy_socket = DummySocket(b'GET / HTTP/1.1\r\nX-Real-IP: 1.2.3.4\r\nHost: example.com\r\nMinWaf-Dest: localhost:12346\r\n')
        # Monkeypatch socket.socket to use UpstreamSocket for upstream connections
        monkeypatch.setattr('socket.socket', UpstreamSocket)


    def test_init_socket_loop(self, config, rts, monkeypatch):
        # Patch socket to avoid real network
        mock_socket = MagicMock()
        monkeypatch.setattr('socket.socket', lambda *a, **kw: mock_socket)
        mock_socket.accept.side_effect = KeyboardInterrupt  # Stop after one loop
        # Should not raise
        Proxy(config, rts)
