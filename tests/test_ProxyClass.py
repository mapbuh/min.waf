import socket
import threading
from unittest.mock import MagicMock

import pytest

from classes.Config import Config
from classes.Proxy import Proxy
from classes.RunTimeStats import RunTimeStats


RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'


class TestMinProxy:
    @pytest.fixture
    def config(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("classes.Config.BotWhitelist.load", lambda *args: {})
        config = Config("test.conf")
        config.config.set('main', 'ip_blacklist', '')
        config.config.set('main', 'connection_idle_timeout', '2')
        return config

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

    @pytest.fixture
    def upstream(self):
        """A one-shot upstream app that records the request and answers RESPONSE."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.settimeout(5)
        received: list[bytes] = []

        def serve():
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(5)
                data = b''
                while b'\r\n\r\n' not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                received.append(data)
                conn.sendall(RESPONSE)

        thread = threading.Thread(target=serve)
        thread.start()
        yield server.getsockname()[1], received
        # wakes up accept() when the proxy never connected
        server.shutdown(socket.SHUT_RDWR)
        server.close()
        thread.join()

    @staticmethod
    def handle(proxy: Proxy, request: bytes) -> bytes:
        client, frontend = socket.socketpair()
        with client:
            client.sendall(request)
            proxy.proxy_handle_client(frontend, ('127.0.0.1', 12345))
            client.settimeout(5)
            response = b''
            while chunk := client.recv(4096):
                response += chunk
        assert frontend.fileno() == -1
        return response

    def test_request_is_relayed_to_upstream(self, proxy: Proxy, upstream):
        port, received = upstream
        request = (
            b'GET /index.php HTTP/1.1\r\n'
            b'X-Real-IP: 1.2.3.4\r\n'
            b'Host: example.com\r\n'
            b'MinWaf-Dest: 127.0.0.1:%d\r\n'
            b'\r\n' % port
        )
        assert self.handle(proxy, request) == RESPONSE
        assert received == [request]
        assert "1.2.3.4" not in proxy.rts.banned_ips

    def test_harmful_request_is_banned_and_not_relayed(self, proxy: Proxy, upstream):
        port, received = upstream
        request = (
            b'GET /index.php?cmd=shell_exec(id) HTTP/1.1\r\n'
            b'X-Real-IP: 1.2.3.4\r\n'
            b'Host: example.com\r\n'
            b'MinWaf-Dest: 127.0.0.1:%d\r\n'
            b'\r\n' % port
        )
        assert self.handle(proxy, request) == b''
        assert received == []
        assert "1.2.3.4" in proxy.rts.banned_ips

    def test_unreachable_upstream_closes_client(self, proxy: Proxy):
        request = (
            b'GET / HTTP/1.1\r\n'
            b'X-Real-IP: 1.2.3.4\r\n'
            b'Host: example.com\r\n'
            b'MinWaf-Dest: 127.0.0.1:1\r\n'
            b'\r\n'
        )
        assert self.handle(proxy, request) == b''

    def test_init_socket_loop(self, config: Config, rts: RunTimeStats, monkeypatch: pytest.MonkeyPatch):
        # Patch socket to avoid real network
        mock_socket = MagicMock()
        monkeypatch.setattr(socket, "socket", lambda *a: mock_socket)
        mock_socket.accept.side_effect = KeyboardInterrupt  # Stop after one loop
        # Should not raise
        Proxy(config, rts, lambda: None, lambda: None)
