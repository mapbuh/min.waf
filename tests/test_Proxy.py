import pytest
import socket
from unittest.mock import MagicMock, patch
from classes.Proxy import MinProxy
from classes.Config import Config
from classes.RunTimeStats import RunTimeStats

def test_minproxy_init(monkeypatch: pytest.MonkeyPatch):
    # Patch socket methods to avoid real network calls
    mock_socket = MagicMock()
    monkeypatch.setattr('socket.socket', lambda *a, **kw: mock_socket)
    mock_socket.accept.side_effect = KeyboardInterrupt  # Stop after one loop
    config = Config()
    rts = RunTimeStats(config)
    # Should not raise
    MinProxy(config, rts)

def test_proxy_upstream_send(monkeypatch):
    config = Config()
    rts = RunTimeStats(config)
    proxy = MinProxy.__new__(MinProxy)  # Don't call __init__
    proxy.config = config
    proxy.rts = rts
    # Mock socket
    mock_socket = MagicMock(spec=socket.socket)
    # Test data
    buffer = b"GET /index.php?cmd=ls HTTP/1.1\r\nHost: test\r\n\r\n"
    request_whole = buffer
    request_clean_upto = 0
    # Call the method
    proxy.upstream_send(mock_socket, buffer, request_whole, request_clean_upto, config.longest_signature)
    # Check that send was called
    assert mock_socket.send.called

"""
def test_proxy_handle_client_basic(monkeypatch):
    config = Config()
    rts = RunTimeStats(config)
    proxy = MinProxy.__new__(MinProxy)  # Don't call __init__
    proxy.config = config
    proxy.rts = rts
    # Mock socket
    mock_socket = MagicMock(spec=socket.socket)
    mock_socket.recv.side_effect = [b'GET / HTTP/1.1\r\nHost: test\r\n\r\n', b'']
    # Patch dependencies
    monkeypatch.setattr('classes.Proxy.Config.inspect_packets', False)
    monkeypatch.setattr('classes.Proxy.LogLine', MagicMock())
    monkeypatch.setattr('classes.Proxy.Nginx.process_line', MagicMock(return_value=None))
    proxy.proxy_handle_client(mock_socket, ('127.0.0.1', 12345))
    assert mock_socket.recv.called
    assert mock_socket.close.called
"""