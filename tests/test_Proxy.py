import pytest
from classes.Proxy import MinProxy
from classes.Config import Config
from classes.RunTimeStats import RunTimeStats


def test_proxy_inspect(monkeypatch: pytest.MonkeyPatch):
    config = Config()
    rts = RunTimeStats(config)
    proxy = MinProxy.__new__(MinProxy)  # Don't call __init__
    proxy.config = config
    proxy.rts = rts

    # ok data
    payload = '{ "name": "Ahmet", "email": "ahmet@example.com", "password": "123456" }'
    content_length = len(str(payload).encode())
    buffer: bytes = (
        "POST /api/add-user HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "\r\n\r\n"
        f"{payload}"
    ).encode()
    request_whole: bytes = buffer
    request_clean_upto = 0
    # Call the method
    result: bool = proxy.is_safe(request_whole, request_clean_upto)
    assert isinstance(result, bool)
    assert result is True

    # sql inject in post data
    payload = '{ "name": "Ahmet", "email": "ahmet@example.com", "password": "DROP TABLE" }'
    content_length = len(str(payload).encode())
    buffer: bytes = (
        "POST /api/add-user HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "\r\n\r\n"
        f"{payload}"
    ).encode()
    request_whole: bytes = buffer
    request_clean_upto = 0
    # Call the method
    result: bool = proxy.is_safe(request_whole, request_clean_upto)
    assert isinstance(result, bool)
    assert result is False

    # sql inject in get data
    buffer: bytes = (
        "GET /api/add-user?payload=DROP%20TABLE HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "\r\n\r\n"
        f"{payload}"
    ).encode()
    request_whole: bytes = buffer
    request_clean_upto = 0
    # Call the method
    result: bool = proxy.is_safe(request_whole, request_clean_upto)
    assert isinstance(result, bool)
    assert result is False

    # sql inject in get data, case insensitive
    buffer: bytes = (
        "GET /api/add-user?payload=DrOp%20TaBlE HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "\r\n\r\n"
        f"{payload}"
    ).encode()
    request_whole: bytes = buffer
    request_clean_upto = 0
    # Call the method
    result: bool = proxy.is_safe(request_whole, request_clean_upto)
    assert isinstance(result, bool)
    assert result is False


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
