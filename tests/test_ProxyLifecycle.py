import time
import select
import socket
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest

from classes.Config import Config
from classes.HttpHeaders import HttpHeaders
from classes.Proxy import Proxy
from classes.RequestInspector import RequestInspector


@pytest.fixture
def proxy(monkeypatch):
    monkeypatch.setattr("classes.Config.BotWhitelist.load", lambda *args: None)
    instance = Proxy.__new__(Proxy)
    instance.config = Config('test.conf')
    instance.config.config.set('main', 'connection_idle_timeout', '0.02')
    instance.rts = MagicMock()
    # the test clients do not close after the response, so the lingering
    # close would wait its full time
    monkeypatch.setattr(Proxy, 'linger_time', 0.1)
    return instance


def prepare_handler(proxy, monkeypatch, frontend, upstream):
    monkeypatch.setattr(proxy, 'read_headers', lambda *args: b'GET / HTTP/1.1\r\n\r\n')
    monkeypatch.setattr(proxy, 'parse_headers', lambda *args: HttpHeaders())
    monkeypatch.setattr(proxy, 'connect_upstream', lambda *args: upstream)
    monkeypatch.setattr('classes.Proxy.Checks.headers', lambda *args: True)
    monkeypatch.setattr('classes.Proxy.Checks.content', lambda *args, **kwargs: (True, 0))
    monkeypatch.setattr('classes.Proxy.Checks.headers_with_status', lambda *args: True)


@pytest.mark.parametrize('failure', [None, ValueError('invalid response'), BrokenPipeError()])
def test_handler_closes_both_sockets(proxy, monkeypatch, failure):
    frontend, upstream = MagicMock(), MagicMock()
    prepare_handler(proxy, monkeypatch, frontend, upstream)
    relay = MagicMock(side_effect=failure)
    monkeypatch.setattr(proxy, 'forward', relay)
    proxy.proxy_handle_client(frontend, ('127.0.0.1', 1234))
    relay.assert_called_once()
    frontend.close.assert_called_once()
    upstream.close.assert_called_once()


@pytest.mark.parametrize('event', [select.POLLHUP, select.POLLERR, select.POLLOUT])
def test_disconnected_frontend_releases_worker(proxy, monkeypatch, event):
    frontend, upstream = MagicMock(), MagicMock()
    frontend.fileno.return_value = 10
    upstream.fileno.return_value = 11
    frontend.send.side_effect = BrokenPipeError()
    poller = MagicMock()
    poller.__enter__.return_value = poller
    # A second poll means the disconnected client's worker was retained.
    poller.poll.side_effect = [[(10, event)], AssertionError('worker still waiting')]
    monkeypatch.setattr('classes.Proxy.select.epoll', lambda: poller)
    proxy.forward(HttpHeaders(), frontend, b'', upstream, b'response', b'', RequestInspector(proxy.config, HttpHeaders()))
    poller.poll.assert_called_once()
    poller.__exit__.assert_called_once()


def test_poller_closed_when_relay_raises(proxy, monkeypatch):
    frontend, upstream = MagicMock(), MagicMock()
    frontend.fileno.return_value = 10
    upstream.fileno.return_value = 11
    upstream.send.side_effect = BrokenPipeError()
    poller = MagicMock()
    poller.__enter__.return_value = poller
    poller.poll.return_value = [(11, select.POLLOUT)]
    monkeypatch.setattr('classes.Proxy.select.epoll', lambda: poller)
    with pytest.raises(BrokenPipeError):
        proxy.forward(HttpHeaders(), frontend, b'request', upstream, b'', b'', RequestInspector(proxy.config, HttpHeaders()))
    poller.__exit__.assert_called_once()


def test_idle_connections_do_not_accumulate_workers(proxy, monkeypatch):
    # Reuse the same worker for multiple stalled connections with real epoll.
    with ThreadPoolExecutor(max_workers=1) as executor:
        for _ in range(5):
            frontend, client = socket.socketpair()
            upstream, server = socket.socketpair()
            with frontend, client, upstream, server:
                upstream.setblocking(False)
                prepare_handler(proxy, monkeypatch, frontend, upstream)
                future = executor.submit(proxy.proxy_handle_client, frontend, ('local', 0))
                future.result(timeout=1)
                assert frontend.fileno() == -1
                assert upstream.fileno() == -1
        assert executor.submit(lambda: 'available').result(timeout=1) == 'available'


def test_buffered_response_delivered_before_close(proxy, monkeypatch):
    frontend, client = socket.socketpair()
    upstream, server = socket.socketpair()
    with frontend, client, upstream, server, ThreadPoolExecutor(max_workers=1) as executor:
        upstream.setblocking(False)
        client.settimeout(1)
        prepare_handler(proxy, monkeypatch, frontend, upstream)
        response = b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello'
        server.sendall(response)
        server.shutdown(socket.SHUT_WR)
        future = executor.submit(proxy.proxy_handle_client, frontend, ('local', 0))
        received = b''
        while chunk := client.recv(8192):
            received += chunk
        future.result(timeout=1)
        assert received == response
        assert upstream.fileno() == -1


def test_malformed_status_line_relayed_without_traceback(proxy, monkeypatch, caplog):
    # a non-numeric upstream status must not kill the relay with an exception
    frontend, client = socket.socketpair()
    upstream, server = socket.socketpair()
    with frontend, client, upstream, server, ThreadPoolExecutor(max_workers=1) as executor:
        upstream.setblocking(False)
        prepare_handler(proxy, monkeypatch, frontend, upstream)
        response = b'HTTP/1.1 WTF NOT FOUND\r\nContent-Length: 2\r\n\r\nhi'
        server.sendall(response)
        server.shutdown(socket.SHUT_WR)
        future = executor.submit(proxy.proxy_handle_client, frontend, ('local', 0))
        received = b''
        while chunk := client.recv(8192):
            received += chunk
        future.result(timeout=1)
        assert 'Error handling connection' not in caplog.text
        assert upstream.fileno() == -1


def test_client_data_while_draining_upstream_close(proxy, monkeypatch):
    # the client can keep sending while a large response is still draining
    # after the upstream closed; that must not touch the closed upstream fd
    frontend, client = socket.socketpair()
    upstream, server = socket.socketpair()
    with frontend, client, upstream, server, ThreadPoolExecutor(max_workers=3) as executor:
        upstream.setblocking(False)
        prepare_handler(proxy, monkeypatch, frontend, upstream)
        proxy.config.config.set('main', 'connection_idle_timeout', '5')
        body = b'x' * (8 * 1024 * 1024)  # bigger than socket buffers, so draining stalls
        response = b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n' % len(body) + body
        future = executor.submit(proxy.proxy_handle_client, frontend, ('local', 0))

        def serve():
            server.sendall(response)
            server.shutdown(socket.SHUT_WR)

        def keep_sending():
            # client data pending past the upstream EOF; the relay reads and
            # drops it once the upstream is closed, and closes the client
            # after the response, which may cut this send short
            try:
                client.sendall(b'GET /more HTTP/1.1\r\n' * 50000)
            except (BrokenPipeError, ConnectionResetError):
                pass

        served = executor.submit(serve)
        sending = executor.submit(keep_sending)
        received = b''
        client.settimeout(5)
        while chunk := client.recv(8192):
            received += chunk
        served.result(timeout=5)
        future.result(timeout=5)
        sending.result(timeout=5)
        assert received == response
        assert upstream.fileno() == -1


def test_relay_buffers_at_most_max_buffer(proxy, monkeypatch):
    # a fast upstream and a client that does not read: the relay stops
    # reading the upstream instead of holding the whole response in memory
    frontend, client = socket.socketpair()
    upstream, server = socket.socketpair()
    with frontend, client, upstream, server, ThreadPoolExecutor(max_workers=2) as executor:
        upstream.setblocking(False)
        server.setblocking(False)
        prepare_handler(proxy, monkeypatch, frontend, upstream)
        proxy.config.config.set('main', 'connection_idle_timeout', '0.5')
        monkeypatch.setattr(Proxy, 'max_buffer', 64 * 1024)
        future = executor.submit(proxy.proxy_handle_client, frontend, ('local', 0))
        pushed = server.send(b'HTTP/1.1 200 OK\r\n\r\n')
        chunk = b'x' * 65536
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                pushed += server.send(chunk)
            except BlockingIOError:
                time.sleep(0.05)
            except BrokenPipeError:
                break  # the relay ended on the idle timeout
        future.result(timeout=5)  # ends on the idle timeout
        # the upstream could push socket buffers plus max_buffer, not everything
        assert pushed < 32 * 1024 * 1024


@pytest.mark.parametrize('failure', [TimeoutError(), socket.gaierror(), OSError('unreachable')])
def test_connect_failure_closes_socket(proxy, monkeypatch, failure):
    upstream = MagicMock()
    upstream.connect.side_effect = failure
    monkeypatch.setattr('classes.Proxy.socket.socket', lambda *args: upstream)
    if isinstance(failure, TimeoutError):
        assert proxy.connect_upstream(HttpHeaders()) is None
    else:
        with pytest.raises(OSError):
            proxy.connect_upstream(HttpHeaders())
    upstream.settimeout.assert_called_once_with(10)
    upstream.close.assert_called_once()


def test_header_hangup_returns_without_spinning(proxy, monkeypatch):
    frontend = MagicMock()
    frontend.fileno.return_value = 10
    poller = MagicMock()
    poller.__enter__.return_value = poller
    poller.poll.side_effect = [[(10, select.EPOLLHUP)], AssertionError('busy loop')]
    monkeypatch.setattr('classes.Proxy.select.epoll', lambda: poller)
    assert proxy.read_headers(frontend, b'') == b''
    frontend.close.assert_called_once()


def test_trickled_headers_cannot_hold_worker_indefinitely(proxy, monkeypatch):
    frontend = MagicMock()
    frontend.fileno.return_value = 10
    frontend.recv.return_value = b'G'
    poller = MagicMock()
    poller.__enter__.return_value = poller
    poller.poll.return_value = [(10, select.EPOLLIN)]
    monkeypatch.setattr('classes.Proxy.select.epoll', lambda: poller)
    # Bytes arrive, but the overall header deadline still expires.
    monkeypatch.setattr('classes.Proxy.time.monotonic', MagicMock(side_effect=[0, 1, 6]))
    assert proxy.read_headers(frontend, b'') == b'G'
    frontend.close.assert_called_once()
    poller.poll.assert_called_once_with(4)


def test_temporary_write_backpressure_preserves_response(proxy, monkeypatch):
    frontend, upstream = MagicMock(), MagicMock()
    frontend.fileno.return_value = 10
    upstream.fileno.return_value = 11
    results = [BlockingIOError(), len(b'response')]
    sent = []

    def send(data):
        # the relay buffer is a bytearray emptied after the send: keep a copy
        sent.append(bytes(data))
        result = results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    frontend.send.side_effect = send
    poller = MagicMock()
    poller.__enter__.return_value = poller
    poller.poll.side_effect = [[(10, select.POLLOUT)], [(10, select.POLLOUT)], []]
    monkeypatch.setattr('classes.Proxy.select.epoll', lambda: poller)
    proxy.forward(HttpHeaders(), frontend, b'', upstream, b'response', b'', RequestInspector(proxy.config, HttpHeaders()))
    assert sent == [b'response', b'response']


def test_periodic_callbacks_survive_failures(monkeypatch):
    # the callbacks run on their own thread; one failing must not end min.waf
    import threading
    monkeypatch.setattr(Proxy, 'periodic_interval', 0.01)
    calls = []
    stop = threading.Event()

    def failing():
        calls.append(1)
        if len(calls) >= 3:
            stop.set()
        raise RuntimeError('blacklist is not utf-8')

    hourly = MagicMock()
    thread = threading.Thread(target=Proxy.periodic, args=(failing, hourly, stop))
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert len(calls) == 3
    hourly.assert_not_called()


def test_periodic_runs_hourly_callback(monkeypatch):
    import threading
    monkeypatch.setattr(Proxy, 'periodic_interval', 0.01)
    clock = [0.0]
    monkeypatch.setattr('classes.Proxy.time.monotonic', lambda: clock[0])
    stop = threading.Event()

    def tick():
        clock[0] += 1800

    def hourly():
        stop.set()

    hourly_mock = MagicMock(side_effect=hourly)
    thread = threading.Thread(target=Proxy.periodic, args=(tick, hourly_mock, stop))
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive()
    hourly_mock.assert_called_once()


def test_linger_close_drains_client_data_before_closing():
    # closing with unread client data would send a reset, which can make the
    # client drop the end of the response
    sock, peer = socket.socketpair()
    with peer:
        sock.setblocking(False)
        peer.sendall(b'late client data')
        peer.shutdown(socket.SHUT_WR)
        Proxy.linger_close(sock)
        assert sock.fileno() == -1
        assert peer.recv(10) == b''  # a normal close, not a reset
