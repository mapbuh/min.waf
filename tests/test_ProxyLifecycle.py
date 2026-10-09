import select
import socket
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest

from classes.Config import Config
from classes.HttpHeaders import HttpHeaders
from classes.Proxy import Proxy


@pytest.fixture
def proxy(monkeypatch):
    monkeypatch.setattr("classes.Config.BotWhitelist.load", lambda *args: None)
    instance = Proxy.__new__(Proxy)
    instance.config = Config('test.conf')
    instance.config.config.set('main', 'connection_idle_timeout', '0.02')
    instance.rts = MagicMock()
    return instance


def prepare_handler(proxy, monkeypatch, frontend, upstream):
    monkeypatch.setattr(proxy, 'read_headers', lambda *args: b'GET / HTTP/1.1\r\n\r\n')
    monkeypatch.setattr(proxy, 'parse_headers', lambda *args: HttpHeaders())
    monkeypatch.setattr(proxy, 'connect_upstream', lambda *args: upstream)
    monkeypatch.setattr('classes.Proxy.Checks.headers', lambda *args: True)
    monkeypatch.setattr('classes.Proxy.Checks.content', lambda *args: (True, 0))
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
    proxy.forward(HttpHeaders(), frontend, b'', upstream, b'response', b'', 0)
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
        proxy.forward(HttpHeaders(), frontend, b'request', upstream, b'', b'', 0)
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
    frontend.send.side_effect = [BlockingIOError(), len(b'response')]
    poller = MagicMock()
    poller.__enter__.return_value = poller
    poller.poll.side_effect = [[(10, select.POLLOUT)], [(10, select.POLLOUT)], []]
    monkeypatch.setattr('classes.Proxy.select.epoll', lambda: poller)
    proxy.forward(HttpHeaders(), frontend, b'', upstream, b'response', b'', 0)
    assert [call.args for call in frontend.send.call_args_list] == [(b'response',), (b'response',)]
