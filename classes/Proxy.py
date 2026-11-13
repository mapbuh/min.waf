import logging
import ipaddress
import re
import select
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from classes.Checks import Checks
from classes.Config import Config
from classes.HttpHeaders import HttpHeaders
from classes.IpTables import IpTables
from classes.RequestInspector import RequestInspector
from classes.ResponseInspector import ResponseInspector
from classes.RunTimeStats import RunTimeStats


class Proxy:

    buffer_size: int = 8192  # 8 KB
    # stop reading a side while this much of its data waits for the other side
    max_buffer: int = 262144  # 256 KB

    _head_end = re.compile(rb'\r?\n\r?\n')
    _hop_header = re.compile(rb'^(connection|keep-alive|proxy-connection)[ \t]*:', re.IGNORECASE)
    _upgrade_header = re.compile(rb'^upgrade[ \t]*:', re.IGNORECASE | re.MULTILINE)
    # the reason phrase is optional in practice: 'HTTP/1.1 200' is accepted
    _status_line = re.compile(rb'HTTP/\d+(?:\.\d+)?[ \t]+(\d{3})(?:[ \t\r]|$)')

    def __init__(
        self,
        config: Config,
        rts: RunTimeStats,
        cb_10_seconds: Callable[[], None],
        cb_1_hour: Callable[[], None]
    ) -> None:
        self.config = config
        self.rts = rts

        host = config.config.get("main", "host")
        port = int(config.config.get("main", "port"))
        max_workers = config.config.getint("main", "max_workers", fallback=200)

        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1024)

        executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="proxy-worker")
        stop = threading.Event()
        threading.Thread(
            target=Proxy.periodic,
            args=(cb_10_seconds, cb_1_hour, stop),
            name="periodic",
            daemon=True,
        ).start()

        try:
            while True:
                conn, addr = s.accept()
                with self.rts._counters_lock:
                    self.rts.all += 1
                executor.submit(self.proxy_handle_client, conn, addr)

        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            if s:
                s.close()
            executor.shutdown(wait=True, cancel_futures=False)

    periodic_interval: float = 10.0

    @staticmethod
    def periodic(cb_10_seconds: Callable[[], None], cb_1_hour: Callable[[], None], stop: threading.Event) -> None:
        """Runs the periodic callbacks off the accept loop until stop is set.

        They run on time when no connections arrive, a slow one (a download,
        iptables calls) does not hold up accepting connections, and a failing
        one is logged and retried on the next tick instead of ending min.waf.
        """
        last_hour = time.monotonic()
        while not stop.wait(Proxy.periodic_interval):
            Proxy.run_callback(cb_10_seconds)
            if time.monotonic() - last_hour >= 3600:
                last_hour = time.monotonic()
                Proxy.run_callback(cb_1_hour)

    @staticmethod
    def run_callback(callback: Callable[[], None]) -> None:
        try:
            callback()
        except Exception:
            logging.getLogger("min.waf").exception("Periodic task %s failed", getattr(callback, "__name__", callback))

    header_read_timeout: float = 5.0

    def read_headers(self, frontend_socket: socket.socket, buffer: bytes) -> bytes:
        deadline = time.monotonic() + Proxy.header_read_timeout
        with select.epoll() as epoll:
            epoll.register(frontend_socket.fileno(), select.EPOLLIN)
            while True:
                remaining = deadline - time.monotonic()
                events = epoll.poll(max(0, remaining)) if remaining > 0 else []
                if not events:
                    epoll.unregister(frontend_socket.fileno())
                    frontend_socket.close()
                    return buffer
                for _, event in events:
                    if event & select.EPOLLIN:
                        try:
                            data = frontend_socket.recv(Proxy.buffer_size)
                        except BlockingIOError:
                            continue
                        except (ConnectionResetError, BrokenPipeError):
                            data = None
                        if not data:
                            epoll.unregister(frontend_socket.fileno())
                            frontend_socket.close()
                            return buffer
                        buffer += data
                    elif event & (select.EPOLLHUP | select.EPOLLERR):
                        frontend_socket.close()
                        return buffer
                if buffer.find(b'\r\n\r\n') != -1 or buffer.find(b'\n\n') != -1:
                    epoll.unregister(frontend_socket.fileno())
                    break
        return buffer

    def forward(
            self,
            httpHeaders: HttpHeaders,
            frontend_socket: socket.socket,
            frontend_buffer: bytes,
            upstream_socket: socket.socket,
            upstream_buffer: bytes,
            request_whole: bytes,
            inspector: RequestInspector,
    ) -> None:
        response_status: int | None = None
        response_whole: bytes = b''
        response_inspector = ResponseInspector(self.config, httpHeaders)
        max_inspect_size = self.config.config.getint("main", "max_inspect_size")
        idle_timeout = self.config.config.getfloat("main", "connection_idle_timeout", fallback=60)
        # bytearrays drop sent bytes from the front without copying the rest
        to_upstream = bytearray(frontend_buffer)
        to_frontend = bytearray(upstream_buffer)
        with select.epoll() as p:
            masks: dict[int, int] = {}

            def watch(sock: socket.socket, pending_out: bytearray, pending_in: bytearray, peer: socket.socket) -> None:
                # read a side only while what it sends the other way is below
                # max_buffer, so a fast peer cannot fill the memory while the
                # other one is slow; once the peer is closed, reading goes on
                # to notice the close; write while there is something to send
                fd = sock.fileno()
                if fd == -1:
                    return
                readable = len(pending_in) < Proxy.max_buffer or peer.fileno() == -1
                mask = (select.POLLIN if readable else 0) | (select.POLLOUT if pending_out else 0)
                if fd not in masks:
                    p.register(fd, mask)
                elif masks[fd] != mask:
                    p.modify(fd, mask)
                masks[fd] = mask

            while True:
                if frontend_socket.fileno() == -1 and upstream_socket.fileno() == -1:
                    break
                watch(frontend_socket, to_frontend, to_upstream, upstream_socket)
                watch(upstream_socket, to_upstream, to_frontend, frontend_socket)
                events = p.poll(idle_timeout)
                if not events:
                    return
                for fd, event in events:
                    if event & select.POLLIN:
                        if fd == frontend_socket.fileno():
                            try:
                                data = frontend_socket.recv(Proxy.buffer_size)
                            except BlockingIOError:
                                continue
                            except (ConnectionResetError, BrokenPipeError):
                                data = None
                            if not data:
                                frontend_socket.close()
                                upstream_socket.close()
                                self.log(httpHeaders, request_whole)
                                break
                            if upstream_socket.fileno() != -1:
                                # nowhere to send it once the upstream closed
                                to_upstream += data
                            if len(request_whole) < max_inspect_size:
                                request_whole += data
                            if not inspector.feed(data):
                                self.ban(httpHeaders.ip, self.rts, self.config, httpHeaders.ban_reason)
                                frontend_socket.close()
                                upstream_socket.close()
                                self.log(httpHeaders, request_whole)
                                break
                            if len(request_whole) >= max_inspect_size:
                                self.log(httpHeaders, request_whole)
                        elif fd == upstream_socket.fileno():
                            try:
                                data = upstream_socket.recv(Proxy.buffer_size)
                            except BlockingIOError:
                                continue
                            except (ConnectionResetError, BrokenPipeError):
                                frontend_socket.close()
                                upstream_socket.close()
                                break
                            if response_status is None:
                                response_whole += data
                                response_status = Proxy.response_status(response_whole)
                                if response_status is not None:
                                    httpHeaders.http_status = response_status
                                    httpHeaders.upstream_response_time = time.time() - httpHeaders.ts
                                    if not Checks.headers_with_status(httpHeaders, self.config, self.rts):
                                        self.ban(httpHeaders.ip, self.rts, self.config, httpHeaders.ban_reason)
                                        self.log(httpHeaders, request_whole)
                                        frontend_socket.close()
                                        upstream_socket.close()
                                        break
                            clean, released = response_inspector.feed(data)
                            if not clean:
                                self.ban(httpHeaders.ip, self.rts, self.config, httpHeaders.ban_reason)
                                self.log(httpHeaders, request_whole)
                                frontend_socket.close()
                                upstream_socket.close()
                                break
                            to_frontend += released
                            if not data:
                                upstream_socket.close()
                                if not to_frontend:
                                    Proxy.linger_close(frontend_socket)
                                break
                    if event & select.POLLOUT:
                        # also when the same event was readable, so a socket
                        # that keeps receiving still gets its data sent
                        if fd == upstream_socket.fileno() and to_upstream:
                            try:
                                sent = upstream_socket.send(to_upstream)
                            except BlockingIOError:
                                continue
                            del to_upstream[:sent]
                        elif fd == frontend_socket.fileno() and to_frontend:
                            try:
                                sent = frontend_socket.send(to_frontend)
                            except BlockingIOError:
                                continue
                            except (ConnectionResetError, BrokenPipeError):
                                return
                            del to_frontend[:sent]
                            if not to_frontend and upstream_socket.fileno() == -1:
                                Proxy.linger_close(frontend_socket)
                    if not event & (select.POLLIN | select.POLLOUT) and event & (select.POLLHUP | select.POLLERR):
                        if fd == frontend_socket.fileno():
                            return
                        elif fd == upstream_socket.fileno():
                            upstream_socket.close()
                            if not to_frontend:
                                return

    linger_time: float = 1.0

    @staticmethod
    def linger_close(sock: socket.socket) -> None:
        """Closes the client connection after a complete response without a reset.

        Closing a socket with unread data sends an RST, which can make the
        client drop the end of the response still in its receive buffer. The
        write side is shut down first, then what the client still sends is
        read and dropped until it closes, for at most linger_time seconds.
        """
        try:
            sock.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + Proxy.linger_time
            with select.epoll() as p:
                p.register(sock.fileno(), select.EPOLLIN)
                while (remaining := deadline - time.monotonic()) > 0:
                    if not p.poll(remaining) or not sock.recv(Proxy.buffer_size):
                        break
        except OSError:
            pass
        finally:
            sock.close()

    def only_read(
        self,
        httpHeaders: HttpHeaders,
        frontend_socket: socket.socket,
        frontend_buffer: bytes,
        request_whole: bytes
    ) -> None:
        max_inspect_size = self.config.config.getint("main", "max_inspect_size")
        with select.epoll() as p:
            p.register(frontend_socket, select.POLLIN)
            bail: float = time.time() + 1  # do not waste much time, we know it is bad request, we only want to log it
            while True:
                if time.time() > bail:
                    frontend_socket.sendall(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n')
                    frontend_socket.close()
                    break
                if frontend_socket.fileno() == -1:
                    break
                events = p.poll(1)  # Returns list of (fd, event_type) tuples
                for fd, event in events:
                    if event & select.POLLIN:
                        if fd == frontend_socket.fileno():
                            data = frontend_socket.recv(Proxy.buffer_size)
                            if not data:
                                frontend_socket.close()
                                break
                            frontend_buffer += data
                            if len(request_whole) < max_inspect_size:
                                request_whole += data
                                if len(request_whole) >= max_inspect_size:
                                    self.log(httpHeaders, request_whole)
                                    frontend_socket.sendall(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n')
                                    frontend_socket.close()
                                    break
                    if event & (select.POLLHUP | select.POLLERR):
                        if fd == frontend_socket.fileno():
                            frontend_socket.close()
        if len(request_whole) < max_inspect_size:
            self.log(httpHeaders, request_whole)

    def parse_headers(self, frontend_socket: socket.socket, buffer: bytes) -> HttpHeaders:
        buffer_decoded = buffer.decode(errors='ignore')
        host: str = ''
        ip: str = ''
        ua: str = ''
        referer: str = ''
        upstream_host: str = ''
        upstream_port: int = 0
        host_match = re.search(r'^Host: (.*)$', buffer_decoded, re.MULTILINE | re.IGNORECASE)
        if host_match:
            host = host_match.group(1).strip().split(':')[0]
        ip_match = re.search(r'^X-Real-IP: (.*)$', buffer_decoded, re.MULTILINE | re.IGNORECASE)
        if ip_match:
            try:
                ip = str(ipaddress.ip_address(ip_match.group(1).strip()))
            except ValueError:
                ip = ''
        ua_match = re.search(r'^User-Agent: (.*)$', buffer_decoded, re.MULTILINE | re.IGNORECASE)
        if ua_match:
            ua = ua_match.group(1).strip()
        referer_match = re.search(r'^Referer: (.*)$', buffer_decoded, re.MULTILINE | re.IGNORECASE)
        if referer_match:
            referer = referer_match.group(1).strip()
        match = re.search(r'^MinWaf-Dest: (http://|https://)*(.*)$', buffer_decoded, re.MULTILINE | re.IGNORECASE)
        if match:
            waf_dest = match.group(2).strip()
            upstream_host, sep, upstream_port_str = waf_dest.partition(':')
            try:
                p = int(upstream_port_str) if sep else 80
                upstream_port = p if 1 <= p <= 65535 else 80
            except ValueError:
                upstream_port = 80

        lines = buffer_decoded.splitlines()
        parts = lines[0].split(' ', 2) if lines else []
        method, path, proto = parts if len(parts) == 3 else ('', '', '')
        return HttpHeaders(
            host=host,
            ip=ip,
            ua=ua,
            referer=referer,
            upstream_host=upstream_host,
            upstream_port=upstream_port,
            method=method,
            path=path,
            proto=proto,
        )

    def connect_upstream(self, httpHeaders: HttpHeaders) -> socket.socket | None:
        upstream_socket = None
        try:
            upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream_socket.settimeout(self.config.config.getfloat("main", "connect_timeout", fallback=10))
            upstream_socket.connect((httpHeaders.upstream_host, httpHeaders.upstream_port))
            upstream_socket.setblocking(False)
        except ConnectionRefusedError:
            logger = logging.getLogger("min.waf")
            logger.info(f"Connection to {httpHeaders.upstream_host}:{httpHeaders.upstream_port} refused")
            if upstream_socket is not None:
                upstream_socket.close()
            upstream_socket = None
        except TimeoutError:
            logger = logging.getLogger("min.waf")
            logger.info(f"Connection to {httpHeaders.upstream_host}:{httpHeaders.upstream_port} timed out")
            if upstream_socket is not None:
                upstream_socket.close()
            upstream_socket = None
        except OSError:
            if upstream_socket is not None:
                upstream_socket.close()
            raise
        return upstream_socket

    @staticmethod
    def response_status(response: bytes) -> int | None:
        """Returns the status of the final response, None until it has arrived.

        Interim 1xx responses (100 Continue, 103 Early Hints) are skipped, so
        the stats and triggers see the real status; 101 Switching Protocols is
        final. A status line that cannot be parsed, or no final status within
        ResponseInspector.max_head bytes, gives -1.
        """
        pos = 0
        while True:
            nl = response.find(b'\n', pos)
            if nl == -1:
                break
            match = Proxy._status_line.match(response, pos, nl)
            if not match:
                return -1
            status = int(match.group(1))
            if not 100 <= status < 200 or status == 101:
                return status
            head_end = Proxy._head_end.search(response, pos)
            if not head_end:
                break
            pos = head_end.end()
        return -1 if len(response) > ResponseInspector.max_head else None

    @staticmethod
    def close_after_response(buffer: bytes) -> bytes:
        """Asks the upstream to close the connection after its response.

        Only the first request on a connection goes through the checks, so the
        connection must not be reused: the Connection, Keep-Alive and
        Proxy-Connection headers are replaced with 'Connection: close'. When the
        upstream closes, the frontend connection is closed too, so a frontend
        that pools backend connections (Apache mod_proxy) opens a new one for
        its next request. Upgrade requests (WebSocket) are left untouched.
        """
        match = Proxy._head_end.search(buffer)
        if not match:
            return buffer
        head, rest = buffer[:match.start()], buffer[match.start():]
        if Proxy._upgrade_header.search(head):
            return buffer
        lines = [line.removesuffix(b'\r') for line in head.split(b'\n')]
        kept = [lines[0]] + [line for line in lines[1:] if not Proxy._hop_header.match(line)]
        kept.append(b'Connection: close')
        eol = b'\r\n' if rest.startswith(b'\r') else b'\n'
        return eol.join(kept) + rest

    def proxy_handle_client(
            self,
            frontend_socket: socket.socket,
            addr: tuple[str, int]
    ) -> None:
        frontend_buffer: bytes = b''
        upstream_buffer: bytes = b''
        upstream_socket: socket.socket | None = None
        forward: bool = True
        request_whole: bytes = b''

        try:
            frontend_socket.setblocking(False)
            frontend_buffer = self.read_headers(frontend_socket, frontend_buffer)
            if frontend_socket.fileno() == -1:
                return
            request_whole = frontend_buffer
            httpHeaders = self.parse_headers(frontend_socket, frontend_buffer)
            if not Checks.headers(httpHeaders, self.config, self.rts):
                forward = False
                self.ban(str(httpHeaders.ip), self.rts, self.config, httpHeaders.ban_reason)
            inspector = RequestInspector(self.config, httpHeaders)
            if not inspector.feed(request_whole):
                forward = False
                self.ban(str(httpHeaders.ip), self.rts, self.config, httpHeaders.ban_reason)
            if not forward and not self.config.mode_honeypot:
                return
            if forward:
                frontend_buffer = Proxy.close_after_response(frontend_buffer)
                upstream_socket = self.connect_upstream(httpHeaders)
                if not upstream_socket or upstream_socket.fileno() == -1:
                    return
                self.forward(
                    httpHeaders,
                    frontend_socket,
                    frontend_buffer,
                    upstream_socket,
                    upstream_buffer,
                    request_whole,
                    inspector
                )
            elif self.config.mode_honeypot:
                self.only_read(httpHeaders, frontend_socket, frontend_buffer, request_whole)
            return
        except OSError as exc:
            logging.getLogger("min.waf").debug("Connection %s closed: %s", addr, exc)
        except Exception:
            logging.getLogger("min.waf").exception("Error handling connection from %s", addr)
        finally:
            frontend_socket.close()
            if upstream_socket is not None:
                upstream_socket.close()

    @staticmethod
    def ban(
        ip: str,
        rts: RunTimeStats,
        config: Config,
        reason: str = "request rejected",
    ) -> None:
        if not ip:
            # without X-Real-IP there is nobody to ban; banning '' would block
            # every other request without an IP
            logging.getLogger("min.waf").debug("request without client IP rejected; %s", reason)
            return
        with rts._counters_lock:
            rts.bans += 1
        if config.config.get('main', 'ban_method') == 'iptables':
            new_ban = IpTables.ban(ip, rts, config)
        else:
            with rts._banned_ips_lock:
                new_ban = ip not in rts.banned_ips
                rts.banned_ips[ip] = time.time()
        if new_ban and config.config.getboolean("log", "bans"):
            logging.getLogger("min.waf").info("%s banned; %s", ip, reason or "request rejected")

    def log(self, httpHeaders: HttpHeaders, request_whole: bytes) -> None:
        if not httpHeaders.status == HttpHeaders.STATUS_BAD:
            return
        if httpHeaders.logged:
            return
        httpHeaders.logged = True
        if self.config.config.get('log', 'requests'):
            with open(self.config.config.get('log', 'requests'), 'a+') as f:
                f.write(f"{httpHeaders.path}\n")
        if self.config.config.get('log', 'contents'):
            decoded = request_whole.decode(errors='ignore')
            head_end = decoded.find("\r\n\r\n")
            sep = 4
            if head_end == -1:
                head_end = decoded.find("\n\n")
                sep = 2
            if head_end != -1:
                data = decoded[head_end + sep:]
                if data:
                    with open(self.config.config.get('log', 'contents'), 'a+') as f:
                        f.write(data + "\n===\n")
