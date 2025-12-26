import logging
import re
import select
import socket
import threading
import time
from typing import Callable

from classes.Checks import Checks
from classes.Config import Config
from classes.HttpHeaders import HttpHeaders
from classes.IpTables import IpTables
from classes.RunTimeStats import RunTimeStats


class Proxy:

    buffer_size: int = 8192  # 8 KB

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
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1024)

        all_threads: list[threading.Thread] = []
        refresh_ts: float = time.time()
        logstats_ts: float = time.time()

        try:
            while True:
                conn, addr = s.accept()
                t = threading.Thread(target=self.proxy_handle_client, args=(conn, addr))
                t.start()
                all_threads.append(t)
                for t in all_threads[:]:
                    if not t.is_alive():
                        t.join(1)
                        all_threads.remove(t)
                if (time.time() - refresh_ts) > 10:
                    refresh_ts = time.time()
                    cb_10_seconds()
                if (time.time() - logstats_ts) > 3600:
                    logstats_ts = time.time()
                    cb_1_hour()

        except KeyboardInterrupt:
            pass
        finally:
            if s:
                s.close()

    def read_headers(self, nginx_socket: socket.socket, buffer: bytes) -> bytes:
        epoll = select.epoll()
        epoll.register(nginx_socket.fileno(), select.EPOLLIN)
        while True:
            events = epoll.poll()
            for _, event in events:
                if event & select.EPOLLIN:
                    data = nginx_socket.recv(Proxy.buffer_size)
                    buffer += data
            if buffer.find(b'\r\n\r\n') != -1 or buffer.find(b'\n\n') != -1:
                epoll.unregister(nginx_socket.fileno())
                break
        return buffer

    def forward(
            self,
            httpHeaders: HttpHeaders,
            nginx_socket: socket.socket,
            nginx_buffer: bytes,
            upstream_socket: socket.socket,
            upstream_buffer: bytes,
            request_whole: bytes,
            request_clean_upto: int,
    ) -> None:
        response_status: int | None = None
        response_whole: bytes = b''
        p = select.epoll()
        if len(upstream_buffer) > 0:
            p.register(nginx_socket, select.POLLIN | select.POLLOUT)
        else:
            p.register(nginx_socket, select.POLLIN)
        if len(nginx_buffer) > 0:
            p.register(upstream_socket, select.POLLIN | select.POLLOUT)
        else:
            p.register(upstream_socket, select.POLLIN)

        while True:
            if nginx_socket.fileno() == -1 and upstream_socket.fileno() == -1:
                break
            events = p.poll()
            for fd, event in events:
                if event & select.POLLIN:
                    if fd == nginx_socket.fileno():
                        data = nginx_socket.recv(Proxy.buffer_size)
                        if not data:
                            p.unregister(nginx_socket.fileno())
                            nginx_socket.close()
                            if len(request_whole) < self.config.config.getint("main", "max_inspect_size"):
                                self.log(httpHeaders, request_whole)
                            break
                        nginx_buffer += data
                        if len(request_whole) < self.config.config.getint("main", "max_inspect_size"):
                            request_whole += data
                            if not Checks.content(self.config, httpHeaders, request_whole, request_clean_upto):
                                self.ban(str(data), self.rts, self.config)
                            if len(request_whole) >= self.config.config.getint("main", "max_inspect_size"):
                                self.log(httpHeaders, request_whole)
                        p.modify(upstream_socket, select.POLLOUT)
                    elif fd == upstream_socket.fileno():
                        data = upstream_socket.recv(Proxy.buffer_size)
                        if not response_status:
                            response_whole += data
                        if not response_status and response_whole and "\n" in response_whole.decode(errors='ignore'):
                            first_line = response_whole.decode(errors='ignore').splitlines()[0]
                            _, response_status_str, _ = first_line.split(' ', 2)
                            response_status = int(response_status_str)
                            httpHeaders.http_status = int(response_status_str)
                            if not Checks.headers_with_status(httpHeaders, self.config, self.rts):
                                self.ban(httpHeaders.ip, self.rts, self.config)
                                self.log(httpHeaders, request_whole)
                                p.unregister(nginx_socket.fileno())
                                nginx_socket.close()
                                data = None
                                break
                        if not data:
                            p.unregister(upstream_socket.fileno())
                            upstream_socket.close()
                            if len(upstream_buffer) == 0 and nginx_socket.fileno() != -1:
                                p.unregister(nginx_socket.fileno())
                                nginx_socket.close()
                            break
                        upstream_buffer += data
                        p.modify(nginx_socket, select.POLLOUT)
                elif event & select.POLLOUT:
                    if fd == upstream_socket.fileno() and len(nginx_buffer) > 0:
                        sent = upstream_socket.send(nginx_buffer)
                        nginx_buffer = nginx_buffer[sent:]
                        if len(nginx_buffer) == 0:
                            p.modify(upstream_socket, select.POLLIN)
                    elif fd == nginx_socket.fileno() and len(upstream_buffer) > 0:
                        try:
                            sent = nginx_socket.send(upstream_buffer)
                        except ConnectionResetError:
                            p.unregister(nginx_socket.fileno())
                            nginx_socket.close()
                            break
                        upstream_buffer = upstream_buffer[sent:]
                        if len(upstream_buffer) == 0:
                            if upstream_socket.fileno() == -1:
                                p.unregister(nginx_socket.fileno())
                                nginx_socket.close()
                            else:
                                p.modify(nginx_socket, select.POLLIN)
                elif event & (select.POLLHUP | select.POLLERR):
                    if fd == nginx_socket.fileno():
                        p.unregister(nginx_socket.fileno())
                        nginx_socket.close()
                    elif fd == upstream_socket.fileno():
                        p.unregister(upstream_socket.fileno())
                        upstream_socket.close()

    def only_read(
        self,
        httpHeaders: HttpHeaders,
        nginx_socket: socket.socket,
        nginx_buffer: bytes,
        request_whole: bytes
    ) -> None:
        p = select.epoll()
        p.register(nginx_socket, select.POLLIN)
        while True:
            if nginx_socket.fileno() == -1:
                break
            events = p.poll()  # Returns list of (fd, event_type) tuples
            for fd, event in events:
                if event & select.POLLIN:
                    if fd == nginx_socket.fileno():
                        data = nginx_socket.recv(Proxy.buffer_size)
                        if not data:
                            nginx_socket.close()
                            break
                        nginx_buffer += data
                        if len(request_whole) < self.config.config.getint("main", "max_inspect_size"):
                            request_whole += data
                            if len(request_whole) >= self.config.config.getint("main", "max_inspect_size"):
                                self.log(httpHeaders, request_whole)
                                nginx_socket.close()
                                break
                if event & (select.POLLHUP | select.POLLERR):
                    if fd == nginx_socket.fileno():
                        nginx_socket.close()
        if len(request_whole) < self.config.config.getint("main", "max_inspect_size"):
            self.log(httpHeaders, request_whole)

    def parse_headers(self, nginx_socket: socket.socket, buffer: bytes) -> HttpHeaders:
        buffer_decoded = buffer.decode(errors='ignore')
        host: str = ''
        ip: str = ''
        ua: str = ''
        referer: str = ''
        upstream_host: str = ''
        upstream_port: int = 0
        host_match = re.search(r'^Host: (.*)$', buffer_decoded, re.MULTILINE)
        if host_match:
            host = host_match.group(1).strip().split(':')[0]
        ip_match = re.search(r'^X-Real-IP: (.*)$', buffer_decoded, re.MULTILINE)
        if ip_match:
            ip = ip_match.group(1).strip()
        ua_match = re.search(r'^(User-Agent|user-agent): (.*)$', buffer_decoded, re.MULTILINE)
        if ua_match:
            ua = ua_match.group(2).strip()
        referer_match = re.search(r'^(Referer|referer): (.*)$', buffer_decoded, re.MULTILINE)
        if referer_match:
            referer = referer_match.group(2).strip()
        match = re.search(r'^MinWaf-Dest: (http://|https://)*(.*)$', buffer_decoded, re.MULTILINE)
        if match:
            waf_dest = match.group(2).strip()
            upstream_host, sep, upstream_port_str = waf_dest.partition(':')
            upstream_port = int(upstream_port_str) if sep else 80

        method, path, proto = buffer_decoded.splitlines()[0].split(' ', 2)
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

    def connect_upstream(self, httpHeaders: HttpHeaders) -> socket.socket:
        upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            upstream_socket.connect((httpHeaders.upstream_host, httpHeaders.upstream_port))
        except ConnectionRefusedError:
            logger = logging.getLogger("min.waf")
            logger.info(f"Connection to {httpHeaders.upstream_host}:{httpHeaders.upstream_port} refused")
            upstream_socket.close()
        return upstream_socket

    def proxy_handle_client(
            self,
            nginx_socket: socket.socket,
            addr: tuple[str, int]
    ) -> None:
        nginx_buffer: bytes = b''
        upstream_buffer: bytes = b''
        upstream_socket: socket.socket | None = None
        forward: bool = True
        request_whole: bytes = b''
        request_clean_upto: int = 0

        nginx_socket.setblocking(False)
        nginx_buffer = self.read_headers(nginx_socket, nginx_buffer)
        request_whole = nginx_buffer
        httpHeaders = self.parse_headers(nginx_socket, nginx_buffer)
        if not Checks.headers(httpHeaders, self.config, self.rts):
            forward = False
            self.ban(str(httpHeaders.ip), self.rts, self.config)
        if not Checks.content(self.config, httpHeaders, request_whole, request_clean_upto):
            forward = False
            self.ban(str(httpHeaders.ip), self.rts, self.config)
        if not forward and not self.config.mode_honeypot:
            nginx_socket.close()
            return
        if forward:
            upstream_socket = self.connect_upstream(httpHeaders)
            upstream_socket.setblocking(False)
            self.forward(
                httpHeaders,
                nginx_socket,
                nginx_buffer,
                upstream_socket,
                upstream_buffer,
                request_whole,
                request_clean_upto
            )
        elif self.config.mode_honeypot:
            self.only_read(httpHeaders, nginx_socket, nginx_buffer, request_whole)
        return

    @staticmethod
    def ban(
        ip: str,
        rts: RunTimeStats,
        config: Config
    ) -> None:
        if config.config.get('main', 'ban_method') == 'iptables':
            IpTables.ban(ip, rts, config)
        else:
            rts.banned_ips[ip] = time.time()

    def log(self, httpHeaders: HttpHeaders, request_whole: bytes) -> None:
        if not httpHeaders.status == HttpHeaders.STATUS_BAD:
            return
        if self.config.config.get('log', 'requests'):
            with open(self.config.config.get('log', 'requests'), 'a+') as f:
                f.write(f"{httpHeaders.path}\n")
        if self.config.config.get('log', 'contents'):
            data = request_whole.decode(errors='ignore').split("\r\n\r\n", 1)[1]
            if len(data) >= 1:
                with open(self.config.config.get('log', 'contents'), 'a+') as f:
                    f.write(data + "\n===\n")
