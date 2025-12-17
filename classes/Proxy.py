import logging
import re
import select
import socket
import threading
import time
import urllib.parse

from classes.Config import Config
from classes.IpTables import IpTables
from classes.LogLine import LogLine
from classes.Nginx import Nginx
from classes.RunTimeStats import RunTimeStats


class Proxy:
    from typing import Callable

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

    def proxy_handle_client(self, nginx_socket: socket.socket, addr: tuple[str, int]) -> None:
        logger = logging.getLogger("min.waf")
        waf_dest: str = ''
        header_end: bool = False
        upstream_socket: socket.socket | None = None
        log_line_data: dict[str, str | int | float] = {
            'method': '',
            'path': '',
            'proto': '',
            'host': '',
            'ip': '',
            'req_ts': time.time(),
            'upstream_response_time': 1.23,
            'logged': False,
        }
        buffer: bytes = b''
        buff_size = 8192
        data: bytes = b''
        request_whole: bytes = b''
        # response_whole: bytes = b''
        request_clean_upto: int = 0
        # response_clean_upto: int = 0
        while True:
            try:
                data = nginx_socket.recv(buff_size)
                if self.config.config.getboolean("main", "inspect_packets"):
                    request_whole += data
            except ConnectionResetError:
                nginx_socket.close()
            if not data:
                # eof
                break
            buffer += data
            if (buffer.find(b'\r\n\r\n') != -1 or buffer.find(b'\n\n') != -1) and len(buffer) > 1:
                break
        buffer_decoded = buffer.decode(errors='ignore')
        host_match = re.search(r'^Host: (.*)$', buffer_decoded, re.MULTILINE)
        if host_match:
            log_line_data['host'] = host_match.group(1).strip().split(':')[0]
        ip_match = re.search(r'^X-Real-IP: (.*)$', buffer_decoded, re.MULTILINE)
        if ip_match:
            log_line_data['ip'] = ip_match.group(1).strip()
            if log_line_data['ip'] in self.rts.banned_ips.keys():
                # logger.info(f"Connection from banned IP {log_line_data['ip']} rejected")
                nginx_socket.close()
                return
        ua_match = re.search(r'^(User-Agent|user-agent): (.*)$', buffer_decoded, re.MULTILINE)
        if ua_match:
            log_line_data['ua'] = ua_match.group(2).strip()
        referer_match = re.search(r'^(Referer|referer): (.*)$', buffer_decoded, re.MULTILINE)
        if referer_match:
            log_line_data['referer'] = referer_match.group(2).strip()
        match = re.search(r'^MinWaf-Dest: (http://|https://)*(.*)$', buffer_decoded, re.MULTILINE)
        if match and waf_dest == '':
            waf_dest = match.group(2).strip()
            upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host, sep, port_str = waf_dest.partition(':')
            port = int(port_str) if sep else 80
            try:
                upstream_socket.connect((host, port))
            except ConnectionRefusedError:
                logger.info(f"Connection to WAF destination {waf_dest} refused")
                nginx_socket.close()
                return
            if self.is_safe(
                request_whole,
                request_clean_upto,
            ):
                upstream_socket.sendall(buffer)
            else:
                IpTables.ban(str(log_line_data['ip']), self.rts, self.config)
                logger.info(f"{log_line_data['ip']} banned; harmful signature detected in request")
                nginx_socket.close()
                upstream_socket.close()
                return
            # Efficiently extract the first line (request line) without splitlines()
            first_line_end = buffer_decoded.find('\n')
            if first_line_end == -1:
                request_line = buffer_decoded.strip()
            else:
                request_line = buffer_decoded[:first_line_end].strip()
            try:
                log_line_data['method'], log_line_data['path'], log_line_data['proto'] = request_line.split(' ', 2)
                log_line_data['req'] = f"{log_line_data['host']}{log_line_data['path']}"
            except ValueError:
                logging.warning(f"Malformed request line: '{request_line}' from {addr}")
                log_line_data['upstream_response_time'] = time.time() - float(log_line_data['req_ts'])
                log_line = LogLine(log_line_data)
                log_line_data['logged'] = True
                Nginx.process_line(self.config, self.rts, log_line, "")
                nginx_socket.close()
                upstream_socket.close()
                return
            if not self.is_safe_header(log_line_data['path']):
                IpTables.ban(str(log_line_data['ip']), self.rts, self.config)
                logger.info(f"{log_line_data['ip']} banned; harmful signature detected in request")
                nginx_socket.close()
                upstream_socket.close()
                return
        else:
            log_line_data['upstream_response_time'] = time.time() - float(log_line_data['req_ts'])
            log_line = LogLine(log_line_data)
            log_line_data['logged'] = True
            Nginx.process_line(self.config, self.rts, log_line, "")
            nginx_socket.close()
            return
        header_end = False
        http_status: str = '200'
        p = select.epoll()
        p.register(nginx_socket, select.POLLIN)
        p.register(upstream_socket, select.POLLIN)
        while True:
            if nginx_socket.fileno() == -1 and upstream_socket.fileno() == -1:
                break
            events = p.poll()  # Returns list of (fd, event_type) tuples
            for fd, _ in events:
                if fd == nginx_socket.fileno():
                    sock = nginx_socket
                elif fd == upstream_socket.fileno():
                    sock = upstream_socket
                else:
                    continue
                try:
                    data = sock.recv(buff_size)
                    if self.config.config.getboolean("main", "inspect_packets"):
                        if sock == nginx_socket:
                            request_whole += data
                        # else:
                        #     response_whole += data
                    if not data:
                        # connection closed
                        nginx_socket.close()
                        upstream_socket.close()
                        break
                    else:
                        if sock == nginx_socket:
                            if self.is_safe(
                                request_whole,
                                request_clean_upto,
                            ):
                                upstream_socket.sendall(data)
                            else:
                                IpTables.ban(str(log_line_data['ip']), self.rts, self.config)
                                logger.info(f"{log_line_data['ip']} banned; harmful signature detected in request")
                                nginx_socket.close()
                                upstream_socket.close()
                                return
                        else:
                            if not header_end:
                                headers = data.partition(b'\r\n\r\n')[0].decode(errors='ignore')
                                _, http_status, _ = headers.splitlines()[0].split(' ', 2)
                                header_end = True
                                try:
                                    log_line_data['http_status'] = int(http_status)
                                except ValueError:
                                    logger.warning(f"Malformed HTTP status: '{http_status}' in response from {addr}")
                                    log_line_data['http_status'] = 0
                                log_line_data['upstream_response_time'] = time.time() - float(log_line_data['req_ts'])
                                log_line = LogLine(log_line_data)
                                log_line_data['logged'] = True
                                if (Nginx.process_line(self.config, self.rts, log_line, "") == Nginx.STATUS_BANNED):
                                    # just enough for iptables to register the ban and annoy the attacker a bit
                                    time.sleep(3)
                                    # and confuse them, in case it hasn't propagated yet
                                    try:
                                        nginx_socket.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                                    except (BrokenPipeError, OSError):
                                        pass
                                    nginx_socket.close()
                                    upstream_socket.close()
                                    return
                            try:
                                nginx_socket.sendall(data)
                            except (BrokenPipeError, OSError):
                                nginx_socket.close()
                                upstream_socket.close()
                                break
                except ConnectionResetError:
                    nginx_socket.close()
                    upstream_socket.close()
                    break
        if not log_line_data['logged']:
            log_line_data['upstream_response_time'] = time.time() - float(log_line_data['req_ts'])
            log_line = LogLine(log_line_data)
            Nginx.process_line(self.config, self.rts, log_line, "")
        return

    def is_safe(
            self,
            request_whole: bytes,
            request_clean_upto: int,
    ) -> bool:
        logger = logging.getLogger("min.waf")
        if self.config.config.getboolean("main", "inspect_packets"):
            if request_clean_upto >= self.config.config.getint("main", "max_inspect_size"):
                return True
            # Inspect only the new data since last clean point
            dirty_data_from: int = request_clean_upto - self.config.longest_harmful_pattern() + 1
            if dirty_data_from < 0:
                dirty_data_from = 0
            dirty_data = request_whole[dirty_data_from:]
            for signature in self.config.harmful_patterns():
                if signature.encode().lower() in dirty_data.lower():
                    logger.debug(f"Harmful signature detected: {signature}")
                    logger.debug(f"Dirty data: {request_whole}")
                    # Drop the connection by not sending data upstream
                    return False
            request_clean_upto = len(request_whole)
        return True

    def is_safe_header(self, path: str) -> bool:
        logger = logging.getLogger("min.waf")
        if self.config.config.getboolean("main", "inspect_packets"):
            for signature in self.config.harmful_patterns():
                if signature.lower() in urllib.parse.unquote(path).lower():
                    logger.debug(f"Harmful signature detected in header: {signature}")
                    logger.debug(f"Dirty data: {path}")
                    return False
        return True
