import logging
import re
import select
import socket
import threading
import time

from Config import Config
from IpTables import IpTables
from LogLine import LogLine
from Nginx import Nginx
from PrintStats import PrintStats
from RunTimeStats import RunTimeStats


class MinProxy:
    def __init__(self, config: Config, rts: RunTimeStats) -> None:
        self.config = config
        self.rts = rts

        host = config.proxy_listen_host
        port = config.proxy_listen_port
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
                    IpTables.unban_expired(self.config, self.rts)
                if (time.time() - logstats_ts) > 3600:
                    logstats_ts = time.time()
                    PrintStats.log_stats(self.rts)
                    if self.config.ip_blacklist and self.rts.ip_blacklist:
                        self.rts.ip_blacklist.refresh_list()

        except KeyboardInterrupt:
            logging.info("Stopped by Ctrl+C")
        finally:
            if s:
                logging.debug("Closing server socket")
                s.close()
            for t in all_threads:
                logging.debug(f"Joining thread {t.name}")
                t.join(1)

    def proxy_handle_client(self, request_socket: socket.socket, addr: tuple[str, int]) -> None:
        waf_dest: str = ''
        header_end: bool = False
        response_socket: socket.socket | None = None
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
        while True:
            try:
                data = request_socket.recv(buff_size)
            except ConnectionResetError:
                request_socket.close()
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
                logging.info(f"Connection from banned IP {log_line_data['ip']} rejected")
                request_socket.close()
                return
        ua_match = re.search(r'^(User-Agent|user-agent): (.*)$', buffer_decoded, re.MULTILINE)
        if ua_match:
            log_line_data['ua'] = ua_match.group(2).strip()
        referer_match = re.search(r'^(Referer|referer): (.*)$', buffer_decoded, re.MULTILINE)
        if referer_match:
            log_line_data['referer'] = referer_match.group(2).strip()
        match = re.search(r'^MinWaf-Dest: (.*)$', buffer_decoded, re.MULTILINE)
        if match and waf_dest == '':
            waf_dest = match.group(1).strip()
            response_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host, sep, port_str = waf_dest.partition(':')
            port = int(port_str) if sep else 80
            try:
                response_socket.connect((host, port))
            except ConnectionRefusedError:
                logging.info(f"Connection to WAF destination {waf_dest} refused")
                request_socket.close()
                return
            response_socket.send(buffer)
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
                request_socket.close()
                response_socket.close()
                return
        else:
            #  logging.info("MinWaf-Dest header found but no WAF destination set")
            #  logging.info(f"{log_line_data} address={addr}")
            #  logging.info(f">>{buffer_decoded}<<")
            log_line_data['upstream_response_time'] = time.time() - float(log_line_data['req_ts'])
            log_line = LogLine(log_line_data)
            log_line_data['logged'] = True
            Nginx.process_line(self.config, self.rts, log_line, "")
            return
        header_end = False
        http_status: str = '200'
        while True:
            if request_socket.fileno() == -1 and response_socket.fileno() == -1:
                break
            socket_list = [request_socket, response_socket]
            read_sockets, _, _ = select.select(socket_list, [], [])
            for sock in read_sockets:
                try:
                    data = sock.recv(buff_size)
                    if not data:
                        # connection closed
                        request_socket.close()
                        response_socket.close()
                        break
                    else:
                        if sock == request_socket:
                            response_socket.send(data)
                        else:
                            if not header_end:
                                headers = data.partition(b'\r\n\r\n')[0].decode(errors='ignore')
                                _, http_status, _ = headers.splitlines()[0].split(' ', 2)
                                header_end = True
                                try:
                                    log_line_data['http_status'] = int(http_status)
                                except ValueError:
                                    logging.warning(f"Malformed HTTP status: '{http_status}' in response from {addr}")
                                    log_line_data['http_status'] = 0
                                log_line_data['upstream_response_time'] = time.time() - float(log_line_data['req_ts'])
                                log_line = LogLine(log_line_data)
                                log_line_data['logged'] = True
                                if Nginx.process_line(self.config, self.rts, log_line, "") == Nginx.STATUS_BANNED:
                                    # just enough for iptables to register the ban and annoy the attacker a bit
                                    time.sleep(3)
                                    # and confuse them, in case it hasn't propagated yet
                                    try:
                                        request_socket.send(b"HTTP/1.1 200 OK\r\n\r\n")
                                    except (BrokenPipeError, OSError):
                                        pass
                                    request_socket.close()
                                    response_socket.close()
                                    return
                            try:
                                request_socket.send(data)
                            except (BrokenPipeError, OSError):
                                request_socket.close()
                                response_socket.close()
                                break
                except ConnectionResetError:
                    request_socket.close()
                    response_socket.close()
                    break
        if not log_line_data['logged']:
            log_line_data['upstream_response_time'] = time.time() - float(log_line_data['req_ts'])
            log_line = LogLine(log_line_data)
            Nginx.process_line(self.config, self.rts, log_line, "")
        return
