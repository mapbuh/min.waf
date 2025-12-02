import datetime
import logging
import re
import shlex
import subprocess
import sys

from classes.Bots import Bots
from classes.Checks import Checks
from classes.Config import Config
from classes.ExpiringList import ExpiringList
from classes.IpData import IpData
from classes.IpTables import IpTables
from classes.KnownAttacks import KnownAttacks
from classes.LogLine import LogLine
from classes.RunTimeStats import RunTimeStats


class Nginx:
    STATUS_BANNED = 'banned'
    STATUS_OK = 'ok'
    STATUS_SLOW = 'slow'
    STATUS_UNKNOWN = 'unknown'

    @staticmethod
    def config_get() -> dict[str, str]:
        log_file_path = ""
        nginx_config: str = subprocess.run(
            ["nginx", "-T"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        ).stdout.decode("utf-8")
        output = re.search(
            r"access_log\s+([^\s]+)\s+([^\s]+)\s*;", nginx_config, flags=re.IGNORECASE
        )
        if output is None:
            print("Could not find access_log directive in nginx config")
            raise RuntimeError
        log_file_path = output.group(1)
        log_file_format = output.group(2)
        output = re.search(
            f"log_format\\s+{log_file_format}([^;]+);",
            nginx_config,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if output is None:
            print(
                f"Could not find log_format {log_file_format} in nginx config")
            sys.exit(1)
        log_format = ""
        for line in output.group(1).splitlines():
            line = line.strip()
            if line[0] == "'" and line.endswith("'"):
                line = line[1:-1]
            log_format += line + " "
        log_format = re.sub(r"\s+", " ", log_format).strip()
        return {"log_format": log_format, "log_file_path": log_file_path}

    @staticmethod
    def parse_log_format(log_format: str) -> dict[str, int]:
        columns = shlex.split(log_format)
        offset = 0
        config_columns: dict[str, int] = {}
        for i, col in enumerate(columns):
            if re.search(r"^\$remote_addr$", col):
                config_columns["remote_addr"] = i + offset
            elif re.search(r"^\$host$", col):
                config_columns["host"] = i + offset
            elif re.search(r"\$time_local", col):
                config_columns["time_local"] = i + offset
                offset += 1  # time_local is two columns in the log
            elif re.search(r"^\$request$", col):
                config_columns["request"] = i + offset
            elif re.search(r"^\$status$", col):
                config_columns["status"] = i + offset
            elif re.search(r"^\$upstream_response_time$", col):
                config_columns["upstream_response_time"] = i + offset
            elif re.search(r"^\$http_user_agent$", col):
                config_columns["http_user_agent"] = i + offset
            elif re.search(r"^\$http_referer$", col):
                config_columns["http_referer"] = i + offset
        return config_columns

    @staticmethod
    def parse_log_line(
        line: str, config_columns: dict[str, int]
    ) -> LogLine | None:
        try:
            columns = shlex.split(line)
        except ValueError:
            # cannot parse line
            logging.error(f"Could not parse log line: {line.strip()}")
            return
        try:
            ip = columns[config_columns["remote_addr"]]
            upstream_response_time = columns[config_columns["upstream_response_time"]]
            req_ts = (
                columns[config_columns["time_local"]]
                + " "
                + columns[config_columns["time_local"] + 1]
            )
            req_ts = datetime.datetime.strptime(
                req_ts, "[%d/%b/%Y:%H:%M:%S %z]"
            ).timestamp()
            http_status = columns[config_columns["status"]]
            path = Nginx.parse_path(columns[config_columns["request"]])
            req = columns[config_columns["host"]] + path
            ua = columns[config_columns["http_user_agent"]]
            referer = columns[config_columns["http_referer"]]
        except (IndexError, KeyError):
            logging.error(
                f"Could not parse log line (missing columns): {line.strip()}")
            return
        if upstream_response_time == "-":
            upstream_response_time = 0.01
        return LogLine(
            {
                "ip": ip,
                "upstream_response_time": float(upstream_response_time),
                "req_ts": int(req_ts),
                "http_status": int(http_status),
                "req": req,
                "ua": ua,
                "referer": referer,
                "log_line": line,
                "host": columns[config_columns["host"]],
                "path": path,
            }
        )

    @staticmethod
    def parse_path(request: str) -> str:
        # request is like: "GET /path/to/resource HTTP/1.1"
        try:
            path = request.split(" ")[1].split("?")[0]
        except IndexError:
            path = request.split("?")[0]
        return path

    @staticmethod
    def process_line(config: Config, rts: RunTimeStats, log_line: LogLine, line: str, debug: str = "") -> str:
        ua_data: IpData | None = None
        url_data: IpData | None = None

        rts.lines_parsed += 1
        if log_line.ip.strip() == '':
            logging.info(f"strange ip {log_line.host=} {log_line.ip=}")
            logging.info(f"line: {line}")
        if rts.ip_whitelist.is_whitelisted(log_line.host, log_line.ip):
            return Nginx.STATUS_OK
        if Bots.good_bot(config, log_line.ua):
            return Nginx.STATUS_OK
        if rts.ip_blacklist and rts.ip_blacklist.is_ip_blacklisted(log_line.ip):
            IpTables.ban(log_line.ip, rts, config, None)
            logging.debug(f"ban: {log_line.ip}; Found in blacklist")
            return Nginx.STATUS_BANNED
        if Bots.bad_bot(config, log_line.ua):
            IpTables.ban(log_line.ip, rts, config)
            logging.info(f"ban: {log_line.ip}; Bad bot detected: {log_line.ua}")
            return Nginx.STATUS_BANNED
        if rts.ip_whitelist.is_trigger(log_line.host, log_line.ip, log_line.path, log_line.http_status):
            return Nginx.STATUS_OK
        if log_line.path.endswith(tuple(config.ignore_extensions)):
            return Nginx.STATUS_OK
        ip_data = rts.ip_stats.get(log_line.ip)
        if ip_data is None:
            ip_data = IpData(
                log_line.ip,
                'ip',
                {
                    "raw_lines": ExpiringList(expiration_time=config.time_frame),
                    "log_lines": ExpiringList(expiration_time=config.time_frame),
                }
            )
        ip_data.raw_lines.append(log_line.req_ts, line)
        ip_data.log_lines.append(log_line.req_ts, log_line)

        if config.url_stats:
            url_data = rts.url_stats.get(log_line.path)
            if url_data is None:
                url_data = IpData(
                    log_line.path,
                    'path',
                    {
                        "raw_lines": ExpiringList(expiration_time=config.time_frame),
                        "log_lines": ExpiringList(expiration_time=config.time_frame),
                    }
                )
            url_data.raw_lines.append(log_line.req_ts, line)
            url_data.log_lines.append(log_line.req_ts, log_line)

        if config.ua_stats:
            ua_data = rts.ua_stats.get(log_line.ua)
            if ua_data is None:
                ua_data = IpData(
                    log_line.ua,
                    'user_agent',
                    {
                        "raw_lines": ExpiringList(expiration_time=config.time_frame),
                        "log_lines": ExpiringList(expiration_time=config.time_frame),
                    }
                )
            ua_data.raw_lines.append(log_line.req_ts, line)
            ua_data.log_lines.append(log_line.req_ts, log_line)

        if KnownAttacks.is_known(config, log_line):
            IpTables.ban(log_line.ip, rts, config, ip_data.raw_lines)
            logging.info(f"Ban: {log_line.ip}; Known attack detected: {log_line.req}")
            return Nginx.STATUS_BANNED
        Checks.log_probes(log_line, line, rts)

        rts.ip_stats.create(ts=log_line.req_ts, key=log_line.ip, value=ip_data)
        if config.url_stats and url_data is not None:
            rts.url_stats.create(ts=log_line.req_ts,
                                 key=log_line.path, value=url_data)
        if config.ua_stats and ua_data is not None:
            rts.ua_stats.create(ts=log_line.req_ts,
                                key=log_line.ua, value=ua_data)

        if Checks.bad_http_stats(config, log_line, ip_data):
            IpTables.ban(log_line.ip, rts, config, ip_data.raw_lines)
            return Nginx.STATUS_BANNED
        if Checks.bad_steal_ratio(config, log_line, ip_data):
            IpTables.ban(log_line.ip, rts, config, ip_data.raw_lines)
            return Nginx.STATUS_BANNED
        return Nginx.STATUS_OK
