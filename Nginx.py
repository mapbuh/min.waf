import datetime
import subprocess
import re
import sys
import shlex

import LogLine


class Nginx:
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
            print(f"Could not find log_format {log_file_format} in nginx config")
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
    ) -> LogLine.LogLine | None:
        try:
            columns = shlex.split(line)
        except ValueError:
            # cannot parse line
            print(f"Could not parse log line: {line.strip()}")
            return
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
        if upstream_response_time == "-":
            upstream_response_time = 0.01
        return LogLine.LogLine(
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
            # "20.65.193.163" _ [18/Oct/2025:04:23:16 +0300] "MGLNDD_144.76.163.188_443" 400 157 0 309 "-" "-" 0.122 "-" "US" "-" 1541953 1 2025-10-18T04:23:16+03:00
            path = request.split("?")[0]
        return path
