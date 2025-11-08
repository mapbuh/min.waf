import time


class LogLine:
    def __init__(self, data: dict[str, str | float | int]):
        """
        Initializes a LogLine instance with data from a dictionary.

        Args:
            data (dict): A dictionary containing log line information with the following possible keys:
                - "ip": The IP address associated with the log entry.
                - "upstream_response_time": The response time from the upstream server.
                - "req_ts": The request timestamp.
                - "http_status": The HTTP status code of the response.
                - "req": The request string.
                - "ua": The user agent string.
                - "referer": The referer URL.
                - "log_line": The raw log line.
                - "host": The host header value.
                - "path": The request path.
        """
        self._ip = str(data.get("ip", ""))
        self._upstream_response_time = float(data.get("upstream_response_time", "0.0"))
        self._req_ts = int(data.get("req_ts", time.time()))
        self._http_status = int(data.get("http_status", 200))
        self._req = str(data.get("req", ""))
        self._ua = str(data.get("ua", ""))
        self._referer = str(data.get("referer", ""))
        if "://" in self._referer:
            self._referer = self._referer.split("://")[1].split("?")[0]
        else:
            self._referer = self._referer.split("?")[0]
        self._log_line = str(data.get("log_line", ""))
        self._host = str(data.get("host", ""))
        self._path = str(data.get("path", ""))

    def __repr__(self) -> str:
        return (f"LogLine(ip={self._ip}, upstream_response_time={self._upstream_response_time}, "
                f"req_ts={self._req_ts}, http_status={self._http_status}, req={self._req}, "
                f"ua={self._ua}, referer={self._referer}, log_line={self._log_line}, "
                f"host={self._host}, path={self._path})")

    @property
    def ip(self) -> str:
        return self._ip

    @property
    def upstream_response_time(self) -> float:
        return self._upstream_response_time

    @property
    def req_ts(self) -> int:
        return self._req_ts

    @property
    def http_status(self) -> int:
        return self._http_status

    @property
    def req(self) -> str:
        return self._req

    @property
    def ua(self) -> str:
        return self._ua

    @property
    def referer(self) -> str:
        return self._referer

    @property
    def log_line(self) -> str:
        return self._log_line

    @property
    def host(self) -> str:
        return self._host

    @property
    def path(self) -> str:
        return self._path
