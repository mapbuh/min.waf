import time


class HttpHeaders:
    STATUS_NEUTRAL = 0
    STATUS_BAD = -1
    STATUS_GOOD = 1

    def __init__(
        self,
        host: str = '',
        ip: str = '',
        ua: str = '',
        referer: str = '',
        upstream_host: str = '',
        upstream_port: int = 0,
        method: str = '',
        path: str = '',
        proto: str = '',
        http_status: int | None = None,
        ts: float | None = None,
        upstream_response_time: float | None = None,
    ) -> None:
        self.host = host
        self.ip = ip
        self.ua = ua
        self.referer = referer
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.method = method
        self.path = path
        self.proto = proto
        self.req = f"{host}{path}"
        self.http_status = http_status
        self.ts: float = ts or time.time()
        self.status: int = self.STATUS_NEUTRAL
        self.logged: bool = False
        self.upstream_response_time: float = upstream_response_time or 0.0
