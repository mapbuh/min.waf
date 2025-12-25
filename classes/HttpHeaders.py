import time


class HttpHeaders:
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
        req_ts: float | None = None,
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
        self.ts = int(req_ts or time.time())
