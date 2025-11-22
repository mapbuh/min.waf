import yaml


class Config:
    def __init__(self) -> None:
        # when reloading config, these keys will not be changed
        self.immutables: list[str] = []
        self.config_file_path: str = ""
        self.columns: dict[str, int] = {
            "remote_addr": -1,
            "host": -1,
            "time_local": -1,
            "request": -1,
            "status": -1,
            "upstream_response_time": -1,
            "http_referer": -1,
            "http_user_agent": -1,
        }
        self.time_frame = 300
        self.debug: bool = False
        self.ban_time = 600
        self.url_stats = False
        self.ua_stats = False
        self.lockfile: str = "/var/run/min.waf.pid"
        self.detail_lines: int = 12
        self.refresh_time: int = 60
        self.whitelist_triggers: dict[str, list[dict[str, str]]] = {}
        self.log_file_path: str = ""
        self.good_bots: dict[str, list[str]] = {}
        self.bad_bots: dict[str, list[str]] = {}
        self.ignore_extensions: list[str] = []
        self.known_attacks: list[str] = []
        self.http_status_bad_threshold: float = 0.51
        self.proxy_listen_host: str = "127.0.0.1"
        self.proxy_listen_port: int = 9009
        # wait at list this many seconds between first and last request
        self.steal_over_time: int = 10
        # if total stolen time is more than this, consider it stealing
        self.steal_total: int = 10
        # if ratio of stolen/available time is more than this, consider it stealing
        self.steal_ratio: float = 0.3
        self.ip_blacklist: str = ''
        self.ip_blacklist_refresh_time: int = 3600
        self.iptables_chain: str = "MINWAF"
        self.mode: str = "proxy"  # or "log2ban"
        self.whitelist_expiration: int = 36000 # 10 hours, a working day plus few hours

    def load(self, filepath: str) -> None:
        self.config_file_path = filepath
        with open(filepath, "r") as f:
            data = yaml.safe_load(f)
            for key, value in data.items():
                if hasattr(self, key):
                    if key in self.immutables:
                        continue
                    setattr(self, key, value)
