import yaml


class Config:
    def __init__(self) -> None:
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
        self.ban_time = 600
        self.background = False
        self.url_stats = False
        self.ua_stats = False
        self.lockfile: str = "/var/run/min.waf.pid"
        self.detail_lines: int = 12
        self.refresh_time: int = 60
        self.whitelist_triggers: dict[str, list[dict[str, str]]] = {}
        self.silent: bool = False
        self.log_file_path: str = ""
        self.good_bots: dict[str, list[str]] = {}
        self.bad_bots: dict[str, list[str]] = {}

    def load(self, filepath: str) -> None:
        with open(filepath, "r") as f:
            data = yaml.safe_load(f)
            for key, value in data.items():
                if hasattr(self, key):
                    setattr(self, key, value)
