import os
import requests
import time
from functools import lru_cache
from Config import Config


class IpBlacklist:

    def __init__(self, config: Config) -> None:
        self.config = config
        self.list: list[str] = []
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.filename = os.path.join(current_dir, "ip_blacklist.txt")
        self.refresh_list()

    def refresh_list(self) -> None:
        if not self.is_file_recent(self.filename, self.config.ip_blacklist_refresh_time):
            self.download_file(self.config.ip_blacklist, self.filename)
            with open(self.filename, 'r') as f:
                self.list = f.read().splitlines()
        elif not self.list:
            with open(self.filename, 'r') as f:
                self.list = f.read().splitlines()

    def is_file_recent(self, filename: str, max_age_seconds: int) -> bool:
        if not os.path.exists(filename):
            return False
        mtime = os.path.getmtime(filename)
        return (time.time() - mtime) < max_age_seconds

    def download_file(self, url: str, filename: str) -> None:
        response = requests.get(url)
        response.raise_for_status()  # Ensure we notice bad responses
        with open(filename, 'wb') as f:
            f.write(response.content)

    @lru_cache(maxsize=1024)
    def is_ip_blacklisted(self, ip: str) -> bool:
        return ip in self.list
