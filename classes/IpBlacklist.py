import logging
import os
import pathlib
import requests
import time
from functools import lru_cache
from classes.Config import Config


class IpBlacklist:

    def __init__(self, config: Config) -> None:
        self.config = config
        self.list: list[str] = []
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.filename = os.path.join(current_dir, "../ip_blacklist.txt")
        self.refresh_list()

    def refresh_list(self) -> None:
        if not self.is_file_recent(self.filename, self.config.ip_blacklist_refresh_time):
            logging.info("blacklist downloading")
            self.download_file(self.config.ip_blacklist, self.filename)
        elif pathlib.Path(self.filename + ".downloaded").exists():
            logging.info("blacklist downloaded")
            with open(self.filename, 'r') as f:
                self.list = f.read().splitlines()
            pathlib.Path(self.filename + ".downloaded").unlink(missing_ok=True)
        elif not self.list:
            logging.info("loaded, no check")
            with open(self.filename, 'r') as f:
                self.list = f.read().splitlines()

    def is_file_recent(self, filename: str, max_age_seconds: int) -> bool:
        if not os.path.exists(filename):
            return False
        mtime = os.path.getmtime(filename)
        return (time.time() - mtime) < max_age_seconds

    def download_file(self, url: str, filename: str) -> None:
        if os.path.exists(filename + ".downloading"):
            return
        if os.fork() == 0:
            pathlib.Path(filename + ".downloading").touch()
            response = requests.get(url)
            response.raise_for_status()  # Ensure we notice bad responses
            with open(filename, 'wb') as f:
                f.write(response.content)
                pathlib.Path(filename + ".downloading").unlink(missing_ok=True)
                pathlib.Path(filename + ".downloaded").touch()
            os._exit(0)

    @lru_cache(maxsize=1024)
    def is_ip_blacklisted(self, ip: str) -> bool:
        return ip in self.list
