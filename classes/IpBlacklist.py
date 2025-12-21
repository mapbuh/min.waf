import logging
import random
import time
from classes.Config import Config
from functools import lru_cache
from classes import Utils


class IpBlacklist:

    def __init__(self, config: Config) -> None:
        self.config = config
        self.list_valid_until = 0
        self.load()

    def load(self) -> None:
        if not self.config.config.get('main', 'ip_blacklist', fallback=''):
            self.list = []
            return
        if time.time() < self.list_valid_until:
            return
        blacklist = Utils.requests_get_cached(
            self.config.config.get('main', 'ip_blacklist'),
            timeout=10,
            ttl=self.config.config.getint('main', 'ip_blacklist_refresh_time', fallback=3600)
        )
        self.list: list[str] = blacklist.decode().splitlines()
        self.list_valid_until = time.time() + random.randint(0, 60) + \
            self.config.config.getint('main', 'ip_blacklist_refresh_time', fallback=3600)

    @lru_cache(maxsize=1024)
    def is_ip_blacklisted(self, ip: str) -> bool:
        logger = logging.getLogger("min.waf")
        if ip in self.list:
            if self.config.config.getboolean('log', 'blacklist'):
                logger.debug(f"{ip} banned; found in blacklist")
            return True
        return False
