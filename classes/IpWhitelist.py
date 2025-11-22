from functools import lru_cache
import logging
from classes.ExpiringList import ExpiringList
from classes.Config import Config

class IpWhitelist:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.whitelist: dict[str, ExpiringList[str]] = {}

    @lru_cache(maxsize=1024)
    def is_whitelisted(self, host: str, ip: str) -> bool:
        if not host in self.whitelist:
            return False
        if ip in self.whitelist[host].values():
            return True
        return False
    
    @lru_cache(maxsize=1024)
    # not passing log_line to make cache effective
    def is_trigger(self, host: str, ip: str, path: str, http_status: int) -> bool:
        if not self.config.whitelist_triggers.get(host):
            return False
        for trigger in self.config.whitelist_triggers[host]:
            if path == trigger['path'] and str(http_status) == str(trigger['http_status']):
                if host not in self.whitelist:
                    self.whitelist[host] = ExpiringList(expiration_time=self.config.whitelist_expiration)
                self.whitelist[host].append(None, ip)
                self.is_whitelisted.cache_clear()
                logging.info(
                    f"{ip} whitelisted due to trigger "
                    f"on path {host}{path} with status "
                    f"{http_status}")
                return True
        return False