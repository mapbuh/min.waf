from functools import lru_cache
import ipaddress
import logging
from classes.ExpiringList import ExpiringList
from classes.Config import Config


class IpWhitelist:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.whitelist: dict[str, ExpiringList[str]] = {}
        self.whitelist_permanent: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.load()

    def load(self) -> None:
        self.whitelist.clear()
        self.is_whitelisted.cache_clear()
        self.is_trigger.cache_clear()

    @lru_cache(maxsize=1024)
    def is_whitelisted(self, host: str, ip: str, user_agent: str) -> bool:
        logger = logging.getLogger("min.waf")
        for net in self.config.getlist('main', 'whitelist'):
            if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
                if self.config.config.getboolean('log', 'whitelist'):
                    logger.debug(f"{ip} permanent whitelist match in {net}")
                return True
        try:
            if host in self.whitelist:
                if ip in self.whitelist[host].values():
                    self.whitelist[host].touch(ip)
                    if self.config.config.getboolean('log', 'whitelist'):
                        logger.debug(f"{ip} found in temporary whitelist for host {host}")
                    return True
        except ValueError as err:
            logger.warning(f"Whitelist checking {ip} {err=}")
        return False

    @lru_cache(maxsize=1024)
    # not passing log_line to make cache effective
    def is_trigger(self, host: str, ip: str, path: str, http_status: int) -> bool:
        logger = logging.getLogger("min.waf")
        for trigger in self.config.whitelist_host_triggers(host):
            if path == trigger['path'] and str(http_status) == str(trigger['status']):
                if host not in self.whitelist:
                    self.whitelist[host] = ExpiringList(
                        expiration_time=self.config.config.getint('main', 'whitelist_expiration'))
                self.whitelist[host].append(None, ip)
                self.is_whitelisted.cache_clear()
                logger.info(
                    f"{ip} whitelisted due to trigger "
                    f"on path {host}{path} with status "
                    f"{http_status}")
                return True
        return False
