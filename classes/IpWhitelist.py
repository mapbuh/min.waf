import functools
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

    @functools.lru_cache(maxsize=4)
    def _parsed_whitelist(self, entries: tuple[str, ...]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parse the configured whitelist networks, once per config change."""
        logger = logging.getLogger("min.waf")
        parsed: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for net in entries:
            try:
                parsed.append(ipaddress.ip_network(net))
            except ValueError as err:
                logger.warning(f"Whitelist network {net!r}: {err}")
        return parsed

    def is_whitelisted(self, host: str, ip: str) -> bool:
        logger = logging.getLogger("min.waf")
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        if addr is not None:
            networks = self._parsed_whitelist(tuple(self.config.getlist('main', 'whitelist')))
            for net in networks:
                if addr in net:
                    if self.config.config.getboolean('log', 'whitelist'):
                        logger.debug(f"{ip} permanent whitelist match in {net}")
                    return True
        if host in self.whitelist:
            if ip in self.whitelist[host].values():
                self.whitelist[host].touch(ip)
                if self.config.config.getboolean('log', 'whitelist'):
                    logger.debug(f"{ip} found in temporary whitelist for host {host}")
                return True
        return False

    def is_trigger(self, host: str, ip: str, path: str, http_status: int) -> bool:
        logger = logging.getLogger("min.waf")
        for trigger in self.config.whitelist_host_triggers(host):
            if path == trigger['path'] and str(http_status) == str(trigger['status']):
                if host not in self.whitelist:
                    self.whitelist[host] = ExpiringList(
                        expiration_time=self.config.config.getint('main', 'whitelist_expiration'))
                self.whitelist[host].append(None, ip)
                logger.info(
                    f"{ip} whitelisted due to trigger "
                    f"on path {host}{path} with status "
                    f"{http_status}")
                return True
        return False
