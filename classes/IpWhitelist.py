from functools import lru_cache
import ipaddress
import logging
import pathlib
import re
import requests
from classes.ExpiringList import ExpiringList
from classes.Config import Config


class IpWhitelist:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.whitelist: dict[str, ExpiringList[str]] = {}
        self.whitelist_permanent: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.whitelist_bots: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}
        self.load()

    def load(self) -> None:
        self.whitelist.clear()
        self.whitelist_load_bots()
        self.whitelist_load_permanent()
        self.is_whitelisted.cache_clear()
        self.is_trigger.cache_clear()

    def whitelist_load_permanent(self) -> None:
        self.whitelist_permanent = []
        if self.config.whitelist_permanent:
            if pathlib.Path(self.config.whitelist_permanent).exists():
                with open(self.config.whitelist_permanent, 'r') as f:
                    for line in f:
                        line = re.sub(r'\s+', '', line)
                        line = re.sub(r'#.*$', '', line)
                        if line:
                            try:
                                self.whitelist_permanent.append(ipaddress.ip_network(line))
                            except ValueError:
                                logging.warning(f"Invalid network in permanent whitelist: {line}")
            else:
                logging.warning(f"Permanent whitelist file {self.config.whitelist_permanent} not found.")

    def whitelist_load_bots(self) -> None:
        self.whitelist_bots = {}
        if not hasattr(self.config, 'bots'):
            return
        for bot, bot_data in self.config.bots.items():
            if bot_data.get('action') == 'allow' and bot_data.get('ip_ranges_url'):
                try:
                    response = requests.get(bot_data['ip_ranges_url'], timeout=10)
                    response.raise_for_status()
                    data = response.json()
                    prefixes = data.get('prefixes', [])
                    for prefix in prefixes:
                        ip_prefix = prefix.get('ipv4Prefix') or prefix.get('ipv6Prefix')
                        if ip_prefix:
                            try:
                                user_agent = bot_data['user_agent']
                                if user_agent not in self.whitelist_bots:
                                    self.whitelist_bots[user_agent] = []
                                self.whitelist_bots[user_agent].append(ipaddress.ip_network(ip_prefix))
                            except ValueError:
                                logging.warning(f"Invalid network in bot whitelist: {ip_prefix}")
                    logging.info(f"Loaded {len(prefixes)} IP ranges for bot {bot}")
                except Exception as e:
                    logging.warning(f"Failed to load IP ranges for bot {bot}: {e}")

    @lru_cache(maxsize=1024)
    def is_whitelisted(self, host: str, ip: str, user_agent: str) -> bool:
        if ip.strip() == '':
            logging.info(f"strange ip {host=} {ip=}")
            return False
        for net in self.whitelist_permanent:
            if ipaddress.ip_address(ip) in net:
                logging.debug(f"{ip} permanent whitelist match in {net}")
                return True
        try:
            if host in self.whitelist:
                if ip in self.whitelist[host].values():
                    self.whitelist[host].touch(ip)
                    logging.debug(f"{ip} found in temporary whitelist for host {host}")
                    return True
        except ValueError as err:
            logging.warning(f"Whitelist checking {ip} {err=}")
        for bot, networks in self.whitelist_bots.items():
            if bot in user_agent:
                for net in networks:
                    if ipaddress.ip_address(ip) in net:
                        logging.debug(f"{ip} bot whitelist match in {net} for bot {bot}")
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
