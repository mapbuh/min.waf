import configparser
import functools
import ipaddress
import logging
import os

from classes import Utils


class Config:
    def __init__(self, filename: str) -> None:
        self.filename: str = filename
        self.load()

    def load(self) -> None:
        minwaf_path: str = os.path.dirname(os.path.realpath(__file__)) + "/.."
        self.config = configparser.ConfigParser()
        self.config.read(minwaf_path + "/defaults.conf")
        self.config.read(self.filename)

    def getlist(self, section: str, option: str) -> list[str]:
        return [s for s in self.config.get(section, option).split("\n") if s]

    @property
    @functools.lru_cache()
    def harmful_patterns(self) -> list[str]:
        sql_injections = self.getlist('signatures', 'sql_injections')
        php_injections = self.getlist('signatures', 'php_injections')
        node_injections = self.getlist('signatures', 'node_injections')
        return sql_injections + php_injections + node_injections

    @property
    @functools.lru_cache()
    def longest_harmful_pattern(self) -> int:
        longest = 0
        for pattern in self.harmful_patterns:
            if len(pattern) > longest:
                longest = len(pattern)
        return longest

    @property
    @functools.lru_cache()
    def whitelist_triggers(self) -> list[dict[str, str | int]]:
        triggers: list[dict[str, str | int]] = []
        for section in self.config.sections():
            if section.startswith('whitelist_trigger.'):
                host = self.config.get(section, 'host')
                path = self.config.get(section, 'path')
                status = self.config.getint(section, 'status')
                triggers.append({
                    'host': host,
                    'path': path,
                    'status': status
                })
        return triggers

    @functools.lru_cache()
    def whitelist_host_triggers(self, host: str) -> list[dict[str, str | int]]:
        return [t for t in self.whitelist_triggers if t['host'] == host]

    @property
    @functools.lru_cache()
    def whitelist_bots(self) -> dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
        logger = logging.getLogger("min.waf")
        bot_sections: list[str] = []
        for section in self.config.sections():
            if section.startswith('bots.'):
                bot_sections.append(section)

        whitelist_bots: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}
        for section in bot_sections:
            if (
                self.config.get(section, 'action') == 'allow'
                and self.config.get(section, 'ip_ranges_url')
            ):
                try:
                    data = Utils.requests_get_cached_json(
                        self.config.get(section, 'ip_ranges_url'),
                        timeout=10,
                        since=86400
                    )
                    prefixes = data.get('prefixes', [])
                    for prefix in prefixes:
                        ip_prefix = prefix.get('ipv4Prefix') or prefix.get('ipv6Prefix')
                        if ip_prefix:
                            try:
                                user_agent = self.config.get(section, 'user_agent')
                                if user_agent not in whitelist_bots:
                                    whitelist_bots[user_agent] = []
                                whitelist_bots[user_agent].append(ipaddress.ip_network(ip_prefix))
                            except ValueError:
                                logger.warning(f"Invalid network in bot whitelist: {ip_prefix}")
                    logger.info(f"Loaded {len(prefixes)} IP ranges for bot {section}")
                except Exception as e:
                    logger.warning(f"Failed to load IP ranges for bot {section}: {e}")
        return whitelist_bots
