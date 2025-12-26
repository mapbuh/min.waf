import configparser
import functools
import ipaddress
import logging
import os
import random

from classes import Utils


class Config:
    def __init__(self, filename: str) -> None:
        self.filename: str = filename
        self.load()
        self.bot_whitelist: BotWhitelist = BotWhitelist(self)

    def load(self) -> None:
        minwaf_path: str = os.path.dirname(os.path.realpath(__file__)) + "/.."
        self.config = configparser.ConfigParser()
        self.config.read(minwaf_path + "/defaults.conf")
        self.config.read(self.filename)

    @property
    def mode_honeypot(self) -> bool:
        return self.config.get('main', 'ban_method') == 'internal' and bool(self.config.get('log', 'requests'))

    def getlist(self, section: str, option: str) -> list[str]:
        return [s for s in self.config.get(section, option).split("\n") if s]

    @functools.lru_cache()
    def getlistint(self, section: str, option: str) -> list[int]:
        return [int(s) for s in self.config.get(section, option).split("\n") if s]

    @functools.lru_cache()
    def harmful_patterns(self) -> list[str]:
        sql_injections = self.getlist('signatures', 'sql_injections')
        php_injections = self.getlist('signatures', 'php_injections')
        node_injections = self.getlist('signatures', 'node_injections')
        return sql_injections + php_injections + node_injections

    @functools.lru_cache()
    def longest_harmful_pattern(self) -> int:
        longest = 0
        for pattern in self.harmful_patterns():
            if len(pattern) > longest:
                longest = len(pattern)
        return longest

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
        return [t for t in self.whitelist_triggers() if t['host'] == host]

    @functools.lru_cache()
    def host_has_trigger(self, host: str) -> bool:
        for t in self.whitelist_triggers():
            if t['host'] == host:
                return True
        return False


class BotWhitelist:
    def __init__(self, config: Config) -> None:
        self.config: Config = config
        self.whitelist: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = self.load()
        self.whitelist_cache: dict[str, dict[str, str]] = {}

    def load(self) -> dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
        logger: logging.Logger = logging.getLogger("min.waf")
        bot_sections: list[str] = []
        for section in self.config.config.sections():
            if section.startswith('bots.'):
                bot_sections.append(section)

        whitelist_bots_list: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}
        for section in bot_sections:
            if (
                self.config.config.get(section, 'action') == 'allow'
                and self.config.config.get(section, 'ip_ranges_url')
            ):
                try:
                    data = Utils.requests_get_cached_json(
                        self.config.config.get(section, 'ip_ranges_url'),
                        timeout=10,
                        ttl=86400 + random.randint(0, 60),
                        strict=False
                    )
                    prefixes = data.get('prefixes', [])
                    for prefix in prefixes:
                        ip_prefix = prefix.get('ipv4Prefix') or prefix.get('ipv6Prefix')
                        if ip_prefix:
                            try:
                                user_agent = self.config.config.get(section, 'user_agent')
                                if user_agent not in whitelist_bots_list:
                                    whitelist_bots_list[user_agent] = []
                                whitelist_bots_list[user_agent].append(ipaddress.ip_network(ip_prefix))
                            except ValueError:
                                logger.warning(f"Invalid network in bot whitelist: {ip_prefix}")
                except Exception as e:
                    logger.warning(f"Failed to load IP ranges for bot {section}: {e}")
        self.whitelist_cache = {}
        return whitelist_bots_list

    def check(self, user_agent: str, ip: str) -> bool:
        if user_agent in self.whitelist_cache:
            if ip in self.whitelist_cache[user_agent]:
                return True
        for bot, networks in self.whitelist.items():
            if bot.lower() in user_agent.lower():
                for net in networks:
                    if ipaddress.ip_address(ip) in net:
                        self.whitelist_cache.setdefault(user_agent, {})[ip] = bot
                        return True
        return False
