from IpData import IpData
from ExpiringDict import ExpiringDict
from Config import Config


class RunTimeStats:
    def __init__(self, config: Config) -> None:
        self.ip_whitelist: dict[str, list[str]] = {}
        self.banned_ips: dict[str, float] = {}
        self.ip_stats: ExpiringDict[IpData] = ExpiringDict[IpData](config.time_frame)
        self.url_stats: ExpiringDict[IpData] = ExpiringDict[IpData](config.time_frame)
        self.ua_stats: ExpiringDict[IpData] = ExpiringDict[IpData](config.time_frame)
        self.bans = 0
