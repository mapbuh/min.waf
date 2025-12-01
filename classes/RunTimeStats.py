import logging

from classes.IpBlacklist import IpBlacklist
from classes.IpData import IpData
from classes.ExpiringDict import ExpiringDict
from classes.Config import Config
from classes.IpWhitelist import IpWhitelist


class IDSHost:
    def __init__(self) -> None:
        self.http_statuses: dict[int, list[str]] = {}


class IDSPath:
    def __init__(self) -> None:
        self.hosts: dict[str, IDSHost] = {}

    def total_count(self) -> int:
        if len(self.hosts) < 3:
            return 0
        count: int = 0
        for host in self.hosts.values():
            for status in host.http_statuses.values():
                count += len(status)
        return count

    def statuses(self) -> list[int]:
        status_set: set[int] = set()
        for host in self.hosts.values():
            for status in host.http_statuses.keys():
                status_set.add(status)
        return list(status_set)

    def lines(self) -> list[str]:
        lines: list[str] = []
        for host in self.hosts.values():
            for status in host.http_statuses.values():
                for line in status:
                    lines.append(line)
        return lines


class IDS:
    def __init__(self) -> None:
        self.path: dict[str, IDSPath] = {}

    def __repr__(self) -> str:
        res = ""
        for path in self.path:
            for host in self.path[path].hosts:
                for status in self.path[path].hosts[host].http_statuses:
                    for line in self.path[path].hosts[host].http_statuses[status]:
                        res += f"path: {path} host: {host} status: {status}\n    line: {line}\n"
        return res

    def add(self, path: str, host: str, http_status: int, raw_line: str) -> None:
        if path not in self.path:
            self.path[path] = IDSPath()
        if host not in self.path[path].hosts:
            self.path[path].hosts[host] = IDSHost()
        if http_status not in self.path[path].hosts[host].http_statuses:
            self.path[path].hosts[host].http_statuses[http_status] = []
        self.path[path].hosts[host].http_statuses[http_status].append(raw_line)


class RunTimeStats:
    def __init__(self, config: Config) -> None:
        self.start_time: float = 0
        self.lines_parsed: int = 0
        self.ip_whitelist: IpWhitelist = IpWhitelist(config)
        self.banned_ips: dict[str, float] = {}
        self.ip_stats: ExpiringDict[IpData] = ExpiringDict[IpData](config.time_frame)
        self.url_stats: ExpiringDict[IpData] = ExpiringDict[IpData](config.time_frame)
        self.ua_stats: ExpiringDict[IpData] = ExpiringDict[IpData](config.time_frame)
        self.bans: int = 0
        self.inter_domain: IDS = IDS()
        self.ip_blacklist: IpBlacklist | None = None

    def init_ip_blacklist(self, config: Config) -> None:
        logging.info("Initializing IP blacklist")
        if config.ip_blacklist:
            self.ip_blacklist = IpBlacklist(config)
        else:
            self.ip_blacklist = None
