import logging

from classes.Config import Config
from classes.LogLine import LogLine
from classes.KnownAttacks import KnownAttacks
from classes.IpData import IpData
from classes.RunTimeStats import RunTimeStats


class Checks:
    @staticmethod
    def bad_req(config: Config, log_line: LogLine) -> str | None:
        if KnownAttacks.is_known(config, log_line.path) and (log_line.http_status in [404, 500]):
            return f"Known attack detected: {log_line.path} http_status: {log_line.http_status}"
        return None

    @staticmethod
    def bad_stats(config: Config, log_line: LogLine, ip_data: IpData) -> str | None:
        if ip_data.http_status_bad >= config.http_status_bad_threshold:
            return f"Bad http_status ratio: {ip_data.http_status_bad:.2f} from {ip_data.request_count} reqs"
        if ip_data.steal_time < (-config.steal_total) and ip_data.avail_time > config.steal_over_time:
            logging.info(
                f"IP {log_line.ip} is stealing time: {ip_data.steal_time:.2f}s "
                f"t/a: {ip_data.total_time:.2f}/{ip_data.avail_time:.2f} "
                f"req: {ip_data.request_count} ratio: {ip_data.steal_ratio:.2f}"
            )
            return None
        return None

    @staticmethod
    def log_probes(log_line: LogLine, raw_line: str, rts: RunTimeStats) -> None:
        # TODO - make it LRU cache
        if log_line.http_status != 200:
            rts.inter_domain.add(log_line.path, log_line.host, log_line.http_status, raw_line)
