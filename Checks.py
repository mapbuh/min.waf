from LogLine import LogLine
from KnownAttacks import KnownAttacks
from IpData import IpData
import logging


class Checks:
    @staticmethod
    def bad_req(log_line: LogLine) -> bool:
        if KnownAttacks.is_known(log_line.path) and (log_line.http_status == 404 or log_line.http_status == 500):
            logging.info(
                f"{log_line.ip} - known attack detected: {log_line.path}"
            )
            return True
        return False

    @staticmethod
    def bad_stats(log_line: LogLine, ip_data: IpData) -> bool:
        if ip_data.http_status_bad >= 0.33:
            logging.debug(
                f"IP {log_line.ip} - "
                f"Requests: {ip_data.request_count}, "
                f"Bad HTTP Statuses: {ip_data.http_status_bad} "
            )
            return True
        if ip_data.steal_time < -30 and ip_data.avail_time > 10:
            logging.debug(
                f"IP {log_line.ip} is stealing time: {ip_data.steal_time:.2f}s "
                f"t/a: {ip_data.total_time:.2f}/{ip_data.avail_time:.2f} "
                f"req: {ip_data.request_count} ratio: {ip_data.steal_ratio:.2f}"
            )
            return False
        return False
