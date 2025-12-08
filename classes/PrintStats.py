import logging
import time
from classes.RunTimeStats import RunTimeStats


class PrintStats:
    column_1_width: int = 105
    column_2_width: int = 10
    column_3_width: int = 15
    column_4_width: int = 17
    column_5_width: int = 17
    column_6_width: int = 7
    column_23_width: int = column_2_width + column_3_width + 1
    column_456_width: int = column_4_width + column_5_width + column_6_width + 2
    column_123456_width: int = (
        column_1_width
        + column_2_width
        + column_3_width
        + column_4_width
        + column_5_width
        + column_6_width
        + 6
    )

    @staticmethod
    def log_stats(rts: RunTimeStats) -> None:
        logging.info(
            f"Running for {(time.time() - rts.start_time)/3600:.2f}h, "
            f"Total bans: {rts.bans}, "
            f"Whitelisted IPs: {', '.join(host + '/' + ip for host, ips in rts.ip_whitelist.whitelist.items() for ip in ips.values())}"
        )
        counter = 10
        for path in sorted(rts.inter_domain.path, key=lambda p: rts.inter_domain.path[p].total_count(), reverse=True):
            if counter <= 0:
                break
            if rts.inter_domain.path[path].total_count() == 0:
                continue
            if path in ["/", "/robots.txt", "/favicon.ico", "/apple-touch-icon.png"]:
                continue
            logging.debug(f"Path: {path}, Total Probes: {rts.inter_domain.path[path].total_count()}")
            counter -= 1
