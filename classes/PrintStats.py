import logging
import time
from classes.RunTimeStats import RunTimeStats


class PrintStats:

    @staticmethod
    def log_stats(rts: RunTimeStats) -> None:
        logger = logging.getLogger("min.waf")
        logger.info(
            f"Running for {(time.time() - rts.start_time)/3600:.2f}h, "
            f"Total bans: {rts.bans}, {rts.bans/((time.time() - rts.start_time)/3600):.2f} bans/h, "
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
            logger.info(f"Path: {path}, Total Probes: {rts.inter_domain.path[path].total_count()}")
            counter -= 1
