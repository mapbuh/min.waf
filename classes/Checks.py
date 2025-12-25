import logging
import urllib.parse

from classes.Config import Config
from classes.HttpHeaders import HttpHeaders
from classes.IpData import IpData
from classes.Bots import Bots
from classes.RunTimeStats import RunTimeStats


class Checks:
    @staticmethod
    def headers(httpHeaders: HttpHeaders, config: Config, rts: RunTimeStats) -> bool:
        logger = logging.getLogger("min.waf")
        if httpHeaders.ip in rts.banned_ips.keys():
            logger.info(f"{httpHeaders.ip} banned; already banned")
            return False
        if rts.ip_whitelist.is_whitelisted(httpHeaders.host, httpHeaders.ip, httpHeaders.ua):
            return True
        if config.bot_whitelist.check(httpHeaders.ua, httpHeaders.ip):
            if (
                config.config.getboolean('log', 'whitelist')
                and config.config.getboolean('log', 'bots')
            ):
                logger.info(f"{httpHeaders.ip} {httpHeaders.ua} bot whitelist match found")
            return True
        if Bots.good_bot(config, httpHeaders.ua):
            if config.config.getboolean('log', 'bots') and config.config.getboolean('log', 'whitelist'):
                logger.info(f"{httpHeaders.ip} good bot: {httpHeaders.ua}")
            return True
        if rts.ip_blacklist and rts.ip_blacklist.is_ip_blacklisted(httpHeaders.ip):
            return False
        if Bots.bad_bot(config, httpHeaders.ua):
            if config.config.getboolean('log', 'bots'):
                logger.info(f"{httpHeaders.ip} banned; Bad bot detected: {httpHeaders.ua}")
            return False
        if (
            config.host_has_trigger(httpHeaders.host)
            and rts.ip_whitelist.is_trigger(
                httpHeaders.host,
                httpHeaders.ip,
                httpHeaders.path,
                httpHeaders.http_status
            )
        ):
            return True
        if httpHeaders.path.endswith(tuple(config.getlist('main', 'static_files'))):
            return True
        if config.config.getboolean("main", "inspect_packets"):
            for signature in config.harmful_patterns():
                if signature.lower() in urllib.parse.unquote(httpHeaders.path).lower():
                    logger.info(f"Harmful signature detected in header: {signature}")
                    return False
        return True

    @staticmethod
    def headers_with_status(httpHeaders: HttpHeaders, config: Config, rts: RunTimeStats) -> bool:
        from classes.Nginx import Nginx
        if Nginx.process_http_request(config, rts, httpHeaders) == Nginx.STATUS_BAN:
            return False
        return True

    @staticmethod
    def content(config: Config, buffer: bytes, clean_upto: int) -> bool:
        if config.config.get('main', 'inspect_packets') == 'False':
            return True
        if clean_upto >= config.config.getint("main", "max_inspect_size"):
            return True
        # Inspect only the new data since last clean point
        dirty_data_from: int = clean_upto - config.longest_harmful_pattern() + 1
        if dirty_data_from < 0:
            dirty_data_from = 0
        dirty_data = buffer[dirty_data_from:]
        for signature in config.harmful_patterns():
            if signature.encode().lower() in dirty_data.lower():
                return False
        clean_upto = len(buffer)
        return True

    @staticmethod
    def bad_http_stats(config: Config, httpHeaders: HttpHeaders, ip_data: IpData) -> bool:
        logger = logging.getLogger("min.waf")
        if ip_data.http_status_bad >= float(config.config.get('main', 'http_status_bad_threshold')):
            logger.info(
                f"{httpHeaders.ip} banned; Bad http_status ratio: {ip_data.http_status_bad:.2f} "
                f"from {ip_data.request_count} reqs")
            return True
        return False

    @staticmethod
    def bad_steal_ratio(config: Config, ip_data: IpData) -> bool:
        logger = logging.getLogger("min.waf")
        if (
            ip_data.steal_time < (-config.config.getint('main', 'steal_total'))
            and ip_data.avail_time > config.config.getint('main', 'steal_over_time')
            and ip_data.steal_ratio > config.config.getfloat('main', 'steal_ratio')
        ):
            logger.info(
                f"{ip_data.key} banned; Stealing time: {ip_data.steal_time:.2f}s "
                f"t/a: {ip_data.total_time:.2f}/{ip_data.avail_time:.2f} "
                f"req: {ip_data.request_count} ratio: {ip_data.steal_ratio:.2f}"
            )
            return False
        return False

    @staticmethod
    def log_probes(httpHeaders: HttpHeaders, rts: RunTimeStats) -> None:
        # TODO - make it LRU cache
        if httpHeaders.http_status != 200:
            rts.inter_domain.add(httpHeaders.path, httpHeaders.host, httpHeaders.http_status or 0)
