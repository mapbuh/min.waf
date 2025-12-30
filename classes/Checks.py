import logging
import urllib.parse

from classes.Bots import Bots
from classes.Config import Config
from classes.ExpiringList import ExpiringList
from classes.HttpHeaders import HttpHeaders
from classes.IpData import IpData
from classes.KnownAttacks import KnownAttacks
from classes.RunTimeStats import RunTimeStats


class Checks:
    @staticmethod
    def headers(httpHeaders: HttpHeaders, config: Config, rts: RunTimeStats) -> bool:
        logger = logging.getLogger("min.waf")
        if httpHeaders.ip in rts.banned_ips.keys():
            if False and config.config.getboolean('log', 'bans'):
                logger.info(f"{httpHeaders.ip} banned; already banned")
            httpHeaders.status = HttpHeaders.STATUS_BAD
            return False
        if rts.ip_whitelist.is_whitelisted(httpHeaders.host, httpHeaders.ip):
            httpHeaders.status = HttpHeaders.STATUS_GOOD
            return True
        if config.bot_whitelist.check(httpHeaders.ua, httpHeaders.ip):
            if config.config.getboolean('log', 'bot_whitelist'):
                logger.info(f"{httpHeaders.ip} bot whitelist match found")
            httpHeaders.status = HttpHeaders.STATUS_GOOD
            return True
        if Bots.good_bot(config, httpHeaders.ua):
            if config.config.getboolean('log', 'good_bots'):
                logger.info(f"{httpHeaders.ip} good bot: {httpHeaders.ua}")
            httpHeaders.status = HttpHeaders.STATUS_GOOD
            return True
        if rts.ip_blacklist and rts.ip_blacklist.is_ip_blacklisted(httpHeaders.ip):
            httpHeaders.status = HttpHeaders.STATUS_BAD
            return False
        if Bots.bad_bot(config, httpHeaders.ua):
            if config.config.getboolean('log', 'bad_bots'):
                logger.info(f"{httpHeaders.ip} banned; Bad bot detected: {httpHeaders.ua}")
            httpHeaders.status = HttpHeaders.STATUS_BAD
            return False
        if httpHeaders.path.endswith(tuple(config.getlist('main', 'static_files'))):
            httpHeaders.status = HttpHeaders.STATUS_GOOD
            return True
        if config.config.getboolean("main", "inspect_packets"):
            for signature in config.harmful_patterns():
                if signature.lower() in urllib.parse.unquote(httpHeaders.path).lower():
                    logger.info(f"Harmful signature detected in header: {signature}")
                    httpHeaders.status = HttpHeaders.STATUS_BAD
                    return False
        return True

    @staticmethod
    def headers_with_status(httpHeaders: HttpHeaders, config: Config, rts: RunTimeStats) -> bool:
        if httpHeaders.status == HttpHeaders.STATUS_GOOD:
            return True
        if httpHeaders.status == HttpHeaders.STATUS_BAD:
            return False
        if (
            config.host_has_trigger(httpHeaders.host)
            and rts.ip_whitelist.is_trigger(
                httpHeaders.host,
                httpHeaders.ip,
                httpHeaders.path,
                httpHeaders.http_status or 0
            )
        ):
            httpHeaders.status = HttpHeaders.STATUS_GOOD
            return True
        if not Checks.process_http_request(config, rts, httpHeaders):
            httpHeaders.status = HttpHeaders.STATUS_BAD
            return False
        return True

    @staticmethod
    def content(config: Config, httpHeaders: HttpHeaders, buffer: bytes, clean_upto: int) -> tuple[bool, int]:
        if httpHeaders.status == HttpHeaders.STATUS_GOOD:
            return True, len(buffer)
        if httpHeaders.status == HttpHeaders.STATUS_BAD:
            return False, clean_upto
        if config.config.get('main', 'inspect_packets') == 'False':
            return True, clean_upto
        if clean_upto >= config.config.getint("main", "max_inspect_size"):
            return True, clean_upto
        # Inspect only the new data since last clean point
        dirty_data_from: int = clean_upto - config.longest_harmful_pattern() + 1
        if dirty_data_from < 0:
            dirty_data_from = 0
        dirty_data = buffer[dirty_data_from:]
        for signature in config.harmful_patterns():
            if signature.encode().lower() in dirty_data.lower():
                logger = logging.getLogger("min.waf")
                logger.info(f"Harmful signature detected in content: {signature}")
                httpHeaders.status = HttpHeaders.STATUS_BAD
                return False, clean_upto
        clean_upto = len(buffer)
        return True, clean_upto

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

    @staticmethod
    def process_http_request(
        config: Config,
        rts: RunTimeStats,
        httpHeaders: HttpHeaders,
    ) -> bool:
        ua_data: IpData | None = None
        url_data: IpData | None = None

        if httpHeaders.ip.strip() == '' and httpHeaders.host.strip() == '':
            return True
        ip_data = rts.ip_stats.get(httpHeaders.ip)
        if ip_data is None:
            ip_data = IpData(
                config,
                httpHeaders.ip,
                'ip',
                {
                    "raw_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
                    "log_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
                }
            )
        ip_data.log_lines.append(httpHeaders.ts, httpHeaders)

        if config.config.getboolean('main', 'url_stats'):
            url_data = rts.url_stats.get(httpHeaders.path)
            if url_data is None:
                url_data = IpData(
                    config,
                    httpHeaders.path,
                    'path',
                    {
                        "raw_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
                        "log_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
                    }
                )
            url_data.log_lines.append(httpHeaders.ts, httpHeaders)

        if config.config.getboolean('main', 'ua_stats'):
            ua_data = rts.ua_stats.get(httpHeaders.ua)
            if ua_data is None:
                ua_data = IpData(
                    config,
                    httpHeaders.ua,
                    'user_agent',
                    {
                        "raw_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
                        "log_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
                    }
                )
            ua_data.log_lines.append(httpHeaders.ts, httpHeaders)

        if Checks.bad_http_stats(config, httpHeaders, ip_data):
            return False
        if Checks.bad_steal_ratio(config, ip_data):
            return False
        if KnownAttacks.is_known(config, httpHeaders):
            return False
        Checks.log_probes(httpHeaders, rts)

        rts.ip_stats.create(ts=httpHeaders.ts, key=httpHeaders.ip, value=ip_data)
        if config.config.getboolean('main', 'url_stats') and url_data is not None:
            rts.url_stats.create(ts=httpHeaders.ts,
                                 key=httpHeaders.path, value=url_data)
        if config.config.getboolean('main', 'ua_stats') and ua_data is not None:
            rts.ua_stats.create(ts=httpHeaders.ts,
                                key=httpHeaders.ua, value=ua_data)

        return True
