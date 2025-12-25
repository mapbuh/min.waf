import logging

from classes.Bots import Bots
from classes.Checks import Checks
from classes.Config import Config
from classes.ExpiringList import ExpiringList
from classes.IpData import IpData
from classes.KnownAttacks import KnownAttacks
from classes.HttpHeaders import HttpHeaders
from classes.RunTimeStats import RunTimeStats


class Nginx:
    STATUS_BAN = 'ban'
    STATUS_OK = 'ok'
    STATUS_SLOW = 'slow'
    STATUS_UNKNOWN = 'unknown'

    @staticmethod
    def parse_path(request: str) -> str:
        # request is like: "GET /path/to/resource HTTP/1.1"
        try:
            path = request.split(" ")[1].split("?")[0]
        except IndexError:
            path = request.split("?")[0]
        return path

    @staticmethod
    def process_http_request(
        config: Config,
        rts: RunTimeStats,
        httpHeaders: HttpHeaders,
    ) -> str:
        ua_data: IpData | None = None
        url_data: IpData | None = None

        logger = logging.getLogger("min.waf")
        if httpHeaders.ip.strip() == '' and httpHeaders.host.strip() == '':
            return Nginx.STATUS_UNKNOWN
        rts.lines_parsed += 1
        if config.bot_whitelist.check(httpHeaders.ua, httpHeaders.ip):
            if (
                config.config.getboolean('log', 'whitelist')
                and config.config.getboolean('log', 'bots')
            ):
                logger.info(f"{httpHeaders.ip} {httpHeaders.ua} bot whitelist match found")
            return Nginx.STATUS_OK
        if Bots.good_bot(config, httpHeaders.ua):
            if config.config.getboolean('log', 'bots') and config.config.getboolean('log', 'whitelist'):
                logger.info(f"{httpHeaders.ip} good bot: {httpHeaders.ua}")
            return Nginx.STATUS_OK
        if rts.ip_blacklist and rts.ip_blacklist.is_ip_blacklisted(httpHeaders.ip):
            return Nginx.STATUS_BAN
        if Bots.bad_bot(config, httpHeaders.ua):
            if config.config.getboolean('log', 'bots'):
                logger.info(f"{httpHeaders.ip} banned; Bad bot detected: {httpHeaders.ua}")
            return Nginx.STATUS_BAN
        if (
            config.host_has_trigger(httpHeaders.host)
            and rts.ip_whitelist.is_trigger(
                httpHeaders.host,
                httpHeaders.ip,
                httpHeaders.path,
                httpHeaders.http_status
            )
        ):
            return Nginx.STATUS_OK
        if httpHeaders.path.endswith(tuple(config.getlist('main', 'static_files'))):
            return Nginx.STATUS_OK
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

        if KnownAttacks.is_known(config, httpHeaders):
            return Nginx.STATUS_BAN
        Checks.log_probes(httpHeaders, rts)

        rts.ip_stats.create(ts=httpHeaders.ts, key=httpHeaders.ip, value=ip_data)
        if config.config.getboolean('main', 'url_stats') and url_data is not None:
            rts.url_stats.create(ts=httpHeaders.ts,
                                 key=httpHeaders.path, value=url_data)
        if config.config.getboolean('main', 'ua_stats') and ua_data is not None:
            rts.ua_stats.create(ts=httpHeaders.ts,
                                key=httpHeaders.ua, value=ua_data)

        if Checks.bad_http_stats(config, httpHeaders, ip_data):
            return Nginx.STATUS_BAN
        if Checks.bad_steal_ratio(config, ip_data):
            return Nginx.STATUS_BAN
        return Nginx.STATUS_OK
