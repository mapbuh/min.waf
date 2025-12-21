import logging

from classes.Bots import Bots
from classes.Checks import Checks
from classes.Config import Config
from classes.ExpiringList import ExpiringList
from classes.IpData import IpData
from classes.IpTables import IpTables
from classes.KnownAttacks import KnownAttacks
from classes.LogLine import LogLine
from classes.RunTimeStats import RunTimeStats


class Nginx:
    STATUS_BANNED = 'banned'
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
    def process_line(
        config: Config,
        rts: RunTimeStats,
        log_line: LogLine,
        line: str,
    ) -> str:
        ua_data: IpData | None = None
        url_data: IpData | None = None

        logger = logging.getLogger("min.waf")
        if log_line.ip.strip() == '' and log_line.host.strip() == '':
            # logger.debug(f"empty request: {line}")
            return Nginx.STATUS_UNKNOWN
        rts.lines_parsed += 1
        if rts.ip_whitelist.is_whitelisted(log_line.host, log_line.ip, log_line.ua):
            return Nginx.STATUS_OK
        if config.bot_whitelist.check(log_line.ua, log_line.ip):
            if (
                config.config.getboolean('log', 'whitelist')
                and config.config.getboolean('log', 'bots')
            ):
                logger.debug(f"{log_line.ip} {log_line.ua} bot whitelist match found")
            return Nginx.STATUS_OK
        if Bots.good_bot(config, log_line.ua):
            if config.config.getboolean('log', 'bots') and config.config.getboolean('log', 'whitelist'):
                logger.debug(f"{log_line.ip} good bot: {log_line.ua}")
            return Nginx.STATUS_OK
        if rts.ip_blacklist and rts.ip_blacklist.is_ip_blacklisted(log_line.ip):
            IpTables.ban(log_line.ip, rts, config, None)
            return Nginx.STATUS_BANNED
        if Bots.bad_bot(config, log_line.ua):
            IpTables.ban(log_line.ip, rts, config)
            if config.config.getboolean('log', 'bots'):
                logger.info(f"{log_line.ip} banned; Bad bot detected: {log_line.ua}")
            return Nginx.STATUS_BANNED
        if (
            config.host_has_trigger(log_line.host)
            and rts.ip_whitelist.is_trigger(
                log_line.host,
                log_line.ip,
                log_line.path,
                log_line.http_status
            )
        ):
            return Nginx.STATUS_OK
        if log_line.path.endswith(tuple(config.getlist('main', 'static_files'))):
            return Nginx.STATUS_OK
        ip_data = rts.ip_stats.get(log_line.ip)
        if ip_data is None:
            ip_data = IpData(
                config,
                log_line.ip,
                'ip',
                {
                    "raw_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
                    "log_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
                }
            )
        ip_data.raw_lines.append(log_line.req_ts, line)
        ip_data.log_lines.append(log_line.req_ts, log_line)

        if config.config.getboolean('main', 'url_stats'):
            url_data = rts.url_stats.get(log_line.path)
            if url_data is None:
                url_data = IpData(
                    config,
                    log_line.path,
                    'path',
                    {
                        "raw_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
                        "log_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
                    }
                )
            url_data.raw_lines.append(log_line.req_ts, line)
            url_data.log_lines.append(log_line.req_ts, log_line)

        if config.config.getboolean('main', 'ua_stats'):
            ua_data = rts.ua_stats.get(log_line.ua)
            if ua_data is None:
                ua_data = IpData(
                    config,
                    log_line.ua,
                    'user_agent',
                    {
                        "raw_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
                        "log_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
                    }
                )
            ua_data.raw_lines.append(log_line.req_ts, line)
            ua_data.log_lines.append(log_line.req_ts, log_line)

        if KnownAttacks.is_known(config, log_line):
            IpTables.ban(log_line.ip, rts, config, ip_data.raw_lines)
            return Nginx.STATUS_BANNED
        Checks.log_probes(log_line, line, rts)

        rts.ip_stats.create(ts=log_line.req_ts, key=log_line.ip, value=ip_data)
        if config.config.getboolean('main', 'url_stats') and url_data is not None:
            rts.url_stats.create(ts=log_line.req_ts,
                                 key=log_line.path, value=url_data)
        if config.config.getboolean('main', 'ua_stats') and ua_data is not None:
            rts.ua_stats.create(ts=log_line.req_ts,
                                key=log_line.ua, value=ua_data)

        if Checks.bad_http_stats(config, log_line, ip_data):
            IpTables.ban(log_line.ip, rts, config, ip_data.raw_lines)
            return Nginx.STATUS_BANNED
        if Checks.bad_steal_ratio(config, ip_data):
            IpTables.ban(log_line.ip, rts, config, ip_data.raw_lines)
            return Nginx.STATUS_BANNED
        return Nginx.STATUS_OK
