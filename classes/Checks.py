import logging
import re
import urllib.parse

from classes.Bots import Bots
from classes.Config import Config
from classes.ExpiringList import ExpiringList
from classes.HttpHeaders import HttpHeaders
from classes.IpData import IpData
from classes.KnownAttacks import KnownAttacks
from classes.MultipartCounter import MultipartCounter
from classes.RunTimeStats import RunTimeStats
from classes.UrlencodedCounter import UrlencodedCounter


class Checks:
    _set_cookie = re.compile(rb'^set-cookie[ \t]*:[ \t]*([^=;\r\n]*)=([^;\r\n]*)', re.IGNORECASE | re.MULTILINE)
    _session_id = re.compile(rb'[A-Za-z0-9,-]*')

    @staticmethod
    def headers(httpHeaders: HttpHeaders, config: Config, rts: RunTimeStats) -> bool:
        logger = logging.getLogger("min.waf")
        with rts._banned_ips_lock:
            is_banned = httpHeaders.ip in rts.banned_ips
        if is_banned:
            httpHeaders.ban_reason = "already banned"
            if config.config.getboolean('log', 'bans'):
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
            httpHeaders.ban_reason = "found in blacklist"
            httpHeaders.status = HttpHeaders.STATUS_BAD
            return False
        if Bots.bad_bot(config, httpHeaders.ua):
            httpHeaders.ban_reason = f"Bad bot detected: {httpHeaders.ua}"
            httpHeaders.status = HttpHeaders.STATUS_BAD
            return False
        # static files only stay out of the ban statistics: their content is
        # still inspected, and the query string must not make a path static
        if httpHeaders.path.split('?', 1)[0].endswith(tuple(config.getlist('main', 'static_files'))):
            httpHeaders.skip_stats = True
        if config.config.getboolean("main", "inspect_packets"):
            path_lower = urllib.parse.unquote(httpHeaders.path).lower()
            for signature in config.harmful_patterns():
                if signature.lower() in path_lower:
                    httpHeaders.ban_reason = f"Harmful signature detected in URL: {signature}"
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
        if httpHeaders.skip_stats:
            return True
        if not Checks.process_http_request(config, rts, httpHeaders):
            httpHeaders.status = HttpHeaders.STATUS_BAD
            return False
        return True

    @staticmethod
    def content(
        config: Config,
        httpHeaders: HttpHeaders,
        buffer: bytes,
        clean_upto: int,
        urlencoded: bool = False,
    ) -> tuple[bool, int]:
        """Checks the content against the harmful signatures.

        A form-urlencoded body is checked decoded too ('+' and %XX), the way
        the application sees it, as the URL path is.
        """
        if httpHeaders.status == HttpHeaders.STATUS_GOOD:
            return True, len(buffer)
        if httpHeaders.status == HttpHeaders.STATUS_BAD:
            return False, clean_upto
        if not config.config.getboolean('main', 'inspect_packets'):
            return True, clean_upto
        if clean_upto >= config.config.getint("main", "max_inspect_size"):
            return True, clean_upto
        # Inspect only the new data since last clean point
        # an encoded signature is up to 3 times longer (%XX per byte)
        overlap = config.longest_harmful_pattern() * (3 if urlencoded else 1)
        dirty_data_from: int = clean_upto - overlap + 1
        if dirty_data_from < 0:
            dirty_data_from = 0
        dirty_data = buffer[dirty_data_from:].lower()
        decoded = urllib.parse.unquote_to_bytes(dirty_data.replace(b'+', b' ')).lower() if urlencoded else b''
        for signature, encoded in zip(config.harmful_patterns(), config.harmful_patterns_encoded()):
            if encoded in dirty_data or encoded in decoded:
                httpHeaders.ban_reason = f"Harmful signature detected in content: {signature}"
                httpHeaders.status = HttpHeaders.STATUS_BAD
                return False, clean_upto
        clean_upto = len(buffer)
        return True, clean_upto

    @staticmethod
    def multipart_headers(config: Config, httpHeaders: HttpHeaders, part_headers: list[bytes]) -> bool:
        if httpHeaders.status == HttpHeaders.STATUS_GOOD:
            return True
        if httpHeaders.status == HttpHeaders.STATUS_BAD:
            return False
        if not config.config.getboolean('main', 'inspect_packets'):
            return True
        patterns = list(zip(config.harmful_patterns(), config.harmful_patterns_encoded()))
        upload_filenames = [
            (name, name.encode().lower())
            for name in config.getlist('signatures', 'upload_filenames')
        ]
        for part_header in part_headers:
            part_header = part_header.lower()
            for signature, encoded in patterns:
                if encoded in part_header:
                    httpHeaders.ban_reason = f"Harmful signature detected in multipart header: {signature}"
                    httpHeaders.status = HttpHeaders.STATUS_BAD
                    return False
            for filename in MultipartCounter.filenames(part_header):
                for signature, encoded in upload_filenames:
                    if encoded in filename:
                        httpHeaders.ban_reason = f"Harmful signature detected in upload filename: {signature}"
                        httpHeaders.status = HttpHeaders.STATUS_BAD
                        return False
        return True

    @staticmethod
    def multipart_limits(
        config: Config,
        httpHeaders: HttpHeaders,
        counter: MultipartCounter | None,
        chunked: bool,
    ) -> bool:
        if httpHeaders.status == HttpHeaders.STATUS_GOOD:
            return True
        if httpHeaders.status == HttpHeaders.STATUS_BAD:
            return False
        if not config.config.getboolean('main', 'inspect_packets'):
            return True
        reason = ""
        if chunked and config.config.getboolean('main', 'multipart_block_chunked'):
            reason = "Chunked multipart request"
        elif counter and counter.long_header:
            reason = f"Multipart header longer than {MultipartCounter.max_line} bytes"
        elif counter:
            for value, option, label in (
                (counter.parts, 'multipart_max_parts', "parts"),
                (counter.part_headers, 'multipart_max_part_headers', "headers in a part"),
                (counter.nesting, 'multipart_max_nesting', "nesting in a part header"),
                (counter.empty_files, 'multipart_max_empty_files', "empty file parts"),
            ):
                limit = config.config.getint('main', option)
                if limit and value > limit:
                    reason = f"Too many multipart {label}: {value} > {limit}"
                    break
        if not reason:
            return True
        httpHeaders.ban_reason = reason
        httpHeaders.status = HttpHeaders.STATUS_BAD
        return False

    @staticmethod
    def urlencoded_limits(config: Config, httpHeaders: HttpHeaders, counter: UrlencodedCounter) -> bool:
        if httpHeaders.status == HttpHeaders.STATUS_GOOD:
            return True
        if httpHeaders.status == HttpHeaders.STATUS_BAD:
            return False
        if not config.config.getboolean('main', 'inspect_packets'):
            return True
        limit = config.config.getint('main', 'urlencoded_max_name_length')
        if not limit or counter.max_array_name <= limit:
            return True
        httpHeaders.ban_reason = f"Urlencoded array field name too long: {counter.max_array_name} > {limit}"
        httpHeaders.status = HttpHeaders.STATUS_BAD
        return False

    @staticmethod
    def response_headers(config: Config, httpHeaders: HttpHeaders, head: bytes) -> bool:
        if httpHeaders.status == HttpHeaders.STATUS_GOOD:
            return True
        if httpHeaders.status == HttpHeaders.STATUS_BAD:
            return False
        if not config.config.getboolean('main', 'inspect_packets'):
            return True
        names = [name.encode().lower() for name in config.getlist('main', 'session_cookies')]
        limit = config.config.getint('main', 'session_cookie_max_length')
        for match in Checks._set_cookie.finditer(head):
            name, value = match.group(1).strip().lower(), match.group(2).strip()
            if name not in names:
                continue
            if limit and len(value) > limit:
                reason = f"Session cookie {name.decode(errors='replace')} too long: {len(value)} > {limit}"
            elif not Checks._session_id.fullmatch(value):
                reason = f"Session cookie {name.decode(errors='replace')} with invalid characters"
            else:
                continue
            httpHeaders.ban_reason = reason
            httpHeaders.status = HttpHeaders.STATUS_BAD
            return False
        return True

    @staticmethod
    def bad_http_stats(config: Config, httpHeaders: HttpHeaders, ip_data: IpData) -> bool:
        return ip_data.http_status_bad >= float(config.config.get('main', 'http_status_bad_threshold'))

    @staticmethod
    def bad_steal_ratio(config: Config, ip_data: IpData) -> bool:
        steal_total = config.config.getint('main', 'steal_total')
        # stealing needs used_time90 > avail_time + steal_total, and used_time90
        # never exceeds total_time: this skips the 90th percentile sort for
        # almost every request
        if ip_data.total_time <= ip_data.avail_time + steal_total:
            return False
        return (
            ip_data.steal_time < -steal_total
            and ip_data.avail_time > config.config.getint('main', 'steal_over_time')
            and ip_data.steal_ratio > config.config.getfloat('main', 'steal_ratio')
        )

    @staticmethod
    def log_probes(httpHeaders: HttpHeaders, rts: RunTimeStats) -> None:
        # TODO - make it LRU cache
        if httpHeaders.http_status != 200:
            rts.inter_domain.add(httpHeaders.path, httpHeaders.host, httpHeaders.http_status or 0, httpHeaders.ip)

    @staticmethod
    def process_http_request(
        config: Config,
        rts: RunTimeStats,
        httpHeaders: HttpHeaders,
    ) -> bool:
        # requests without a client IP would all share one stats entry
        if not httpHeaders.ip.strip():
            return True

        time_frame = config.config.getint('main', 'time_frame')
        ip_data = rts.ip_stats.get_or_create(
            httpHeaders.ip,
            lambda: IpData(config, httpHeaders.ip, 'ip', {
                "log_lines": ExpiringList(expiration_time=time_frame),
            }),
            ts=httpHeaders.ts,
        )
        ip_data.log_lines.append(httpHeaders.ts, httpHeaders)

        if Checks.bad_http_stats(config, httpHeaders, ip_data):
            httpHeaders.ban_reason = (
                f"Bad http_status ratio: {ip_data.http_status_bad:.2f} from {ip_data.request_count} reqs"
            )
            return False
        if Checks.bad_steal_ratio(config, ip_data):
            httpHeaders.ban_reason = (
                f"Stealing time: {ip_data.steal_time:.2f}s "
                f"t/a: {ip_data.total_time:.2f}/{ip_data.avail_time:.2f} "
                f"req: {ip_data.request_count} ratio: {ip_data.steal_ratio:.2f}"
            )
            return False
        if KnownAttacks.is_known(config, httpHeaders):
            return False
        Checks.log_probes(httpHeaders, rts)

        return True
