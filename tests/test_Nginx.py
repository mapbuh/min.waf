import time
import pytest
from classes.Checks import Checks
from classes.IpTables import IpTables
from classes.LogLine import LogLine
from classes.Nginx import Nginx
from classes.Config import Config
from classes.RunTimeStats import RunTimeStats
from classes.IpBlacklist import IpBlacklist


def test_parse_log_format():
    log_format = (
        "$remote_addr $host $time_local $request $status "
        "$upstream_response_time $http_user_agent $http_referer"
    )
    columns = Nginx.parse_log_format(log_format)
    assert columns["remote_addr"] == 0
    assert columns["host"] == 1
    assert columns["time_local"] == 2
    assert columns["request"] == 4
    assert columns["status"] == 5
    assert columns["upstream_response_time"] == 6
    assert columns["http_user_agent"] == 7
    assert columns["http_referer"] == 8


def test_parse_path():
    assert Nginx.parse_path("GET /foo/bar?baz=1 HTTP/1.1") == "/foo/bar"
    assert Nginx.parse_path("GET /onlypath HTTP/1.1") == "/onlypath"
    assert Nginx.parse_path("/no_method?x=1") == "/no_method"


def test_parse_log_line(monkeypatch: pytest.MonkeyPatch):
    log_format = (
        '"$remote_addr" $host [$time_local] "$request" $status $body_bytes_sent $request_length $bytes_sent '
        '"$http_referer" "$http_user_agent" $request_time "$gzip_ratio" "$geoip2_data_country_iso_code" '
        '"$upstream_response_time"'
    )
    columns = Nginx.parse_log_format(log_format)
    # Compose a log line with all required fields
    line = (
        '"1.2.3.4" www.example.com [01/Dec/2025:00:05:25 +0200] '
        '"GET /media/products/images/4311/upr6NnW1Z1kx72U8AxuHaRAkeaTEREAdSmv5Yary_thumb.png/'
        'polet-s-balon-nad-belogradchishkite-skali-snimka_16696_thumb.png HTTP/2.0" 200 6550 124 6821 '
        '"https://www.example.com/vaucheri-za-prezhivyavane/adrenalin/vav-vazduha?utm_source=googleads'
        '&utm_medium=cpc&utm_campaign=GE+-+Performance+Search+for+Bestseller+&utm_term=Vuzduh'
        '&utm_source=google&utm_medium=cpc&utm_campaign=20801060342&utm_content=&utm_term='
        '&tw_source=google&tw_adid=&tw_campaign=20801060342&tw_kwdid=&gad_source=1'
        '&gad_campaignid=20804954761&gbraid=0AAAAADFa9oZZT8kxpKoGlAzg_c7xJvWbR'
        '&gclid=CjwKCAiA86_JBhAIEiwA4i9Ju3LVr9LtLpJblVYHhU6kUT1JD2zUO5YMtR4VUe8sQOKlBlmKhei-XxoCUwQQAvD_BwE" '
        '"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/142.0.0.0 Mobile Safari/537.36" 0.468 "-" "BG" "0.047"'
    )
    # Patch datetime to avoid timezone issues
    log_line = Nginx.parse_log_line(line, columns)
    assert log_line is not None
    assert log_line.host == "www.example.com"
    assert log_line.ip == "1.2.3.4"
    assert log_line.path == (
        "/media/products/images/4311/upr6NnW1Z1kx72U8AxuHaRAkeaTEREAdSmv5Yary_thumb.png/"
        "polet-s-balon-nad-belogradchishkite-skali-snimka_16696_thumb.png"
    )
    assert log_line.http_status == 200
    assert log_line.req == (
        "www.example.com/media/products/images/4311/upr6NnW1Z1kx72U8AxuHaRAkeaTEREAdSmv5Yary_thumb.png/"
        "polet-s-balon-nad-belogradchishkite-skali-snimka_16696_thumb.png"
    )
    assert log_line.ua == (
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/142.0.0.0 Mobile Safari/537.36"
    )
    assert log_line.referer == "www.example.com/vaucheri-za-prezhivyavane/adrenalin/vav-vazduha"
    log_line = Nginx.parse_log_line("dsalkdajs lajdsladkjsa ldasjdl sakdj", columns)
    assert log_line is None



def test_process_line(monkeypatch: pytest.MonkeyPatch):
    # Dummy config and rts
    class DummyConfig(Config):
        def __init__(self):
            super().__init__()
            self.ignore_extensions = []
            self.url_stats = False
            self.ua_stats = False
            self.time_frame = 60
            self.ban_time = 10
            self.known_attacks = ["/.env", "/xmlrpc.php"]
            self.whitelist_triggers = {
                "example.com": [{"path": "/admin-dashboard", "http_status": "200"}]
            }
            self.good_bots = {"Google": ["Googlebot"]}
            self.bad_bots = {"EvilBot": ["EvilBot"]}
            self.ignore_extensions = [".ignored"]
            self.url_stats = True
            self.ua_stats = True

    class DummyLogLine(LogLine):
        def __init__(self, data: dict[str, str | float | int] = {
                "host": "localhost",
                "ip": "1.2.3.4",
                "path": "/index.html",
                "http_status": 404,
                "req": "example.com/index.html",
                "ua": "Mozilla/5.0",
                "req_ts": 1234567890
        }):
            super().__init__(data)
    # Patch dependencies
    # monkeypatch.setattr(Bots, "good_bot", lambda config, log_line: False)
    # monkeypatch.setattr(Bots, "bad_bot", lambda config, log_line: None)
    monkeypatch.setattr(IpTables, "ban", lambda ip, rts, config, raw_lines=None: None)
    # monkeypatch.setattr(Checks, "bad_http_stats", lambda config, log_line, ip_data: None)
    # monkeypatch.setattr(Checks, "bad_steal_ratio", lambda config, log_line, ip_data: None)
    # monkeypatch.setattr(Checks, "log_probes", lambda log_line, line, rts: None)
    # Should return STATUS_OK
    config = DummyConfig()
    rts = RunTimeStats(config)
    rts.banned_ips = {
        "1.2.3.7": time.time() + 10,
    }
    rts.ip_blacklist = IpBlacklist(config)
    rts.ip_blacklist.list = [
        "1.2.3.6",
    ]
    log_line = DummyLogLine()
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.5",  # step on trigger, become whitelisted
        "host": "example.com",
        "req": "example.com/admin-dashboard",
        "http_status": 200
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.5",  # whitelisted now
        "host": "example.com",
        "req": "example.com/.env",
        "http_status": 404
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.4",
        "host": "example.com",
        "req": "example.com/.env",
        "http_status": 404,
        "ua": "Googlebot"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.4",
        "host": "example.com",
        "req": "example.com/.env",
        "http_status": 404,
        "ua": "EvilBot"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_BANNED
    log_line = DummyLogLine({
        "ip": "1.2.3.6",  # banned IP
        "host": "example.com",
        "req": "example.com/index.html",
        "http_status": 200,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_BANNED
    log_line = DummyLogLine({
        "ip": "1.2.3.4",
        "host": "example.com",
        "req": "example.com/file.ignored",
        "http_status": 200,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.4",
        "host": "example.com",
        "req": "example.com/.env",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_BANNED
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-1",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-2",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-3",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-4",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-5",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-6",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-7",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-8",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-9",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-10",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-11",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_BANNED
    log_line = DummyLogLine({
        "ip": "1.2.3.9",
        "host": "example.com",
        "req": "example.com/index.html",
        "http_status": 200,
        "ua": "Mozilla/5.0"
    })
    monkeypatch.setattr(Checks, "bad_steal_ratio", lambda config, log_line, ip_data: True)
    assert Nginx.process_line(config, rts, log_line, "raw log line") == Nginx.STATUS_BANNED
