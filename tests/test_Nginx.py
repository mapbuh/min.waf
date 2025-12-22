import time
import pytest

from classes.Checks import Checks
from classes.Config import Config
from classes.IpBlacklist import IpBlacklist
from classes.IpTables import IpTables
from classes.LogLine import LogLine
from classes.Nginx import Nginx
from classes.RunTimeStats import RunTimeStats


def test_parse_path():
    assert Nginx.parse_path("GET /foo/bar?baz=1 HTTP/1.1") == "/foo/bar"
    assert Nginx.parse_path("GET /onlypath HTTP/1.1") == "/onlypath"
    assert Nginx.parse_path("/no_method?x=1") == "/no_method"


def test_process_line(monkeypatch: pytest.MonkeyPatch):
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
    # monkeypatch.setattr(Bots, "bad_bot", lambda config, log_line: None)
    monkeypatch.setattr(IpTables, "ban", lambda ip, rts, config, raw_lines=None: None)
    # monkeypatch.setattr(Checks, "bad_http_stats", lambda config, log_line, ip_data: None)
    # monkeypatch.setattr(Checks, "bad_steal_ratio", lambda config, log_line, ip_data: None)
    # monkeypatch.setattr(Checks, "log_probes", lambda log_line, line, rts: None)
    # Should return STATUS_OK
    config = Config("test.conf")
    rts = RunTimeStats(config)
    rts.banned_ips = {
        "1.2.3.7": time.time() + 10,
    }
    rts.ip_blacklist = IpBlacklist(config)
    rts.ip_blacklist.list = [
        "1.2.3.6",
    ]
    log_line = DummyLogLine()
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.5",  # step on trigger, become whitelisted
        "host": "example.com",
        "req": "example.com/admin-dashboard",
        "http_status": 200
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK

    log_line = DummyLogLine({
        "ip": "1.2.3.5",  # whitelisted now
        "host": "example.com",
        "req": "example.com/.env",
        "http_status": 404
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK

    log_line = DummyLogLine({
        "ip": "66.249.68.1",  # real google ip
        "host": "example.com",
        "req": "example.com/.env",
        "http_status": 404,
        "ua": "Google"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK

    log_line = DummyLogLine({
        "ip": "1.2.3.4",
        "host": "example.com",
        "req": "example.com/.env",
        "http_status": 404,
        "ua": "EvilBot"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_BANNED
    log_line = DummyLogLine({
        "ip": "1.2.3.6",  # banned IP
        "host": "example.com",
        "req": "example.com/index.html",
        "http_status": 200,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_BANNED
    log_line = DummyLogLine({
        "ip": "1.2.3.4",
        "host": "example.com",
        "req": "example.com/file.ignored",
        "http_status": 200,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.4",
        "host": "example.com",
        "req": "example.com/.env",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_BANNED
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-1",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-2",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-3",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-4",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-5",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-6",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-7",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-8",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-9",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-10",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
    log_line = DummyLogLine({
        "ip": "1.2.3.8",
        "host": "example.com",
        "req": "example.com/non-existent-11",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_BANNED
    log_line = DummyLogLine({
        "ip": "1.2.3.9",
        "host": "example.com",
        "req": "example.com/index.html",
        "http_status": 200,
        "ua": "Mozilla/5.0"
    })
    monkeypatch.setattr(Checks, "bad_steal_ratio", lambda config, ip_data: True)
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_BANNED

    # good bot
    log_line = DummyLogLine({
        "ip": "1.2.3.4",
        "host": "example.com",
        "req": "example.com/non-existent-11",
        "http_status": 404,
        "ua": "https://ad.min.solutions"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK

    # bad bot
    log_line = DummyLogLine({
        "ip": "1.2.3.4",
        "host": "example.com",
        "req": "example.com/non-existent-11",
        "http_status": 404,
        "ua": "python-urllib"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_BANNED

    # static file
    log_line = DummyLogLine({
        "ip": "1.2.3.4",
        "host": "example.com",
        "req": "example.com/dummy.jpeg",
        "http_status": 404,
        "ua": "Mozilla/5.0"
    })
    assert Nginx.process_http_request(config, rts, log_line, "raw log line") == Nginx.STATUS_OK
