import pytest
from classes.IpTables import IpTables
from classes.Nginx import Nginx
from classes.Bots import Bots
from classes.Checks import Checks

def test_parse_log_format():
    log_format = "$remote_addr $host $time_local $request $status $upstream_response_time $http_user_agent $http_referer"
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

def test_parse_log_line(monkeypatch):
    log_format = "$remote_addr $host $time_local $time_local $request $status $upstream_response_time $http_user_agent $http_referer"
    columns = Nginx.parse_log_format(log_format)
    # Compose a log line with all required fields
    line = (
        '1.2.3.4 localhost [18/Oct/2025:04:23:16 +0300] [18/Oct/2025:04:23:16 +0300] '
        '"GET /index.html?foo=bar HTTP/1.1" 404 0.123 "Mozilla/5.0" "http://example.com/page"'
    )
    # Patch datetime to avoid timezone issues
    log_line = Nginx.parse_log_line(line, columns)
    assert log_line is not None
    assert log_line.ip == "1.2.3.4"
    assert log_line.path == "/index.html"

def test_process_line(monkeypatch):
    # Dummy config and rts
    class DummyConfig:
        ignore_extensions = []
        url_stats = False
        ua_stats = False
        time_frame = 60
        ban_time = 10
    class DummyIpWhitelist:
        def is_whitelisted(self, host, ip): return False
        def is_trigger(self, host, ip, path, status): return False
    class DummyIpBlacklist:
        def is_ip_blacklisted(self, ip): return False
    class DummyRts:
        def __init__(self):
            self.lines_parsed = 0
            self.ip_whitelist = DummyIpWhitelist()
            self.ip_blacklist = DummyIpBlacklist()
            self.ip_stats = type("DummyStats", (), {"get": lambda self, k: None, "create": lambda self, ts, key, value: None})()
            self.url_stats = type("DummyStats", (), {"get": lambda self, k: None, "create": lambda self, ts, key, value: None})()
            self.ua_stats = type("DummyStats", (), {"get": lambda self, k: None, "create": lambda self, ts, key, value: None})()
    class DummyLogLine:
        def __init__(self):
            self.host = "localhost"
            self.ip = "1.2.3.4"
            self.path = "/index.html"
            self.http_status = 404
            self.req = "localhost/index.html"
            self.ua = "Mozilla/5.0"
            self.req_ts = 1234567890
    # Patch dependencies
    monkeypatch.setattr(Bots, "good_bot", lambda config, log_line: False)
    monkeypatch.setattr(Bots, "bad_bot", lambda config, log_line: None)
    monkeypatch.setattr(IpTables, "ban", lambda ip, rts, config, raw, reason="", log_info=True: None)
    monkeypatch.setattr(Checks, "bad_req", lambda config, log_line: None)
    monkeypatch.setattr(Checks, "bad_stats", lambda config, log_line, ip_data: None)
    monkeypatch.setattr(Checks, "log_probes", lambda log_line, line, rts: None)
    # Should return STATUS_OK
    config = DummyConfig()
    rts = DummyRts()
    log_line = DummyLogLine()
    result = Nginx.process_line(config, rts, log_line, "raw log line")
    assert result == Nginx.STATUS_OK