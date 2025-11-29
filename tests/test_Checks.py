import pytest
from classes.Checks import Checks

class DummyConfig:
    http_status_bad_threshold = 3
    steal_total = 10
    steal_over_time = 5
    known_attacks = ["/attack", "/.env"]

class DummyLogLine:
    def __init__(self, path="/attack", http_status=404, ip="1.2.3.4", host="host"):
        self.path = path
        self.http_status = http_status
        self.ip = ip
        self.host = host

class DummyIpData:
    def __init__(self, http_status_bad=0, request_count=10, steal_time=0, avail_time=0, total_time=0, steal_ratio=0):
        self.http_status_bad = http_status_bad
        self.request_count = request_count
        self.steal_time = steal_time
        self.avail_time = avail_time
        self.total_time = total_time
        self.steal_ratio = steal_ratio

class DummyKnownAttacks:
    @staticmethod
    def is_known(config, path):
        return path == "/attack"

class DummyInterDomain:
    def __init__(self):
        self.calls = []
    def add(self, path, host, http_status, raw_line):
        self.calls.append((path, host, http_status, raw_line))

class DummyRunTimeStats:
    def __init__(self):
        self.inter_domain = DummyInterDomain()

def test_bad_req(monkeypatch):
    config = DummyConfig()
    log_line = DummyLogLine(path="/attack", http_status=404)
    result = Checks.bad_req(config, log_line)
    assert result is not None
    assert "Known attack detected" in result

    log_line = DummyLogLine(path="/notattack", http_status=404)
    result = Checks.bad_req(config, log_line)
    assert result is None

def test_bad_stats():
    config = DummyConfig()
    log_line = DummyLogLine()
    ip_data = DummyIpData(http_status_bad=4)
    result = Checks.bad_stats(config, log_line, ip_data)
    assert result is not None
    assert "Bad http_status ratio" in result

    ip_data = DummyIpData(http_status_bad=2, steal_time=-11, avail_time=6, total_time=20, steal_ratio=0.5)
    result = Checks.bad_stats(config, log_line, ip_data)
    assert result is None

def test_log_probes():
    log_line = DummyLogLine(http_status=404, path="/probe", host="host")
    raw_line = "raw"
    rts = DummyRunTimeStats()
    Checks.log_probes(log_line, raw_line, rts)
    assert rts.inter_domain.calls == [("/probe", "host", 404, "raw")]

    log_line = DummyLogLine(http_status=200, path="/probe", host="host")
    rts = DummyRunTimeStats()
    Checks.log_probes(log_line, raw_line, rts)
    assert rts.inter_domain.calls == []