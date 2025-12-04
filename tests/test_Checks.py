import pytest
from classes.Checks import Checks
from classes.LogLine import LogLine
from classes.Config import Config
from classes.IpData import IpData
from classes.RunTimeStats import RunTimeStats

class DummyConfig(Config):
    def __init__(self):
        super().__init__()
        self.http_status_bad_threshold = 3
        self.steal_total = 10
        self.steal_over_time = 5
        self.known_attacks = ["/attack", "/.env"]

class DummyLogLine(LogLine):
    def __init__(self, path: str = "/attack", http_status: int = 404, ip: str = "1.2.3.4", host: str = "host"):
        super().__init__({path: path, "http_status": http_status, "ip": ip, "host": host})

class DummyIpData:
    def __init__(self, http_status_bad=0, request_count=10, steal_time=0, avail_time=0, total_time=0, steal_ratio=0):
        self.http_status_bad = http_status_bad
        self.request_count = request_count
        self.steal_time = steal_time
        self.avail_time = avail_time
        self.total_time = total_time
        self.steal_ratio = steal_ratio

class DummyInterDomain:
    def __init__(self):
        self.calls = []
    def add(self, path, host, http_status, raw_line):
        self.calls.append((path, host, http_status, raw_line))

class DummyRunTimeStats:
    def __init__(self):
        self.inter_domain = DummyInterDomain()


def test_bad_steal_ratio():
    config = DummyConfig()
    log_line = DummyLogLine()
    ip_data = DummyIpData(steal_time=-15, avail_time=10, total_time=30, steal_ratio=0.6)
    assert Checks.bad_steal_ratio(config, log_line, ip_data) is True

    ip_data = DummyIpData(steal_time=-5, avail_time=4)
    assert Checks.bad_steal_ratio(config, log_line, ip_data) is False

