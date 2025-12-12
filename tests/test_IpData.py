from typing import Any
from classes.IpData import IpData
from classes.ExpiringList import ExpiringList
from classes.Config import Config


class DummyLogLine:
    def __init__(self, path: str, http_status: int, req_ts: float, upstream_response_time: float):
        self.path = path
        self.http_status = http_status
        self.req_ts = req_ts
        self.upstream_response_time = upstream_response_time


def make_log_lines():
    return [
        DummyLogLine("/index.html", 200, 1.0, 0.5),
        DummyLogLine("/bad.php", 500, 2.0, 1.0),
        DummyLogLine("/static.js", 404, 3.0, 0.2),
        DummyLogLine("/dangerous.py", 403, 4.0, 2.0),
        DummyLogLine("/other", 206, 5.0, 0.1),
    ]


def test_ipdata_init_and_repr():
    data: dict[str, Any] = {
        "raw_lines": ExpiringList(60),
        "log_lines": ExpiringList(60)
    }
    ipd = IpData(Config("test.conf"), "1.2.3.4", "ip", data)
    assert "IpData" in repr(ipd)
    assert isinstance(ipd.raw_lines, ExpiringList)
    assert isinstance(ipd.log_lines, ExpiringList)


def test_min_max_ts():
    log_lines: ExpiringList[DummyLogLine] = ExpiringList(60)
    for ll in make_log_lines():
        log_lines.append(None, ll)
    ipd = IpData(Config("test.conf"), "1.2.3.4", "ip", {"log_lines": log_lines})
    assert ipd.min_ts == 1.0
    assert ipd.max_ts == 5.0


def test_avail_time_and_request_count():
    log_lines: ExpiringList[DummyLogLine] = ExpiringList(60)
    for ll in make_log_lines():
        log_lines.append(None, ll)
    ipd = IpData(Config("test.conf"), "1.2.3.4", "ip", {"log_lines": log_lines})
    assert ipd.avail_time == 4
    assert ipd.request_count == 5


def test_total_and_avg_time():
    log_lines: ExpiringList[DummyLogLine] = ExpiringList(60)
    for ll in make_log_lines():
        log_lines.append(None, ll)
    ipd = IpData(Config("test.conf"), "1.2.3.4", "ip", {"log_lines": log_lines})
    assert ipd.total_time == 3.8
    assert ipd.avg_time == 0.76


def test_http_status_bad_and_score():
    log_lines: ExpiringList[DummyLogLine] = ExpiringList(60)
    for ll in make_log_lines():
        log_lines.append(None, ll)
    ipd = IpData(Config("test.conf"), "1.2.3.4", "ip", {"log_lines": log_lines})
    # Should be 0 because count <= 10
    assert ipd.http_status_bad == 0
    # Should be 0 because request_count < 10
    assert ipd.score == 0


def test_steal_time_and_steal_ratio():
    log_lines: ExpiringList[DummyLogLine] = ExpiringList(60)
    for ll in make_log_lines():
        log_lines.append(None, ll)
    ipd = IpData(Config("test.conf"), "1.2.3.4", "ip", {"log_lines": log_lines})
    assert ipd.steal_time == 4 - 3.8
    assert ipd.steal_ratio == (3.8 / 4) * 100.0
