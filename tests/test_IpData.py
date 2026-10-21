import time
from typing import Any

import pytest

from classes.IpData import IpData
from classes.ExpiringList import ExpiringList
from classes.Config import Config
from classes.HttpHeaders import HttpHeaders


@pytest.fixture
def config(monkeypatch: pytest.MonkeyPatch) -> Config:
    monkeypatch.setattr("classes.Config.BotWhitelist.load", lambda *args: {})
    return Config("test.conf")


def make_ip_data(config: Config) -> IpData:
    base = time.time() - 10
    log_lines: ExpiringList[HttpHeaders] = ExpiringList(60)
    for path, http_status, offset, upstream_response_time in (
        ("/index.html", 200, 1.0, 0.5),
        ("/bad.php", 500, 2.0, 1.0),
        ("/static.js", 404, 3.0, 0.2),
        ("/dangerous.py", 403, 4.0, 2.0),
        ("/other", 206, 5.0, 0.1),
    ):
        line = HttpHeaders(
            path=path,
            http_status=http_status,
            ts=base + offset,
            upstream_response_time=upstream_response_time,
        )
        log_lines.append(line.ts, line)
    return IpData(config, "1.2.3.4", "ip", {"log_lines": log_lines})


def test_ipdata_init_and_repr(config: Config):
    data: dict[str, Any] = {
        "raw_lines": ExpiringList(60),
        "log_lines": ExpiringList(60)
    }
    ipd = IpData(config, "1.2.3.4", "ip", data)
    assert "IpData" in repr(ipd)
    assert isinstance(ipd.raw_lines, ExpiringList)
    assert isinstance(ipd.log_lines, ExpiringList)


def test_min_max_ts(config: Config):
    ipd = make_ip_data(config)
    assert ipd.max_ts - ipd.min_ts == pytest.approx(4.0)


def test_avail_time_and_request_count(config: Config):
    ipd = make_ip_data(config)
    assert ipd.avail_time == 4
    assert ipd.request_count == 5


def test_total_and_avg_time(config: Config):
    ipd = make_ip_data(config)
    assert ipd.total_time == pytest.approx(3.8)
    assert ipd.avg_time == pytest.approx(0.76)
    # the slowest 10% of requests are left out
    assert ipd.used_time90 == pytest.approx(1.8)


def test_http_status_bad_and_score(config: Config):
    ipd = make_ip_data(config)
    # Should be 0 because count <= http_status_min_count
    assert ipd.http_status_bad == 0
    # Should be 0 because request_count < 10
    assert ipd.score == 0


def test_steal_time_and_steal_ratio(config: Config):
    ipd = make_ip_data(config)
    assert ipd.steal_time == pytest.approx(4 - 1.8)
    assert ipd.steal_ratio == pytest.approx((1.8 / 4) * 100.0)


def test_empty_ip_data(config: Config):
    ipd = IpData(config, "1.2.3.4", "ip", {})
    assert ipd.request_count == 0
    assert ipd.avail_time == 1
    assert ipd.used_time90 == 0.0
    assert ipd.avg_time == 0.0
