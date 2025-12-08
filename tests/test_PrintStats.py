import logging
import sys
import io
from classes.PrintStats import PrintStats


def test_log_stats(monkeypatch):
    class DummyWhitelist:
        whitelist = {"host": type("DummyList", (), {"values": lambda self: ["1.2.3.4"]})()}
    class DummyInterDomain:
        path = {}
    class DummyRts:
        start_time = 0
        bans = 1
        ip_whitelist = DummyWhitelist()
        inter_domain = DummyInterDomain()
    logs = []
    logger = logging.getLogger("min.waf")
    monkeypatch.setattr(logger, "info", lambda msg: logs.append(msg))
    PrintStats.log_stats(DummyRts())
    assert any("Total bans: 1" in log for log in logs)
