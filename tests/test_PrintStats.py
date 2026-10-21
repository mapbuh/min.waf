import logging
from classes.PrintStats import PrintStats
from classes.RunTimeStats import IDS


def test_log_stats(monkeypatch):
    class DummyWhitelist:
        whitelist = {"host": type("DummyList", (), {"values": lambda self: ["1.2.3.4"]})()}

    class DummyRts:
        start_time = 0
        all = 10
        bans = 1
        ip_whitelist = DummyWhitelist()
        inter_domain = IDS()
    rts = DummyRts()
    for host in ("a.com", "b.com", "c.com"):
        rts.inter_domain.add("/.env", host, 404, "5.6.7.8")
    rts.inter_domain.add("/", "a.com", 404, "5.6.7.8")
    logs = []
    logger = logging.getLogger("min.waf")
    monkeypatch.setattr(logger, "info", lambda msg: logs.append(msg))
    PrintStats.log_stats(rts)
    assert "Total requests: 10" in logs[0]
    assert "Total bans: 1" in logs[0]
    assert "host/1.2.3.4" in logs[0]
    assert logs[1:] == ["Path: /.env, Total Probes: 3"]
