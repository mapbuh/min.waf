import pytest
import time
from classes.Config import Config
from classes.IpTables import IpTables


class DummyConfig:
    iptables_chain = "MINWAF"
    ban_time = 10


class DummyRunTimeStats:
    def __init__(self):
        self.banned_ips: dict[str, float] = {}
        self.bans = 0


def test_clear_and_init(monkeypatch: pytest.MonkeyPatch):
    calls = []
    monkeypatch.setattr("subprocess.run", lambda args, **kwargs: calls.append(args))
    config = Config("test.conf")
    IpTables.clear(config)
    assert any("iptables" in c[0] or "ip6tables" in c[0] for c in calls)
    calls.clear()
    IpTables.init(config)
    assert any("iptables" in c[0] or "ip6tables" in c[0] for c in calls)


def test_slow_ipv4(monkeypatch: pytest.MonkeyPatch):
    calls = []
    monkeypatch.setattr("subprocess.run", lambda args, **kwargs: calls.append(args))
    config = Config("test.conf")
    rts = DummyRunTimeStats()
    IpTables.slow("1.2.3.4", config, rts)
    assert "1.2.3.4" in rts.banned_ips
    assert any("iptables" in c[0] for c in calls)


def test_slow_ipv6(monkeypatch: pytest.MonkeyPatch):
    calls = []
    monkeypatch.setattr("subprocess.run", lambda args, **kwargs: calls.append(args))
    config = Config("test.conf")
    rts = DummyRunTimeStats()
    IpTables.slow("abcd::1234", config, rts)
    assert "abcd::1234" in rts.banned_ips
    assert any("ip6tables" in c[0] for c in calls)


def test_ban(monkeypatch: pytest.MonkeyPatch):
    calls = []
    monkeypatch.setattr("subprocess.run", lambda args, **kwargs: calls.append(args))
    config = Config("test.conf")
    rts = DummyRunTimeStats()
    IpTables.ban("1.2.3.4", rts, config)
    assert "1.2.3.4" in rts.banned_ips
    assert rts.bans == 1
    assert any("iptables" in c[0] for c in calls)


def test_unban_expired(monkeypatch: pytest.MonkeyPatch):
    calls = []
    monkeypatch.setattr("subprocess.run", lambda args, **kwargs: calls.append(args))
    config = Config("test.conf")
    rts = DummyRunTimeStats()
    rts.banned_ips["1.2.3.4"] = time.time() - 3600  # expired
    IpTables.unban_expired(config, rts)
    assert "1.2.3.4" not in rts.banned_ips
    assert any("iptables" in c[0] for c in calls)