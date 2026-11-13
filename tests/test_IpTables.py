import pytest
import threading
import time
from classes.Config import Config
from classes.IpTables import IpTables


class DummyRunTimeStats:
    def __init__(self):
        self.banned_ips: dict[str, float] = {}
        self._banned_ips_lock = threading.Lock()


def test_clear_and_init(monkeypatch: pytest.MonkeyPatch):
    calls = []
    monkeypatch.setattr("subprocess.run", lambda args, **kwargs: calls.append(args))
    config = Config("test.conf")
    IpTables.clear(config)
    assert any("iptables" in c[0] or "ip6tables" in c[0] for c in calls)
    calls.clear()
    IpTables.init(config)
    assert any("iptables" in c[0] or "ip6tables" in c[0] for c in calls)


def test_ban(monkeypatch: pytest.MonkeyPatch):
    calls = []
    monkeypatch.setattr("subprocess.run", lambda args, **kwargs: calls.append(args))
    config = Config("test.conf")
    rts = DummyRunTimeStats()
    assert IpTables.ban("1.2.3.4", rts, config)
    assert "1.2.3.4" in rts.banned_ips
    assert any("iptables" in c[0] for c in calls)
    calls.clear()
    # already banned: the ban time is refreshed without a new rule
    assert not IpTables.ban("1.2.3.4", rts, config)
    assert calls == []


def test_unban_expired(monkeypatch: pytest.MonkeyPatch):
    calls = []
    monkeypatch.setattr("subprocess.run", lambda args, **kwargs: calls.append(args))
    config = Config("test.conf")
    rts = DummyRunTimeStats()
    rts.banned_ips["1.2.3.4"] = time.time() - 3600  # expired
    IpTables.unban_expired(config, rts)
    assert "1.2.3.4" not in rts.banned_ips
    assert any("iptables" in c[0] for c in calls)