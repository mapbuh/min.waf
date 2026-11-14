import threading
import time
from types import SimpleNamespace

import pytest

from classes.Config import Config
from classes.IpSet import IpSet
from classes.MinWaf import MinWaf


class DummyRunTimeStats:
    def __init__(self):
        self.banned_ips: dict[str, float] = {}
        self._banned_ips_lock = threading.Lock()


@pytest.fixture
def config(tmp_path):
    config = Config("test.conf")
    config.config.set('main', 'lockfile', str(tmp_path / "min.waf.pid"))
    return config


def test_init_creates_sets_and_rules_once(monkeypatch: pytest.MonkeyPatch, config):
    calls = []
    existing_rules = set()

    def run(args, **kwargs):
        calls.append(args)
        if args[1] == "-C":
            return SimpleNamespace(returncode=0 if (args[0], tuple(args[2:])) in existing_rules else 1)
        if args[1] == "-I":
            existing_rules.add((args[0], tuple(args[2:])))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("subprocess.run", run)
    IpSet.init(config)
    creates = [c for c in calls if c[:2] == ["ipset", "create"]]
    assert [(c[2], c[5]) for c in creates] == [("minwaf", "inet"), ("minwaf6", "inet6")]
    assert all("-exist" in c for c in creates)
    inserts = [c for c in calls if c[1] == "-I"]
    assert sorted((c[0], c[c.index("--match-set") + 1]) for c in inserts) == [
        ("ip6tables", "minwaf6"), ("iptables", "minwaf"),
    ]
    # a second instance finds the rules and does not add them again
    calls.clear()
    IpSet.init(config)
    assert not any(c[1] == "-I" for c in calls)


def test_ban_always_refreshes_timeout(monkeypatch: pytest.MonkeyPatch, config):
    calls = []
    monkeypatch.setattr("subprocess.run", lambda args, **kwargs: calls.append(args))
    rts = DummyRunTimeStats()
    assert IpSet.ban("1.2.3.4", rts, config)
    assert not IpSet.ban("1.2.3.4", rts, config)
    assert IpSet.ban("2001:db8::1", rts, config)
    assert set(rts.banned_ips) == {"1.2.3.4", "2001:db8::1"}
    ban_time = config.config.get('main', 'ban_time')
    assert calls == [
        ["ipset", "add", "minwaf", "1.2.3.4", "timeout", ban_time, "-exist"],
        ["ipset", "add", "minwaf", "1.2.3.4", "timeout", ban_time, "-exist"],
        ["ipset", "add", "minwaf6", "2001:db8::1", "timeout", ban_time, "-exist"],
    ]


def test_unban_expired_leaves_the_set_to_the_kernel(monkeypatch: pytest.MonkeyPatch, config):
    calls = []
    monkeypatch.setattr("subprocess.run", lambda args, **kwargs: calls.append(args))
    rts = DummyRunTimeStats()
    rts.banned_ips["1.2.3.4"] = time.time() - 3600
    rts.banned_ips["5.6.7.8"] = time.time()
    MinWaf.unban_expired(config, rts)
    assert list(rts.banned_ips) == ["5.6.7.8"]
    assert calls == []


def test_ipset_name_is_shared_between_ports():
    assert Config("test.conf", port=9010).config.get('main', 'ipset_name') == "minwaf"
