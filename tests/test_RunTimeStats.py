import pytest
from classes.RunTimeStats import RunTimeStats, IDS, IDSPath, IDSHost

class DummyConfig:
    time_frame = 60
    ip_blacklist = ""
    whitelist_permanent = None
    ip_blacklist_refresh_time = 10

def test_idshost_init():
    host = IDSHost()
    assert isinstance(host.http_statuses, dict)
    assert host.http_statuses == {}

def test_idspath_methods():
    path = IDSPath()
    # Add hosts and statuses
    path.hosts["host1"] = IDSHost()
    path.hosts["host2"] = IDSHost()
    path.hosts["host3"] = IDSHost()
    for i, host in enumerate(path.hosts.values()):
        host.http_statuses[200 + i] = [f"line{i}"]
    assert path.total_count() == 3
    statuses = path.statuses()
    assert set(statuses) == {200, 201, 202}
    lines = path.lines()
    assert all(f"line{i}" in lines for i in range(3))

def test_ids_add_and_repr():
    ids = IDS()
    ids.add("/path", "host", 404, "raw line")
    assert "/path" in ids.path
    assert "host" in ids.path["/path"].hosts
    assert 404 in ids.path["/path"].hosts["host"].http_statuses
    assert "raw line" in ids.path["/path"].hosts["host"].http_statuses[404]
    rep = repr(ids)
    assert "path: /path host: host status: 404" in rep

def test_runtimestats_init_and_blacklist(monkeypatch):
    config = DummyConfig()
    rts = RunTimeStats(config)
    assert rts.start_time == 0
    assert rts.lines_parsed == 0
    assert isinstance(rts.ip_whitelist, object)
    assert isinstance(rts.banned_ips, dict)
    assert isinstance(rts.ip_stats, object)
    assert isinstance(rts.inter_domain, IDS)
    config.ip_blacklist = ""
    rts.init_ip_blacklist(config)
    assert rts.ip_blacklist is None