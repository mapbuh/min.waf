from classes.RunTimeStats import IDS


def test_continuous_probes_expire_individually(monkeypatch):
    now = [0.0]
    monkeypatch.setattr('classes.RunTimeStats.time.monotonic', lambda: now[0])
    ids = IDS(expiration_time=10)
    # Simulate sustained activity for far longer than the retention window.
    for second in range(1000):
        now[0] = second
        for host in ['a', 'b', 'c']:
            ids.add('/busy', host, 404, str(second))
    assert len(ids.path['/busy'].lines()) == 33
    assert ids.counts() == [('/busy', 33)]
    assert len(ids._events) == 33
    assert set(ids.path['/busy'].lines()) == {str(i) for i in range(989, 1000)}
    now[0] = 1010
    ids.expire()
    assert ids.path == {}
    assert ids.ts == {}
    assert not ids._events


def test_expiry_removes_old_hosts_and_statuses(monkeypatch):
    now = [0.0]
    monkeypatch.setattr('classes.RunTimeStats.time.monotonic', lambda: now[0])
    ids = IDS(expiration_time=10)
    ids.add('/busy', 'old-host', 404, 'old')
    ids.add('/busy', 'active-host', 500, 'old')
    now[0] = 5
    ids.add('/busy', 'active-host', 404, 'new')
    now[0] = 11
    assert ids.counts() == [('/busy', 0)]  # fewer than three current hosts
    assert set(ids.path['/busy'].hosts) == {'active-host'}
    assert ids.path['/busy'].statuses() == [404]
    assert ids.path['/busy'].lines() == ['new']
    now[0] = 16
    assert ids.counts() == []  # reads expire records even without new probes
