import pytest
import time
from classes.Checks import Checks
from classes.Config import Config
from classes.HttpHeaders import HttpHeaders
from classes.RunTimeStats import RunTimeStats
from classes.MinWaf import MinWaf
from classes.IpBlacklist import IpBlacklist
from classes.IpData import IpData
from classes.ExpiringList import ExpiringList


@pytest.fixture
def config() -> Config:
    return Config("test.conf")


def clean_rts(config: Config) -> RunTimeStats:
    rts = RunTimeStats(config)
    rts.banned_ips = {}
    return rts

@pytest.fixture
def rts(config: Config) -> RunTimeStats:
    return clean_rts(config)


def clean_http_headers() -> HttpHeaders:
    return HttpHeaders(
        ip="10.0.0.1",
        ua="CustomUA/1.0",
        host="example.com",
        path="/index.html",
        http_status=200,
    )


def test_headers(monkeypatch: pytest.MonkeyPatch, config: Config, rts: RunTimeStats) -> None:
    # normal
    http_headers = clean_http_headers()
    assert Checks.headers(http_headers, config, rts) is True

    # already banned ip
    rts = clean_rts(config)
    rts.banned_ips[http_headers.ip] = time.time()
    assert Checks.headers(http_headers, config, rts) is False

    # ip that was banned long ago
    rts = clean_rts(config)
    rts.banned_ips[http_headers.ip] = time.time() - 3600 * 24
    MinWaf.unban_expired(config, rts)
    assert Checks.headers(http_headers, config, rts) is True

    # ip in whitelist
    rts = clean_rts(config)
    monkeypatch.setattr(
        "classes.RunTimeStats.IpWhitelist.is_whitelisted",
        lambda self, host, ip: True,  # type: ignore
    )
    assert Checks.headers(http_headers, config, rts) is True
    monkeypatch.undo()

    # ip in bot whitelist
    rts = clean_rts(config)
    monkeypatch.setattr(config.bot_whitelist, "whitelist_cache", {"CustomUA/1.0": {"10.0.0.1": "match"}})
    assert Checks.headers(http_headers, config, rts) is True
    monkeypatch.undo()

    # good bot
    http_headers.ua = "GoodBot/2.0"
    assert Checks.headers(http_headers, config, rts) is True

    # ip in blacklist
    http_headers = clean_http_headers()
    monkeypatch.setattr(IpBlacklist, "is_ip_blacklisted", lambda self, ip: True)  # type: ignore
    assert Checks.headers(http_headers, config, rts) is False
    monkeypatch.setattr(IpBlacklist, "is_ip_blacklisted", lambda self, ip: False)  # type: ignore

    # bad bot
    http_headers.ua = "BadBot/2.0"
    assert Checks.headers(http_headers, config, rts) is False
    http_headers.ua = "CustomUA/1.0"

    # host trigger
    http_headers.path = "/foo"
    assert Checks.headers(http_headers, config, rts) is True
    http_headers.path = "/index.html"

    # static file
    http_headers.path = "/image.jpeg"
    assert Checks.headers(http_headers, config, rts) is True
    http_headers.path = "/index.html"

    # harmfull pattern in path
    http_headers.path = "/xmlrpc.php?a=exec("
    assert Checks.headers(http_headers, config, rts) is False
    http_headers.path = "/index.html"


def test_headers_with_status(
        monkeypatch: pytest.MonkeyPatch,
        config: Config,
        rts: RunTimeStats,
) -> None:
    # not a known attack
    http_headers = clean_http_headers()
    http_headers.http_status = 404
    assert Checks.headers_with_status(http_headers, config, rts) is True

    # known attack
    http_headers = clean_http_headers()
    http_headers.path = "/xmlrpc.php"
    http_headers.http_status = 404
    assert Checks.headers_with_status(http_headers, config, rts) is False

    # known attack, but returns HTTP 200
    http_headers = clean_http_headers()
    rts = clean_rts(config)
    http_headers.path = "/xmlrpc.php"
    assert Checks.headers_with_status(http_headers, config, rts) is True

    # host trigger
    http_headers = clean_http_headers()
    rts = clean_rts(config)
    http_headers.path = "/trigger-123"
    assert Checks.headers_with_status(http_headers, config, rts) is True
    http_headers = clean_http_headers()
    # known attack, but ip is whitelisted
    assert Checks.headers_with_status(http_headers, config, rts) is True
    http_headers.status = HttpHeaders.STATUS_NEUTRAL
    http_headers.path = "/index.html"
    http_headers.http_status = 200


def test_content(
        monkeypatch: pytest.MonkeyPatch,
        config: Config,
) -> None:
    # clean content
    content = b"<html><body>Hello, world!</body></html>"
    http_headers = clean_http_headers()
    assert Checks.content(config, http_headers, content, 0) == (True, len(content))

    # harmful content
    http_headers = clean_http_headers()
    content = b"<script>exec()</script>"
    assert Checks.content(config, http_headers, content, 0) == (False, 0)

    # harmful, but inspection is disabled
    http_headers = clean_http_headers()
    monkeypatch.setitem(config.config['main'], 'inspect_packets', 'False')
    content = b"<script>exec()</script>"
    assert Checks.content(config, http_headers, content, 0) == (True, 0)
    monkeypatch.undo()

    # harmful, but beyond max inspect size
    http_headers = clean_http_headers()
    monkeypatch.setitem(config.config['main'], 'max_inspect_size', '10')
    content = b"<script></script><script>exec()</script>"
    assert Checks.content(config, http_headers, content, 10) == (True, 10)
    monkeypatch.undo()


def test_bad_http_stats(
        monkeypatch: pytest.MonkeyPatch,
        config: Config,
) -> None:
    http_headers = clean_http_headers()
    ip_data = IpData(
        config,
        http_headers.ip,
        'ip',
        {
            "raw_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
            "log_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
        }
    )
    # one normal log line
    ip_data.log_lines.append(time.time(), HttpHeaders(
        ip=http_headers.ip,
        http_status=200,
        path="/path1"
    ))
    assert Checks.bad_http_stats(config, http_headers, ip_data) is False

    # multiple normal log lines
    http_headers = clean_http_headers()
    for i in range(2, 20):
        ip_data.log_lines.append(time.time(), HttpHeaders(
            ip=http_headers.ip,
            http_status=200,
            path=f"/path{i}"
        ))
    assert Checks.bad_http_stats(config, http_headers, ip_data) is False

    # multiple bad log lines on same path
    http_headers = clean_http_headers()
    ip_data = IpData(
        config,
        http_headers.ip,
        'ip',
        {
            "raw_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
            "log_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
        }
    )
    for i in range(1, 20):
        ip_data.log_lines.append(time.time(), HttpHeaders(
            ip=http_headers.ip,
            http_status=500,
            path="/path1"
        ))
    assert Checks.bad_http_stats(config, http_headers, ip_data) is False

    # multiple bad log lines on different paths
    http_headers = clean_http_headers()
    ip_data = IpData(
        config,
        http_headers.ip,
        'ip',
        {
            "raw_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
            "log_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
        }
    )
    for i in range(1, 20):
        ip_data.log_lines.append(time.time(), HttpHeaders(
            ip=http_headers.ip,
            http_status=500,
            path=f"/path{i}"
        ))
    assert Checks.bad_http_stats(config, http_headers, ip_data) is True

    # 60 bad, 40 good, 50 ignored
    http_headers = clean_http_headers()
    ip_data = IpData(
        config,
        http_headers.ip,
        'ip',
        {
            "raw_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
            "log_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
        }
    )
    for i in range(1, 61):
        ip_data.log_lines.append(time.time(), HttpHeaders(
            ip=http_headers.ip,
            http_status=500,
            path=f"/badpath{i}"
        ))
    for i in range(1, 41):
        ip_data.log_lines.append(time.time(), HttpHeaders(
            ip=http_headers.ip,
            http_status=200,
            path=f"/goodpath{i}"
        ))
    for i in range(1, 51):
        ip_data.log_lines.append(time.time(), HttpHeaders(
            ip=http_headers.ip,
            http_status=301,
            path=f"/ignoredpath{i}"
        ))
    assert Checks.bad_http_stats(config, http_headers, ip_data) is True


def test_bad_steal_ratio(
        monkeypatch: pytest.MonkeyPatch,
        config: Config,
) -> None:
    http_headers = clean_http_headers()
    ip_data = IpData(
        config,
        http_headers.ip,
        'ip',
        {
            "raw_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
            "log_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
        }
    )
    for i in range(1, 20):
        ip_data.log_lines.append(time.time(), HttpHeaders(
            ip=http_headers.ip,
            upstream_response_time=i/100,
            ts=time.time()-i
        ))
    ip_data.log_lines.append(time.time(), HttpHeaders(
        ip=http_headers.ip,
        upstream_response_time=10,
        ts=time.time()
    ))
    ip_data.log_lines.append(time.time(), HttpHeaders(
        ip=http_headers.ip,
        upstream_response_time=20,
        ts=time.time()
    ))
    assert ip_data.used_time90 < 5
    assert Checks.bad_steal_ratio(config, ip_data) is False

    http_headers.status = HttpHeaders.STATUS_NEUTRAL
    ip_data = IpData(
        config,
        http_headers.ip,
        'ip',
        {
            "raw_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
            "log_lines": ExpiringList(expiration_time=config.config.getint('main', 'time_frame')),
        }
    )
    for i in range(1, 20):
        ip_data.log_lines.append(time.time(), HttpHeaders(
            ip=http_headers.ip,
            upstream_response_time=4,
            ts=time.time()-i
        ))
    assert ip_data.used_time90 > 5
    assert Checks.bad_steal_ratio(config, ip_data) is False
