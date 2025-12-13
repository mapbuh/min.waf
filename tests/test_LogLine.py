from classes.LogLine import LogLine

def test_logline_init_and_repr():
    data: dict[str, str | float | int] = {
        "ip": "1.2.3.4",
        "upstream_response_time": 0.123,
        "req_ts": 1234567890,
        "http_status": 404,
        "req": "www.example.com/index.html",
        "ua": "Mozilla/5.0",
        "referer": "http://example.com/page?foo=bar",
        "log_line": "raw log line",
        "host": "example.com",
        "path": "/index.html"
    }
    log = LogLine(data)
    assert "LogLine(ip=1.2.3.4" in repr(log)
    assert log.ip == "1.2.3.4"
    assert log.upstream_response_time == 0.123
    assert log.req_ts == 1234567890
    assert log.http_status == 404
    assert log.req == "www.example.com/index.html"
    assert log.ua == "Mozilla/5.0"
    assert log.referer == "example.com/page"
    assert log.log_line == "raw log line"
    assert log.host == "www.example.com"
    assert log.path == "/index.html"

def test_logline_defaults():
    log = LogLine({})
    assert log.ip == ""
    assert log.upstream_response_time == 0.0
    assert isinstance(log.req_ts, int)
    assert log.http_status == 200
    assert log.req == ""
    assert log.ua == ""
    assert log.referer == ""
    assert log.log_line == ""
    assert log.host == ""
    assert log.path == ""

def test_logline_referer_parsing():
    log = LogLine({"referer": "https://foo.com/bar?baz=1"})
    assert log.referer == "foo.com/bar"
    log = LogLine({"referer": "bar?baz=1"})
    assert log.referer == "bar"
    log = LogLine({"referer": ""})
    assert log.referer == ""