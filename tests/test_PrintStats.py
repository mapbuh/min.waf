import sys
import io
from classes.PrintStats import PrintStats

def test_msg_colors():
    assert "\x1b[1;31m" in PrintStats.msg_red("test")
    assert "\x1b[1;32m" in PrintStats.msg_green("test")
    assert "\x1b[1;33m" in PrintStats.msg_yellow("test")

def test_print_colors(capsys):
    PrintStats.print_red("red")
    PrintStats.print_green("green")
    PrintStats.print_yellow("yellow")
    out = capsys.readouterr()
    assert "\x1b[1;31mred\x1b[0m" in out.out
    assert "\x1b[1;32mgreen\x1b[0m" in out.out
    assert "\x1b[1;33myellow\x1b[0m" in out.err

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
    monkeypatch.setattr("logging.info", lambda msg: logs.append(msg))
    PrintStats.log_stats(DummyRts())
    assert any("Total bans: 1" in log for log in logs)

def test_print_stats(monkeypatch):
    class DummyStats:
        total_time = 1.0
        avail_time = 1
        http_status_bad = 0.0
        request_count = 1
        score = 0
    class DummyConfig:
        time_frame = 60
        detail_lines = 1
        url_stats = False
        ua_stats = False
    class DummyRts:
        start_time = 0
        bans = 1
        lines_parsed = 1
        ip_stats = {"1.2.3.4": DummyStats()}
        banned_ips = {"1.2.3.4": 123}
        ip_whitelist = type("DummyWhitelist", (), {"whitelist": {"host": type("DummyList", (), {"values": lambda self: ["1.2.3.4"]})()}})()
        url_stats = {}
        ua_stats = {}
    # Capture stdout
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    PrintStats.print_stats(DummyConfig(), DummyRts())
    output = sys.stdout.getvalue()
    sys.stdout = old_stdout
    assert "Banned: 1.2.3.4" in output
    assert "Whitelisted: host/1.2.3.4" in output