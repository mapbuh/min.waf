import pytest
import tempfile
import os
from classes.IpBlacklist import IpBlacklist

class DummyConfig:
    ip_blacklist = "http://example.com/blacklist.txt"
    ip_blacklist_refresh_time = 3600

def test_is_file_recent(tmp_path):
    config = DummyConfig()
    ipb = IpBlacklist(config)
    test_file = tmp_path / "test.txt"
    test_file.write_text("data")
    # File just created, should be recent
    assert ipb.is_file_recent(str(test_file), 10)
    # File modified long ago, should not be recent
    old_time = os.path.getmtime(test_file)
    os.utime(test_file, (old_time - 10000, old_time - 10000))
    assert not ipb.is_file_recent(str(test_file), 10)

def test_is_ip_blacklisted(monkeypatch, tmp_path):
    config = DummyConfig()
    ipb = IpBlacklist(config)
    # Patch list directly
    ipb.list = ["1.2.3.4", "5.6.7.8"]
    assert ipb.is_ip_blacklisted("1.2.3.4")
    assert not ipb.is_ip_blacklisted("9.9.9.9")

def test_refresh_list_reads_file(monkeypatch, tmp_path):
    config = DummyConfig()
    ipb = IpBlacklist(config)
    test_file = tmp_path / "ip_blacklist.txt"
    test_file.write_text("1.2.3.4\n5.6.7.8\n")
    ipb.filename = str(test_file)
    ipb.list = []
    monkeypatch.setattr(ipb, "is_file_recent", lambda f, t: True)
    ipb.refresh_list()
    assert "1.2.3.4" in ipb.list
    assert "5.6.7.8" in ipb.list

def test_download_file(monkeypatch: pytest.MonkeyPatch, tmp_path):
    config = DummyConfig()
    ipb = IpBlacklist(config)
    called = {}
    def fake_requests_get(url):
        class Response:
            content = b"1.2.3.4\n"
            def raise_for_status(self): pass
        called["url"] = url
        return Response()
    monkeypatch.setattr("requests.get", fake_requests_get)
    # Patch os.fork to avoid forking in test
    monkeypatch.setattr("os.fork", lambda: 0)
    monkeypatch.setattr("os._exit", lambda x: None)
    ipb.download_file("http://example.com/blacklist.txt", str(tmp_path / "ip_blacklist.txt"))
    assert called["url"] == "http://example.com/blacklist.txt"