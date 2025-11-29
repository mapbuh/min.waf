import ipaddress
import pathlib
import pytest
from classes.IpWhitelist import IpWhitelist

class DummyExpiringList(list[str]):
    def values(self):
        return self
    def touch(self, ip: str) -> None:
        pass
    def append(self, ip: str) -> None:
        self.append(ip)

class DummyConfig:
    whitelist_permanent: str | None = None
    whitelist_triggers = {}
    whitelist_expiration = 60

def test_whitelist_load_permanent(tmp_path: pathlib.Path, monkeypatch):
    # Create a dummy whitelist file
    whitelist_file = tmp_path / "whitelist.txt"
    whitelist_file.write_text("192.168.1.0/24\n# comment\n10.0.0.0/8\n# comment line\n77.70.85.10\nxxxx\n")
    config = DummyConfig()
    config.whitelist_permanent = str(whitelist_file)
    ipw = IpWhitelist(config)
    assert any(isinstance(net, ipaddress.IPv4Network) for net in ipw.whitelist_permanent)
    assert ipaddress.ip_network("192.168.1.0/24") in ipw.whitelist_permanent
    assert ipaddress.ip_network("10.0.0.0/8") in ipw.whitelist_permanent
    config.whitelist_permanent = str(tmp_path / "nonexistent.txt")
    ipw = IpWhitelist(config)  # Should log a warning but not raise
    assert ipw.whitelist_permanent == []

def test_is_whitelisted(monkeypatch):
    config = DummyConfig()
    ipw = IpWhitelist(config)
    ipw.whitelist_permanent = [ipaddress.ip_network("127.0.0.0/8")]
    ipw.whitelist = {"host": DummyExpiringList(["1.2.3.4"])}
    assert ipw.is_whitelisted("host", "127.0.0.1")
    assert ipw.is_whitelisted("host", "1.2.3.4")
    assert not ipw.is_whitelisted("host", "8.8.8.8")
    assert not ipw.is_whitelisted("otherhost", "1.2.3.4")

def test_is_trigger(monkeypatch):
    config = DummyConfig()
    config.whitelist_triggers = {
        "host": [{"path": "/foo", "http_status": 200}]
    }
    ipw = IpWhitelist(config)
    ipw.whitelist = {}
    result = ipw.is_trigger("host", "5.6.7.8", "/foo", 200)
    assert result
    assert "host" in ipw.whitelist
    assert "5.6.7.8" in ipw.whitelist["host"].values()
    assert not ipw.is_trigger("host", "5.6.7.8", "/bar", 404)
    assert not ipw.is_trigger("otherhost", "5.6.7.8", "/foo", 200)