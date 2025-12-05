import ipaddress
import pathlib
import pytest
from classes.IpWhitelist import IpWhitelist
from classes.Config import Config


class DummyExpiringList(list[str]):
    def values(self):
        return self

    def touch(self, ip: str) -> None:
        pass

    def append(self, ip: str) -> None:
        self.append(ip)


class DummyConfig(Config):
    whitelist_permanent = ""
    whitelist_triggers = {}
    whitelist_expiration = 60
    bots = {}


def test_whitelist_bot_load(monkeypatch: pytest.MonkeyPatch):
    config = DummyConfig()
    config.bots = {
        'Google': {
            'user_agent': 'GoogleUA',
            'ip_ranges_url': 'https://developers.google.com/static/search/apis/ipranges/googlebot.json',
            'action': 'allow',
        },
    }
    ipw = IpWhitelist(config)
    ipw.whitelist_load_bots()
    assert ipw.whitelist_bots
    assert 'GoogleUA' in ipw.whitelist_bots
    assert isinstance(ipw.whitelist_bots['GoogleUA'], list)
    assert len(ipw.whitelist_bots['GoogleUA']) > 10


def test_whitelist_load_permanent(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
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


def test_is_whitelisted(monkeypatch: pytest.MonkeyPatch):
    config = DummyConfig()
    ipw = IpWhitelist(config)
    ipw.whitelist_permanent = [ipaddress.ip_network("127.0.0.0/8")]
    ipw.whitelist = {"host": DummyExpiringList(["1.2.3.4"])}
    assert ipw.is_whitelisted("host", "127.0.0.1", 'Mozilla 5.0')
    assert ipw.is_whitelisted("host", "1.2.3.4", "Mozilla 5.0")
    assert not ipw.is_whitelisted("host", "8.8.8.8", "Mozilla 5.0")
    assert not ipw.is_whitelisted("otherhost", "1.2.3.4", "Mozilla 5.0")
    ipw.whitelist_bots = {
        'GoogleUA': [ipaddress.ip_network("2.3.4.0/24")],
    }
    assert ipw.is_whitelisted("host", "2.3.4.5", "GoogleUA")
    assert not ipw.is_whitelisted("host", "8.8.8.8", "GoogleUA")
    assert not ipw.is_whitelisted("host", "2.3.4.5", "Mozilla 5.0")
    assert not ipw.is_whitelisted("host", "8.8.8.8", "Mozilla 5.0")


def test_is_trigger(monkeypatch: pytest.MonkeyPatch):
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
