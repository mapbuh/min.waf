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
    def __init__(self):
        super().__init__("test.conf")


def test_is_whitelisted(monkeypatch: pytest.MonkeyPatch):
    config = DummyConfig()
    ipw = IpWhitelist(config)
    assert ipw.is_whitelisted("host", "127.0.0.1", 'Mozilla 5.0')
    assert ipw.is_whitelisted("host", "192.168.0.1", "Mozilla 5.0")
    assert ipw.is_whitelisted("host", "192.168.0.3", "Mozilla 5.0")
    assert not ipw.is_whitelisted("host", "1.2.3.4", "Google")
    assert config.bot_whitelist.check("GoogleBot", "66.249.68.1")


def test_is_trigger(monkeypatch: pytest.MonkeyPatch):
    config = DummyConfig()
    ipw = IpWhitelist(config)
    ipw.whitelist = {}
    result = ipw.is_trigger("example.com", "5.6.7.8", "/foo", 200)
    assert result
    assert "example.com" in ipw.whitelist
    assert "5.6.7.8" in ipw.whitelist["example.com"].values()
    assert not ipw.is_trigger("example.com", "5.6.7.8", "/bar", 404)
    assert not ipw.is_trigger("otherhost", "5.6.7.8", "/foo", 200)
    assert ipw.is_whitelisted("example.com", "5.6.7.8", "Mozilla 5.0")
    assert not ipw.is_whitelisted("otherhost", "5.6.7.8", "Mozilla 5.0")
    assert ipw.is_trigger("www.example.com", "5.6.7.8", "/nova-api/articles", 200)
