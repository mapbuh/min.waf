import pytest
from classes.IpWhitelist import IpWhitelist
from classes.Config import Config


@pytest.fixture
def config(monkeypatch: pytest.MonkeyPatch) -> Config:
    monkeypatch.setattr("classes.Config.BotWhitelist.load", lambda *args: {})
    return Config("test.conf")


def test_is_whitelisted(config: Config):
    ipw = IpWhitelist(config)
    assert ipw.is_whitelisted("host", "127.0.0.1")
    assert ipw.is_whitelisted("host", "192.168.0.1")
    assert ipw.is_whitelisted("host", "192.168.0.3")
    assert not ipw.is_whitelisted("host", "1.2.3.4")


def test_is_trigger(config: Config):
    ipw = IpWhitelist(config)
    result = ipw.is_trigger("example.com", "5.6.7.8", "/trigger-123", 200)
    assert result
    assert "example.com" in ipw.whitelist
    assert "5.6.7.8" in ipw.whitelist["example.com"].values()
    assert not ipw.is_trigger("example.com", "5.6.7.8", "/trigger-123", 404)
    assert not ipw.is_trigger("example.com", "5.6.7.8", "/bar", 200)
    assert not ipw.is_trigger("otherhost", "5.6.7.8", "/trigger-123", 200)
    assert ipw.is_whitelisted("example.com", "5.6.7.8")
    assert not ipw.is_whitelisted("otherhost", "5.6.7.8")
    assert ipw.is_trigger("www.example.com", "5.6.7.8", "/nova-api/articles", 200)
