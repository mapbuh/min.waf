import time

import pytest

from classes.IpBlacklist import IpBlacklist
from classes.Config import Config


@pytest.fixture
def config(monkeypatch: pytest.MonkeyPatch) -> Config:
    monkeypatch.setattr("classes.Config.BotWhitelist.load", lambda *args: {})
    return Config("test.conf")


@pytest.fixture
def download(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """The blacklist served to IpBlacklist; empty bytes means a failed download."""
    data = [b"1.2.3.4\n5.6.7.8\n"]
    monkeypatch.setattr("classes.IpBlacklist.Utils.requests_get_cached", lambda *args, **kwargs: data[0])
    return data


def test_is_ip_blacklisted(config: Config, download: list[bytes]):
    ipb = IpBlacklist(config)
    assert ipb.is_ip_blacklisted("1.2.3.4")
    assert ipb.is_ip_blacklisted("5.6.7.8")
    assert not ipb.is_ip_blacklisted("9.9.9.9")
    assert ipb.list_valid_until > time.time() + config.config.getint('main', 'ip_blacklist_refresh_time') - 1


def test_failed_download_retries_soon(config: Config, download: list[bytes]):
    download[0] = b""
    ipb = IpBlacklist(config)
    assert ipb.list == {}
    assert ipb.list_valid_until <= time.time() + IpBlacklist.retry_time
    download[0] = b"1.2.3.4\n"
    ipb.list_valid_until = 0
    ipb.load()
    assert ipb.is_ip_blacklisted("1.2.3.4")


def test_failed_refresh_keeps_previous_list(config: Config, download: list[bytes]):
    ipb = IpBlacklist(config)
    download[0] = b""
    ipb.list_valid_until = 0
    ipb.load()
    assert ipb.is_ip_blacklisted("1.2.3.4")


def test_without_network(config: Config):
    # requests.get is blocked and nothing is cached: an empty list, no crash
    ipb = IpBlacklist(config)
    assert ipb.list == {}
    assert not ipb.is_ip_blacklisted("1.2.3.4")


def test_disabled_blacklist(config: Config):
    config.config.set('main', 'ip_blacklist', '')
    assert IpBlacklist(config).list == {}
