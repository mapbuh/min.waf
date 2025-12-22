import functools
import ipaddress
import pytest

from classes.Bots import Bots
from classes.Config import Config
from classes.IpTables import IpTables
from classes.LogLine import LogLine
from classes.Nginx import Nginx
from classes.RunTimeStats import RunTimeStats


class DummyConfig(Config):
    def __init__(self):
        super().__init__("defaults.conf")
        self.good_bots = {
            "Google": ["Googlebot", "AdsBot-Google"],
            "Bing": ["Bingbot"]
        }
        self.bad_bots = {
            "Scraper": ["python-requests", "curl"],
            "Spammer": ["SpamBot"]
        }


def test_good_bot_detected(monkeypatch: pytest.MonkeyPatch):
    config = DummyConfig()
    assert Bots.good_bot(config, "https://developers.facebook.com/docs/sharing/webmasters/crawler") is True


def test_good_bot_not_detected():
    config = DummyConfig()
    assert Bots.good_bot(config, "Mozilla/5.0 (compatible; SomeOtherBot/1.0)") is False


def test_bad_bot_detected():
    config = DummyConfig()
    assert Bots.bad_bot(config, "python-requests/2.25.1") is True


def test_bad_bot_not_detected():
    config = DummyConfig()
    assert Bots.bad_bot(config, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)") is False


def test_bot_in_blacklist(monkeypatch: pytest.MonkeyPatch):
    def dummy_ban(self: IpTables, ip_address: str, rts: RunTimeStats, config: Config):
        return None
    monkeypatch.setattr(IpTables, "ban", dummy_ban)
    config = Config("test.conf")
    rts = RunTimeStats(config)
    rts.ip_blacklist.list = ["8.8.8.8", "9.9.9.9", "52.167.144.177"]
    assert rts.ip_blacklist.is_ip_blacklisted("8.8.8.8")
    assert config.bot_whitelist.check("Google", "66.249.79.1")
    # in bot_whitelist AND in ip_blacklist
    log_line = LogLine(
        data={"ip": "66.249.79.1", "host": "example.com", "ua": "GoogleBot", "path": "/index.html", "http_status": 200}
    )
    assert Nginx.process_http_request(config, rts, log_line, "") == Nginx.STATUS_OK

    # only in bots
    log_line = LogLine(
        data={"ip": "7.7.7.7", "host": "example.com", "ua": "GoogleBot", "path": "/index.html", "http_status": 200}
    )
    assert Nginx.process_http_request(config, rts, log_line, "") == Nginx.STATUS_OK

    # only in blacklist
    log_line = LogLine(
        data={"ip": "9.9.9.9", "host": "example.com", "ua": "SomeOtherBot", "path": "/index.html", "http_status": 200}
    )
    assert Nginx.process_http_request(config, rts, log_line, "") == Nginx.STATUS_BANNED

    # in neither
    log_line = LogLine(
        data={
            "ip": "10.10.10.10",
            "host": "example.com",
            "ua": "SomeOtherBot",
            "path": "/index.html",
            "http_status": 200
        }
    )
    assert Nginx.process_http_request(config, rts, log_line, "") == Nginx.STATUS_OK

    # bingbot
    log_line = LogLine(
        data={
            "ip": "52.167.144.177",
            "host": "www.example.com/articles/228923/Parvoto-izcyalo-onlajn-tok-shou--Kris-Nenkov-stana-vodesht",
            "ua": (
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; "
                "+http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36"
            ),
            "path": "/index.html",
            "http_status": 200}
    )
    assert Nginx.process_http_request(config, rts, log_line, "") == Nginx.STATUS_OK
