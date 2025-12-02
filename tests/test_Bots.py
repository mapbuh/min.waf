import pytest
from classes.Bots import Bots
from classes.Config import Config

class DummyConfig(Config):
    def __init__(self):
        super().__init__()
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
    assert Bots.good_bot(config, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)") is True

def test_good_bot_not_detected():
    config = DummyConfig()
    assert Bots.good_bot(config, "Mozilla/5.0 (compatible; SomeOtherBot/1.0)") is False

def test_bad_bot_detected():
    config = DummyConfig()
    assert Bots.bad_bot(config, "python-requests/2.25.1") is True

def test_bad_bot_not_detected():
    config = DummyConfig()
    assert Bots.bad_bot(config, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)") is False