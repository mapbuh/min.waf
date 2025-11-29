import pytest
from classes.Bots import Bots

class DummyConfig:
    good_bots = {
        "Google": ["Googlebot", "AdsBot-Google"],
        "Bing": ["Bingbot"]
    }
    bad_bots = {
        "Scraper": ["python-requests", "curl"],
        "Spammer": ["SpamBot"]
    }

class DummyLogLine:
    def __init__(self, ua):
        self.ua = ua

def test_good_bot_detected():
    config = DummyConfig()
    log_line = DummyLogLine("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
    assert Bots.good_bot(config, log_line) is True

def test_good_bot_not_detected():
    config = DummyConfig()
    log_line = DummyLogLine("Mozilla/5.0 (compatible; SomeOtherBot/1.0)")
    assert Bots.good_bot(config, log_line) is False

def test_bad_bot_detected():
    config = DummyConfig()
    log_line = DummyLogLine("python-requests/2.25.1")
    result = Bots.bad_bot(config, log_line)
    assert result is not None
    assert "Scraper" in result

def test_bad_bot_not_detected():
    config = DummyConfig()
    log_line = DummyLogLine("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
    assert Bots.bad_bot(config, log_line) is None