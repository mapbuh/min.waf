import pathlib

import pytest

from classes.Config import Config, BotWhitelist


def ranges(*prefixes: str) -> dict:
    return {"prefixes": [{"ipv6Prefix" if ":" in p else "ipv4Prefix": p} for p in prefixes]}


def test_config_init_defaults(tmp_path: pathlib.Path):
    config = Config("test.conf")
    patterns = config.harmful_patterns()
    assert isinstance(patterns, list)
    assert len(patterns) > 0
    longest = config.longest_harmful_pattern()
    assert isinstance(longest, int)
    assert longest > 0


def test_whitelist_bot_load(monkeypatch: pytest.MonkeyPatch):
    def fake_get(url: str, **kwargs) -> dict:
        if "google" in url:
            return ranges("66.249.64.0/27", "2001:4860:4801:10::/64")
        return {}
    monkeypatch.setattr("classes.Config.Utils.requests_get_cached_json", fake_get)
    config = Config("test.conf")
    bot_whitelist = config.bot_whitelist
    assert list(bot_whitelist.whitelist) == ['Google']
    assert len(bot_whitelist.whitelist['Google']) == 2
    assert bot_whitelist.check("Mozilla/5.0 (compatible; Googlebot/2.1)", "66.249.64.1")
    assert bot_whitelist.check("Mozilla/5.0 (compatible; Googlebot/2.1)", "2001:4860:4801:10::1")
    assert not bot_whitelist.check("Mozilla/5.0 (compatible; Googlebot/2.1)", "1.2.3.4")
    assert not bot_whitelist.check("Mozilla/5.0", "66.249.64.1")


def test_whitelist_bot_load_without_network():
    # requests.get is blocked and nothing is cached: no crash, just no ranges
    bot_whitelist = BotWhitelist(Config("test.conf"))
    assert bot_whitelist.whitelist == {}


def test_whitelist_bot_reload(monkeypatch: pytest.MonkeyPatch):
    data = {"google": ranges("66.249.64.0/27"), "bing": ranges("40.77.167.0/24")}
    monkeypatch.setattr(
        "classes.Config.Utils.requests_get_cached_json",
        lambda url, **kwargs: next((v for k, v in data.items() if k in url), {}),
    )
    bot_whitelist = BotWhitelist(Config("test.conf"))
    assert bot_whitelist.check("Googlebot", "66.249.64.1")
    # a refresh replaces the ranges and the lookup cache
    data["google"] = ranges("66.249.65.0/27")
    bot_whitelist.load()
    assert not bot_whitelist.check("Googlebot", "66.249.64.1")
    assert bot_whitelist.check("Googlebot", "66.249.65.1")
    # a failed refresh keeps the previous ranges of that bot only
    data["google"] = {}
    data["bing"] = ranges("157.55.39.0/24")
    bot_whitelist.load()
    assert bot_whitelist.check("Googlebot", "66.249.65.1")
    assert bot_whitelist.check("bingbot", "157.55.39.1")
    assert not bot_whitelist.check("bingbot", "40.77.167.1")
