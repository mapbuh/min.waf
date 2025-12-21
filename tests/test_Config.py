import pytest
import pathlib
import os
import glob

from classes.Config import Config, BotWhitelist


def test_config_init_defaults(tmp_path: pathlib.Path):
    config = Config("test.conf")
    patterns = config.harmful_patterns()
    assert isinstance(patterns, list)
    assert len(patterns) > 0
    longest = config.longest_harmful_pattern()
    assert isinstance(longest, int)
    assert longest > 0


def test_whitelist_bot_load(monkeypatch: pytest.MonkeyPatch):
    cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../cache")
    cache_files = glob.glob(cache_dir + "/*", recursive=False)
    for cache_file in cache_files:
        try:
            os.remove(cache_file)
        except OSError:
            pass
    config = Config("test.conf")
    bot_whitelist = BotWhitelist(config)
    assert 'Google' in bot_whitelist.whitelist
    assert isinstance(bot_whitelist.whitelist['Google'], list)
    assert len(bot_whitelist.whitelist['Google']) > 10
