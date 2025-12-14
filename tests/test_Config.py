import pytest
from classes.Config import Config
import pathlib
import os
import glob


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
    assert 'Google' in config.whitelist_bots()
    assert isinstance(config.whitelist_bots()['Google'], list)
    assert len(config.whitelist_bots()['Google']) > 10
