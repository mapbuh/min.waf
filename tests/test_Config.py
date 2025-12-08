import pytest
from classes.Config import Config
import pathlib


class DummyConfig(Config):
    def __init__(self):
        super().__init__("test.conf")


def test_config_init_defaults(tmp_path: pathlib.Path):
    config = Config("test.conf")
    patterns = config.harmful_patterns
    assert isinstance(patterns, list)
    assert len(patterns) > 0
    longest = config.longest_harmful_pattern
    assert isinstance(longest, int)
    assert longest > 0


def test_whitelist_bot_load(monkeypatch: pytest.MonkeyPatch):
    config = DummyConfig()
    assert config.whitelist_bots
    assert 'Google' in config.whitelist_bots
    assert isinstance(config.whitelist_bots['Google'], list)
    assert len(config.whitelist_bots['Google']) > 10
