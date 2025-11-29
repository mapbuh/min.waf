import pytest
import yaml
import tempfile
import os
from classes.Config import Config

def test_config_init_defaults():
    config = Config()
    assert isinstance(config.columns, dict)
    assert config.proxy_listen_host == "127.0.0.1"
    assert config.mode == "proxy"
    assert config.whitelist_expiration == 36000

def test_config_load(tmp_path):
    config = Config()
    config.immutables = ["mode"]
    config.mode = "proxy"
    config_file = tmp_path / "config.yaml"
    data = {
        "proxy_listen_host": "0.0.0.0",
        "mode": "log2ban",
        "ban_time": 1234,
        "whitelist_expiration": 9999
    }
    config_file.write_text(yaml.dump(data))
    config.load(str(config_file))
    # mode should not change because it's immutable
    assert config.mode == "proxy"
    assert config.proxy_listen_host == "0.0.0.0"
    assert config.ban_time == 1234
    assert config.whitelist_expiration == 9999

def test_config_load_nonexistent(monkeypatch):
    config = Config()
    with pytest.raises(FileNotFoundError):
        config.load("/nonexistent/config.yaml")