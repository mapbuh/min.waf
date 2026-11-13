import configparser
import signal
from unittest.mock import MagicMock

import pytest

from classes.Config import Config
from classes.MinWaf import MinWaf


def test_sigterm_cleans_up_and_exits_immediately(monkeypatch, caplog):
    # the default executor shutdown waits for idle connections up to the
    # idle timeout; SIGTERM must exit right after cleanup instead
    import logging
    waf = MinWaf.__new__(MinWaf)
    at_exit = MagicMock()
    exit_ = MagicMock()
    monkeypatch.setattr(waf, "at_exit", at_exit)
    monkeypatch.setattr("classes.MinWaf.os._exit", exit_)
    caplog.set_level(logging.INFO, logger="min.waf")

    waf.signal_handler(signal.SIGTERM, None)

    at_exit.assert_called_once()
    exit_.assert_called_once_with(0)
    assert "Received signal 15, exiting..." in caplog.messages


def _minwaf_with_lockfile(tmp_path):
    config = Config.__new__(Config)
    config.config = configparser.ConfigParser()
    config.config.read("defaults.conf")
    config.config.set("main", "lockfile", str(tmp_path / "min.waf.pid"))
    waf = MinWaf.__new__(MinWaf)
    waf.config = config
    return waf


def test_lockfile_blocks_second_instance(tmp_path):
    first = _minwaf_with_lockfile(tmp_path)
    first.lockfile_init()
    try:
        second = _minwaf_with_lockfile(tmp_path)
        with pytest.raises(SystemExit):
            second.lockfile_init()
    finally:
        first.lockfile_remove()
    # after the lock is released another instance can start
    third = _minwaf_with_lockfile(tmp_path)
    third.lockfile_init()
    third.lockfile_remove()
