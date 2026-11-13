import signal
from unittest.mock import MagicMock

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
