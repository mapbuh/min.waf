import pathlib

import pytest
import requests

from classes.Utils import Utils


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    """Keeps tests away from the network and from the project's cache directory.

    Tests that need a download monkeypatch requests.get themselves.
    """
    def blocked(url: str, *args, **kwargs):
        raise requests.ConnectionError(f"network access disabled in tests: {url}")
    monkeypatch.setattr(requests, "get", blocked)
    cache_dir_path = Utils.cache_dir_path
    monkeypatch.setattr(
        Utils,
        "cache_dir_path",
        staticmethod(lambda cache_dir=None: cache_dir_path(cache_dir or str(tmp_path / "cache"))),
    )
