import os
import tempfile
import shutil
import threading
import time
import pytest
from classes import Utils


class DummyResponse:
    def __init__(self, content: bytes, status_code: int = 200):
        self.content = content
        self._status_code = status_code

    def raise_for_status(self):
        if self._status_code != 200:
            raise Exception("HTTP error")


@pytest.fixture
def temp_cache_dir():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d)


def test_cache_dir_path_creates_and_returns():
    temp_cache_dir = "/tmp/min.waf_test_cache"
    path = Utils.cache_dir_path(temp_cache_dir)
    assert os.path.exists(path)
    assert os.path.isdir(path)


def test_requests_get_cached_fetch_and_cache(monkeypatch: pytest.MonkeyPatch):
    temp_cache_dir = "/tmp/min.waf_test_cache"
    url = "http://example.com/data"
    data = b"testdata"

    def fake_get(url: str, timeout: int):
        time.sleep(1)  # Simulate network delay
        return DummyResponse(data)
    monkeypatch.setattr(Utils.requests, "get", fake_get)
    # Remove cache if exists
    cache_file = os.path.join(temp_cache_dir, Utils.hashlib.md5(url.encode()).hexdigest())
    if os.path.exists(cache_file):
        os.remove(cache_file)
    result = Utils.requests_get_cached(url, cache_dir=temp_cache_dir, ttl=0, strict=True)
    assert result == data
    # Should use cache now
    result2 = Utils.requests_get_cached(url, cache_dir=temp_cache_dir, ttl=3600)
    assert result2 == data
    if os.path.exists(cache_file):
        os.remove(cache_file)


def test_requests_get_cached_json(monkeypatch: pytest.MonkeyPatch):
    temp_cache_dir = "/tmp/min.waf_test_cache"
    url = "http://example.com/json"
    json_data = {"a": 1, "b": 2}

    def fake_get(url: str, timeout: int):
        import json
        time.sleep(1)
        return DummyResponse(json.dumps(json_data).encode())
    monkeypatch.setattr(Utils.requests, "get", fake_get)
    result = Utils.requests_get_cached_json(url, cache_dir=temp_cache_dir, ttl=0, strict=False)
    assert result == json_data

    threads: list[threading.Thread] = []
    start_time = time.time()
    for _ in range(10):
        t = threading.Thread(
            target=Utils.requests_get_cached_json,
            args=(url,),
            kwargs={"cache_dir": temp_cache_dir, "ttl": 0, "strict": False}
        )
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    end_time = time.time()
    assert end_time - start_time < 5  # All threads should complete quickly due to caching

    def get_and_assert():
        res = Utils.requests_get_cached_json(url, cache_dir=temp_cache_dir, ttl=0, strict=True)
        assert res == json_data

    threads: list[threading.Thread] = []
    # delete cache to force refetch
    cache_file = os.path.join(temp_cache_dir, Utils.hashlib.md5(url.encode()).hexdigest())
    if os.path.exists(cache_file):
        os.remove(cache_file)
    start_time = time.time()
    for _ in range(10):
        t = threading.Thread(
            target=get_and_assert,
            args=(),
            kwargs={}
        )
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    end_time = time.time()
    assert end_time - start_time > 5  # All threads should complete quickly due to caching


def test_fetch_and_cache(monkeypatch: pytest.MonkeyPatch):
    temp_cache_dir = "/tmp/min.waf_test_cache"
    url = "http://example.com/fetch"
    data = b"fetchdata"

    def fake_get(url: str, timeout: int):
        return DummyResponse(data)
    monkeypatch.setattr(Utils.requests, "get", fake_get)
    cache_file = os.path.join(temp_cache_dir, Utils.hashlib.md5(url.encode()).hexdigest())
    Utils.fetch_and_cache(url, 10, cache_file)
    with open(cache_file, 'rb') as f:
        assert f.read() == data
