import hashlib
import json
import logging
import os
import threading
import time
from typing import Any
import requests


def cache_dir_path(cache_dir: str | None = None) -> str:
    """Get or create the cache directory path."""
    if not cache_dir:
        cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../cache")
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
    return cache_dir


def requests_get_cached(
        url: str,
        timeout: int = 10,
        cache_dir: str | None = None,
        since: int = 3600,
        strict: bool = False
) -> bytes:
    """Fetch a URL with caching to avoid repeated requests."""
    logger = logging.getLogger("min.waf")
    if not cache_dir:
        cache_dir = cache_dir_path()
    cache_file = os.path.join(cache_dir, hashlib.md5(url.encode()).hexdigest())
    result: bytes = b""
    if os.path.exists(cache_file):
        with open(cache_file, 'rb') as f:
            logger.debug(f"Using cached response for {url}")
            result = f.read()
    t = None
    if not os.path.exists(cache_file) or time.time() - os.path.getmtime(cache_file) >= since:
        t = threading.Thread(target=fetch_and_cache, args=(url, timeout, cache_file, since, logger))
        t.start()
    if t and (not result or strict):
        t.join()
        with open(cache_file, 'rb') as f:
            logger.debug(f"Using freshly cached response for {url}")
            result = f.read()
    return result


lock = threading.Lock()


def fetch_and_cache(url: str, timeout: int, cache_file: str, since: int, logger: logging.Logger) -> None:
    """Fetch a URL and cache the response."""
    with lock:
        if os.path.exists(cache_file) and (time.time() - os.path.getmtime(cache_file) < since):
            logger.debug(f"Cache for {url} is freshened from another thread, skipping fetch")
            return
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        with open(cache_file, 'wb') as f:
            logger.debug(f"Fetching response from {url}")
            f.write(response.content)


def requests_get_cached_json(
    url: str,
    timeout: int = 10,
    cache_dir: str | None = None,
    since: int = 3600
) -> dict[str, Any]:
    """Fetch a URL with caching to avoid repeated requests."""
    logger = logging.getLogger("min.waf")
    if not cache_dir:
        cache_dir = cache_dir_path()
    cache_file = os.path.join(cache_dir, hashlib.md5(url.encode()).hexdigest())
    result: dict[str, Any] = {}
    with lock:
        if os.path.exists(cache_file) and (time.time() - os.path.getmtime(cache_file) < since):
            with open(cache_file, 'rb') as f:
                logger.debug(f"Using cached response for {url}")
                result = json.load(f)
        else:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            with open(cache_file, 'wb') as f:
                logger.debug(f"Fetching response from {url}")
                f.write(response.content)
                result = response.json()
    return result
