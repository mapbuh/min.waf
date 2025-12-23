from typing import Any, Optional, Dict
import hashlib
import json
import logging
import os
import requests
import threading
import time


def cache_dir_path(cache_dir: Optional[str] = None) -> str:
    """Get or create the cache directory path."""
    if not cache_dir:
        cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../cache")
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
    return cache_dir


def requests_get_cached(
    url: str,
    timeout: int = 10,
    cache_dir: Optional[str] = None,
    ttl: int = 3600,
    strict: bool = False,
    logger: logging.Logger = logging.getLogger("min.waf")
) -> bytes:
    """Fetch a URL with caching to avoid repeated requests."""
    if not cache_dir:
        cache_dir = cache_dir_path()
    cache_file = os.path.join(cache_dir, hashlib.md5(url.encode()).hexdigest())
    result: bytes = b""

    if os.path.exists(cache_file) and time.time() - os.path.getmtime(cache_file) < ttl:
        with open(cache_file, 'rb') as f:
            logger.info(f"Using cached response for {url} from {cache_file}")
            result = f.read()
        return result

    t = threading.Thread(target=fetch_and_cache, args=(url, timeout, cache_file))
    t.start()

    if not strict and os.path.exists(cache_file):
        with open(cache_file, 'rb') as f:
            logger.info(f"Using cached response for {url} from {cache_file} while fetching new data")
            result = f.read()
        return result

    t.join()
    with open(cache_file, 'rb') as f:
        logger.info(f"Using freshly cached response for {url}")
        result = f.read()
    return result


def requests_get_cached_json(
    url: str,
    timeout: int = 10,
    cache_dir: Optional[str] = None,
    ttl: int = 3600,
    strict: bool = False,
    logger: logging.Logger = logging.getLogger("min.waf")
) -> Dict[str, Any]:
    """Fetch a URL with caching to avoid repeated requests."""
    data = requests_get_cached(url, timeout, cache_dir, ttl, strict, logger)
    return json.loads(data.decode(), strict=False)


lockfile = threading.Lock()


def fetch_and_cache(
    url: str,
    timeout: int,
    cache_file: str,
) -> None:
    """Fetch a URL and cache the response."""
    global thread_map

    logger = logging.getLogger("min.waf")
    with lockfile:
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            temp_file = cache_file + ".tmp"
            with open(temp_file, 'wb') as f:
                logger.info(f"Fetching response from {url}")
                f.write(response.content)
            os.replace(temp_file, cache_file)
        except Exception as e:
            logger.error(f"Error fetching and caching {url}: {e}")
