import threading
import time

from typing import Any, Generic, TypeVar

T = TypeVar('T')


class ExpiringList(Generic[T]):
    def __init__(self, expiration_time: int):
        if expiration_time == 0:
            raise ValueError("Expiration time must be greater than zero")
        self.expiration_time = expiration_time
        self.data: list[tuple[float, T]] = []
        # expired entries are dropped by advancing this head index instead of
        # rebuilding the list; the dead prefix is compacted once it is half
        # of the list, keeping append amortized O(1)
        self._start: int = 0
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        with self._lock:
            self._expire_unlocked()
            return f"ExpiringList({self.data[self._start:]})"

    def touch(self, value: T) -> None:
        current_time = time.time()
        with self._lock:
            for i in range(self._start, len(self.data)):
                _, val = self.data[i]
                if val == value:
                    self.data[i] = (current_time, val)
                    break
            self._expire_unlocked()

    def append(self, ts: float | None, value: T) -> None:
        if ts is None:
            ts = time.time()
        with self._lock:
            self.data.append((ts, value))
            self._expire_unlocked()

    def _expire_unlocked(self) -> None:
        cutoff = time.time()
        data = self.data
        start = self._start
        n = len(data)
        while start < n and (cutoff - data[start][0]) > self.expiration_time:
            start += 1
        self._start = start
        if start and start * 2 >= n:
            self.data = data[start:]
            self._start = 0

    def expire(self) -> None:
        with self._lock:
            self._expire_unlocked()

    def values(self) -> list[Any]:
        with self._lock:
            self._expire_unlocked()
            return [val for _, val in self.data[self._start:]]

    def items(self) -> list[tuple[float, T]]:
        with self._lock:
            self._expire_unlocked()
            return list(self.data[self._start:])

    def len(self) -> int:
        with self._lock:
            self._expire_unlocked()
            return len(self.data) - self._start

    def __len__(self) -> int:
        with self._lock:
            self._expire_unlocked()
            return len(self.data) - self._start

    def get_values_by_key(self, key: str) -> list[Any]:
        with self._lock:
            self._expire_unlocked()
            result: list[Any] = []
            for _, val in self.data[self._start:]:
                if isinstance(val, dict) and key in val:
                    result.append(val[key])
                elif not isinstance(val, dict) and hasattr(val, key):
                    result.append(getattr(val, key))
            return result
