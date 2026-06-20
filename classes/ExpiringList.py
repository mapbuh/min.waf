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
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        with self._lock:
            return f"ExpiringList({self.data})"

    def touch(self, value: T) -> None:
        current_time = time.time()
        with self._lock:
            for i, (_, val) in enumerate(self.data):
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
        self.data = [
            (ts, val)
            for ts, val in self.data
            if cutoff - ts <= self.expiration_time
        ]

    def expire(self) -> None:
        with self._lock:
            self._expire_unlocked()

    def values(self) -> list[Any]:
        with self._lock:
            self._expire_unlocked()
            return [val for _, val in self.data]

    def items(self) -> list[tuple[float, T]]:
        with self._lock:
            self._expire_unlocked()
            return list(self.data)

    def len(self) -> int:
        with self._lock:
            self._expire_unlocked()
            return len(self.data)

    def __len__(self) -> int:
        with self._lock:
            self._expire_unlocked()
            return len(self.data)

    def get_values_by_key(self, key: str) -> list[Any]:
        with self._lock:
            self._expire_unlocked()
            result: list[Any] = []
            for _, val in self.data:
                if isinstance(val, dict) and key in val:
                    result.append(val[key])
                elif not isinstance(val, dict) and hasattr(val, key):
                    result.append(getattr(val, key))
            return result
