import threading
import time
from typing import Any, Generic, TypeVar

T = TypeVar('T')


class ExpiringDict(Generic[T]):

    def __init__(self, expiration_time: int):
        self.expiration_time: int = expiration_time
        self.data: dict[str, T] = {}
        self.ts: dict[str, float] = {}
        self._lock = threading.Lock()

    def create(self, key: str, value: T, ts: float | None) -> None:
        if ts is None:
            ts = time.time()
        with self._lock:
            self.data[key] = value
            self.ts[key] = ts

    def delete(self, key: str) -> None:
        with self._lock:
            if key not in self.data:
                raise KeyError(f"{key} does not exist")
            del self.data[key]
            del self.ts[key]

    def _expire_unlocked(self):
        current_time = time.time()
        for key in list(self.ts.keys()):
            if key in self.ts and ((self.ts[key] + self.expiration_time) < current_time):
                del self.data[key]
                del self.ts[key]

    def expire(self):
        with self._lock:
            self._expire_unlocked()

    def len(self) -> int:
        with self._lock:
            self._expire_unlocked()
            return len(self.data)

    def values(self):
        with self._lock:
            self._expire_unlocked()
            return list(self.data.values())

    def items(self) -> list[tuple[str, T]]:
        with self._lock:
            self._expire_unlocked()
            return list(self.data.items())

    def get(self, key: str, default: Any = None) -> T | None:
        with self._lock:
            self._expire_unlocked()
            return self.data.get(key, default)

    def keys(self) -> list[str]:
        with self._lock:
            self._expire_unlocked()
            return list(self.data.keys())
