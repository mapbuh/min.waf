import threading
import time
from typing import Any, Callable, Generic, TypeVar

T = TypeVar('T')


class ExpiringDict(Generic[T]):

    def __init__(self, expiration_time: int):
        self.expiration_time: int = expiration_time
        self.data: dict[str, T] = {}
        self.ts: dict[str, float] = {}
        self._lock = threading.Lock()
        # full sweeps are throttled; the hot path expires only the key it touches
        self._next_sweep: float = 0.0

    def create(self, key: str, value: T, ts: float | None) -> None:
        if ts is None:
            ts = time.time()
        with self._lock:
            self._sweep_due_unlocked(ts)
            self.data[key] = value
            self.ts[key] = ts

    def delete(self, key: str) -> None:
        with self._lock:
            if key not in self.data:
                raise KeyError(f"{key} does not exist")
            del self.data[key]
            del self.ts[key]

    def _expire_key_unlocked(self, key: str, current_time: float) -> None:
        ts = self.ts.get(key)
        if ts is not None and (ts + self.expiration_time) < current_time:
            del self.data[key]
            del self.ts[key]

    def _sweep_due_unlocked(self, current_time: float) -> None:
        if current_time < self._next_sweep:
            return
        self._next_sweep = current_time + max(1, self.expiration_time // 4)
        for key in list(self.ts.keys()):
            self._expire_key_unlocked(key, current_time)

    def expire(self) -> None:
        with self._lock:
            self._next_sweep = 0.0
            self._sweep_due_unlocked(time.time())

    def len(self) -> int:
        with self._lock:
            self._sweep_due_unlocked(time.time())
            return len(self.data)

    def values(self):
        with self._lock:
            self._sweep_due_unlocked(time.time())
            return list(self.data.values())

    def items(self) -> list[tuple[str, T]]:
        with self._lock:
            self._sweep_due_unlocked(time.time())
            return list(self.data.items())

    def get(self, key: str, default: Any = None) -> T | None:
        with self._lock:
            current_time = time.time()
            self._expire_key_unlocked(key, current_time)
            self._sweep_due_unlocked(current_time)
            return self.data.get(key, default)

    def get_or_create(self, key: str, factory: Callable[[], T], ts: float | None = None) -> T:
        if ts is None:
            ts = time.time()
        with self._lock:
            self._expire_key_unlocked(key, ts)
            self._sweep_due_unlocked(ts)
            if key not in self.data:
                self.data[key] = factory()
            self.ts[key] = ts
            return self.data[key]

    def keys(self) -> list[str]:
        with self._lock:
            self._sweep_due_unlocked(time.time())
            return list(self.data.keys())
