import time
from typing import Any, Generic, TypeVar

T = TypeVar('T')


class ExpiringDict(Generic[T]):

    def __init__(self, expiration_time: int):
        self.expiration_time: int = expiration_time
        self.data: dict[str, T] = {}
        self.ts: dict[str, float] = {}

    def create(self, key: str, value: T, ts: float | None) -> None:
        if ts is None:
            ts = time.time()
        self.data[key] = value
        self.ts[key] = ts

    def delete(self, key: str) -> None:
        if not key in self.data:
            raise KeyError(f"{key} does not exist")
        del self.data[key]
        del self.ts[key]

    def expire(self):
        current_time = time.time()
        for key in list(self.ts.keys()):
            if self.ts[key] + self.expiration_time < current_time:
                del self.data[key]
                del self.ts[key]

    def len(self) -> int:
        self.expire()
        return len(self.data)

    def values(self):
        self.expire()
        return self.data.values()

    def items(self) -> list[tuple[str, T]]:
        self.expire()
        return list(self.data.items())

    def get(self, key: str, default: Any = None) -> T | None:
        self.expire()
        return self.data.get(key, default)

    def keys(self) -> list[str]:
        self.expire()
        return list(self.data.keys())
