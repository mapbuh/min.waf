import time

from typing import Any, Generic, TypeVar

T = TypeVar('T')


class ExpiringList(Generic[T]):
    def __init__(self, expiration_time: int):
        if expiration_time == 0:
            raise ValueError("Expiration time must be greater than zero")
        self.expiration_time = expiration_time
        self.data: list[tuple[float, T]] = []

    def __repr__(self) -> str:
        return f"ExpiringList({self.data})"

    def append(self, ts: float | None, value: T) -> None:
        if ts is None:
            ts = time.time()
        self.data.append((ts, value))
        self.expire()

    def expire(self):
        self.data = [
            (ts, val)
            for ts, val in self.data
            if time.time() - ts <= self.expiration_time
        ]

    def values(self) -> list[Any]:
        self.expire()
        return [val for _, val in self.data]
    
    def items(self) -> list[tuple[float, T]]:
        self.expire()
        return self.data

    def len(self) -> int:
        self.expire()
        return len(self.data)

    def __len__(self) -> int:
        self.expire()
        return len(self.data)

    def get_values_by_key(self, key: str) -> list[Any]:
        self.expire()
        result: list[Any] = []
        for _, val in self.data:
            if isinstance(val, dict) and key in val:
                result.append(val[key])
            elif not isinstance(val, dict) and hasattr(val, key):
                result.append(getattr(val, key))
        return result
