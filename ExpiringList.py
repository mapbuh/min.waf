import time

class ExpiringList:
    def __init__(self, expiration_time: int):
        self.expiration_time = expiration_time
        self.data: list[tuple[float, dict]] = []

    def append(self, ts: float | None, value: dict):
        if ts is not None:
            current_time = ts
        else:
            current_time = time.time()
        self.data.append((current_time, value))
        self.expire()

    def expire(self):
        current_time = time.time()
        self.data = [(ts, val) for ts, val in self.data if current_time - ts <= self.expiration_time]

    def get_values(self) -> list[dict]:
        self.expire()
        return [val for ts, val in self.data]

    def get_values_by_key(self, key: str) -> list:
        self.expire()
        return [val.get(key, None) for ts, val in self.data]

    def len(self) -> int:
        self.expire()
        return len(self.data)

    def max_ts(self) -> float:
        self.expire()
        if not self.data:
            return time.time()
        return max(ts for ts, val in self.data)

    def min_ts(self) -> float:
        self.expire()
        if not self.data:
            return time.time() - self.expiration_time
        return min(ts for ts, val in self.data)
