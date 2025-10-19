import time

class ExpiringList:
    def __init__(self, expiration_time: int):
        self.expiration_time = expiration_time
        self.data: list[tuple[float, float]] = []

    def append(self, value: float):
        current_time = time.time()
        self.data.append((current_time, value))
        self.expire(current_time)

    def expire(self, current_time: float):
        self.data = [(ts, val) for ts, val in self.data if current_time - ts <= self.expiration_time]

    def get_values(self) -> list[float]:
        current_time = time.time()
        self.expire(current_time)
        return [val for ts, val in self.data]

    def len(self) -> int:
        current_time = time.time()
        self.expire(current_time)
        return len(self.data)

