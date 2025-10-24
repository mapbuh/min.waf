from typing import Any

class IpData:
    def __init__(self, data: dict[str, Any]):
        self._score = float(data.get('score', 0.0))
        self._request_count = int(data.get('request_count', 0))
        self._total_time = float(data.get('total_time', 0.0))
        self._http_status_good = int(data.get('http_status_good', 0))
        self._http_status_bad = int(data.get('http_status_bad', 0))
        self._attacks = int(data.get('attacks', 0))
        self._min_ts = int(data.get('min_ts', 0))
        self._max_ts = int(data.get('max_ts', 0))
        self._lines = data.get('lines', [])
        self._referer = data.get('referrer', {})

    @property
    def score(self) -> float:
        return self._score
    
    @score.setter
    def score(self, value: float) -> None:
        self._score = value

    @property
    def request_count(self) -> int:
        return self._request_count
    
    @request_count.setter
    def request_count(self, value: int) -> None:
        self._request_count = value

    @property
    def total_time(self) -> float:
        return self._total_time
    
    @total_time.setter
    def total_time(self, value: float) -> None:
        self._total_time = value

    @property
    def attacks(self) -> int:
        return self._attacks

    @property
    def min_ts(self) -> int:
        return self._min_ts

    @property
    def max_ts(self) -> int:
        return self._max_ts
    
    @max_ts.setter
    def max_ts(self, value: int) -> None:
        self._max_ts = value

    @property
    def lines(self) -> list[str]:
        return self._lines
    
    @property
    def avail_time(self) -> int:
        res = self._max_ts - self._min_ts
        return res if res > 0 else 1
    
    @property
    def http_status_good(self) -> int:
        return self._http_status_good
    
    @http_status_good.setter
    def http_status_good(self, value: int) -> None:
        self._http_status_good = value

    @property
    def http_status_bad(self) -> int:
        return self._http_status_bad

    @http_status_bad.setter
    def http_status_bad(self, value: int) -> None:
        self._http_status_bad = value

    @property
    def http_status_bad_perc(self) -> float:
        if self._request_count == 0:
            return 0.0
        return 100.0 * self._http_status_bad / self._request_count

    @property
    def referer(self) -> dict[str, int]:
        return self._referer

    @referer.setter
    def referer(self, value: dict[str, int]) -> None:
        self._referer = value