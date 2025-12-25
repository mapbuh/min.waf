from typing import Any
from classes.ExpiringList import ExpiringList
from classes.Config import Config
from classes.HttpHeaders import HttpHeaders


class IpData:
    _raw_lines: ExpiringList[str]
    _log_lines: ExpiringList[HttpHeaders]

    def __init__(self, config: Config, key: str, key_name: str, data: dict[str, Any]):
        self.config = config
        self.key = key
        self.key_name = key_name
        self._raw_lines = data.get("raw_lines", ExpiringList(60))
        self._log_lines = data.get("log_lines", ExpiringList(60))

    def __repr__(self) -> str:
        return f"IpData(raw_lines={self._raw_lines}, log_lines={self._log_lines})"

    @property
    def raw_lines(self) -> ExpiringList[str]:
        return self._raw_lines

    @property
    def log_lines(self) -> ExpiringList[HttpHeaders]:
        assert self._log_lines is not None
        return self._log_lines

    @property
    def min_ts(self) -> float:
        return min(self._log_lines.get_values_by_key("req_ts") or [0.0])

    @property
    def max_ts(self) -> float:
        return max(self._log_lines.get_values_by_key("req_ts") or [0.0])

    @property
    def avail_time(self) -> int:
        res = self.max_ts - self.min_ts
        return int(res) if res > 0 else 1

    @property
    def request_count(self) -> int:
        return len(self._log_lines)

    @property
    def total_time(self) -> float:
        return sum(self._log_lines.get_values_by_key("upstream_response_time"))

    @property
    def avg_time(self) -> float:
        if self.request_count == 0:
            return 0.0
        return self.total_time / self.request_count

    @property
    def http_status_bad(self) -> float:
        unique_paths: set[str] = set()
        score = 0.0
        count = 0
        for line in self._log_lines.values():
            if line.http_status in self.config.getlistint('main', 'http_status_ignore'):
                continue
            if line.path in unique_paths:
                continue
            count += 1
            unique_paths.add(line.path)
            if line.http_status in self.config.getlistint('main', 'http_status_good'):
                continue
            score += 1.0  # base score for bad status
        return score / count if count > self.config.config.getint('main', 'http_status_min_count') else 0

    @property
    def steal_time(self) -> float:
        return self.avail_time - self.total_time

    @property
    def steal_ratio(self) -> float:
        if self.avail_time == 0:
            return 0.0
        return (self.total_time / self.avail_time) * 100.0

    @property
    def score(self) -> float:
        score = 0.0
        if self.request_count < 10:
            return 0
        # bad http status
        score += min(10, (self.http_status_bad / 10.0))
        # steal ratio
        score += min(10, (self.steal_ratio / 10.0))
        return score
