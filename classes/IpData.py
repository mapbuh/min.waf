from typing import Any
from classes.ExpiringList import ExpiringList
from classes.LogLine import LogLine
from classes.Config import Config


class IpData:
    _raw_lines: ExpiringList[str]
    _log_lines: ExpiringList[LogLine]

    def __init__(self, key: str, key_name: str, data: dict[str, Any]):
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
    def log_lines(self) -> ExpiringList[LogLine]:
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

    all_status_scores: dict[str, float] = {}

    @property
    def http_status_bad(self) -> float:
        good_statuses: list[int] = [200, 206, 499, 304]
        # ignore_statuses: list[int] = [301, 302, 303, 304, 307, 308]
        ignore_statuses: list[int] = [304]

        unique_paths: set[str] = set()
        score = 0.0
        count = 0
        for line in self._log_lines.values():
            if line.http_status in ignore_statuses:
                continue
            if line.path in unique_paths:
                continue
            count += 1
            unique_paths.add(line.path)
            if line.http_status in good_statuses:
                continue
            for ext in Config.static_files:
                if line.path.endswith(ext):
                    score += 0.1
                    break
            for ext in Config.dynamic_files:
                if line.path.endswith(ext):
                    score += 2.0
                    break
            score += 1.0  # base score for bad status
        if count > 3 and self.key_name == 'ip':
            IpData.all_status_scores[self.key] = score
        return score / count if count > 10 else 0

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
