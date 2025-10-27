from typing import Any
from ExpiringList import ExpiringList
from LogLine import LogLine

class IpData:
    _raw_lines: ExpiringList[str]
    _log_lines: ExpiringList[LogLine]

    def __init__(self, data: dict[str, Any]):
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
        return min(self._log_lines.get_values_by_key("ts") or [0.0])

    @property
    def max_ts(self) -> float:
        return max(self._log_lines.get_values_by_key("ts") or [0.0])

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
    def http_status_bad(self) -> int:
        good_statuses: list[int] = [200, 206, 499]
        ignore_statuses: list[int] = [302, 303, 304, 307, 308]

        return len(
            [
                status
                for status in self._log_lines.get_values_by_key("http_status")
                if status in ignore_statuses or status not in good_statuses
            ]
        )
    
    @property
    def http_status_bad_perc(self) -> float:
        if self.request_count == 0:
            return 0.0
        return (self.http_status_bad / self.request_count) * 100.0
    
    @property
    def steal_time(self) -> float:
        return self.avail_time - self.total_time

    @property
    def steal_ratio(self) -> float:
        if self.avail_time == 0:
            return 0.0
        return (self.steal_time / self.avail_time) * 100.0