import pytest
from classes.Checks import Checks
from classes.LogLine import LogLine
from classes.Config import Config
from classes.IpData import IpData


class DummyLogLine(LogLine):
    def __init__(self, path: str = "/attack", http_status: int = 404, ip: str = "1.2.3.4", host: str = "host"):
        super().__init__({path: path, "http_status": http_status, "ip": ip, "host": host})


class DummyInterDomain:
    def __init__(self):
        self.calls: list[tuple[str, str, int, str]] = []

    def add(self, path: str, host: str, http_status: int, raw_line: str):
        self.calls.append((path, host, http_status, raw_line))


class DummyRunTimeStats:
    def __init__(self):
        self.inter_domain = DummyInterDomain()


class DummyIpData(IpData):
    steal_time: float = 0.0  # pyright: ignore[reportIncompatibleMethodOverride]
    avail_time: int = 1  # pyright: ignore[reportIncompatibleMethodOverride]
    total_time: float = 0.0  # pyright: ignore[reportIncompatibleMethodOverride]
    steal_ratio: float = 0.0  # pyright: ignore[reportIncompatibleMethodOverride]


def test_bad_steal_ratio(monkeypatch: pytest.MonkeyPatch) -> None:
    config = Config("test.conf")
    ip_data = DummyIpData(config, "1.2.3.5", "ip", {})
    monkeypatch.setattr(ip_data, 'steal_time', -15)
    monkeypatch.setattr(ip_data, 'avail_time', 11)
    monkeypatch.setattr(ip_data, 'total_time', 30)
    monkeypatch.setattr(ip_data, 'steal_ratio', 0.6)
    assert Checks.bad_steal_ratio(config, ip_data) is True

    monkeypatch.setattr(ip_data, 'steal_time', -5)
    monkeypatch.setattr(ip_data, 'avail_time', 4)
    assert Checks.bad_steal_ratio(config, ip_data) is False
