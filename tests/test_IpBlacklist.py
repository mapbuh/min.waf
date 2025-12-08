import pytest
import os
from classes.IpBlacklist import IpBlacklist
from classes.Config import Config


def test_is_ip_blacklisted(monkeypatch, tmp_path):
    config = Config("test.conf")
    ipb = IpBlacklist(config)
    # Patch list directly
    ipb.list = ["1.2.3.4", "5.6.7.8"]
    assert ipb.is_ip_blacklisted("1.2.3.4")
    assert not ipb.is_ip_blacklisted("9.9.9.9")

