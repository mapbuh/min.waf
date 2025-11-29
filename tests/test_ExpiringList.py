import time
import pytest
from classes.ExpiringList import ExpiringList

def test_init_and_repr():
    el = ExpiringList(expiration_time=1)
    assert repr(el) == "ExpiringList([])"
    with pytest.raises(ValueError):
        ExpiringList(0)

def test_append_and_len():
    el = ExpiringList(expiration_time=2)
    el.append(None, "a")
    assert el.len() == 1
    assert len(el) == 1
    assert el.values() == ["a"]

def test_expire():
    el = ExpiringList(expiration_time=1)
    el.append(time.time() - 2, "old")
    el.append(None, "new")
    assert "old" not in el.values()
    assert "new" in el.values()
    assert el.len() == 1

def test_touch():
    el = ExpiringList(expiration_time=1)
    el.append(None, "a")
    time.sleep(0.5)
    el.touch("a")
    assert el.len() == 1
    time.sleep(1.1)
    el.expire()
    assert el.len() == 0

def test_items():
    el = ExpiringList(expiration_time=2)
    el.append(None, "x")
    items = el.items()
    assert isinstance(items, list)
    assert items[0][1] == "x"

def test_get_values_by_key_dict():
    el = ExpiringList(expiration_time=2)
    el.append(None, {"foo": 123, "bar": 456})
    el.append(None, {"foo": 789})
    assert el.get_values_by_key("foo") == [123, 789]

class Dummy:
    def __init__(self):
        self.key = "val"

def test_get_values_by_key_attr():
    el = ExpiringList(expiration_time=2)
    el.append(None, Dummy())
    assert el.get_values_by_key("key") == ["val"]