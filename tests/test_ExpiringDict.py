import time
import pytest
from classes.ExpiringDict import ExpiringDict

def test_init_and_create():
    ed = ExpiringDict(expiration_time=2)
    ed.create("a", 123, None)
    assert ed.get("a") == 123
    assert ed.len() == 1
    assert "a" in ed.keys()

def test_expire():
    ed = ExpiringDict(expiration_time=1)
    ed.create("old", "expired", time.time() - 2)
    ed.create("new", "active", None)
    assert "old" not in ed.keys()
    assert "new" in ed.keys()
    assert ed.len() == 1

def test_delete():
    ed = ExpiringDict(expiration_time=2)
    ed.create("a", 1, None)
    ed.delete("a")
    assert ed.len() == 0
    with pytest.raises(KeyError):
        ed.delete("a")

def test_values_and_items():
    ed = ExpiringDict(expiration_time=2)
    ed.create("x", 10, None)
    ed.create("y", 20, None)
    vals = list(ed.values())
    assert 10 in vals and 20 in vals
    items = ed.items()
    assert ("x", 10) in items and ("y", 20) in items

def test_get_with_default():
    ed = ExpiringDict(expiration_time=2)
    assert ed.get("missing", "default") == "default"
    ed.create("present", 42, None)
    assert ed.get("present", "default") == 42

def test_keys():
    ed = ExpiringDict(expiration_time=2)
    ed.create("a", 1, None)
    ed.create("b", 2, None)
    keys = ed.keys()
    assert "a" in keys and "b" in keys