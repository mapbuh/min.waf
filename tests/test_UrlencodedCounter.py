import pytest

from classes.UrlencodedCounter import UrlencodedCounter


def feed(data: bytes, size: int | None = None) -> UrlencodedCounter:
    counter = UrlencodedCounter()
    size = size or len(data)
    for i in range(0, len(data), size):
        counter.feed(data[i:i + size])
    return counter


def test_plain_names_are_not_counted():
    assert feed(b'a=1&' + b'b' * 1000 + b'=2&c').max_array_name == 0


@pytest.mark.parametrize('size', [None, 1, 3, 7])
def test_longest_array_name(size):
    body = b'a=1&x' * 3 + b'&' + b'n' * 100 + b'[x]=1&short[]=2'
    assert feed(body, size).max_array_name == 103


@pytest.mark.parametrize('size', [None, 1, 2])
def test_encoded_bracket_counts(size):
    assert feed(b'nnnnn%5Bx%5D=1', size).max_array_name == 12


def test_name_without_value_runs_to_ampersand():
    assert feed(b'n[' + b'x' * 50 + b'&a=1').max_array_name == 52


def test_brackets_in_value_are_ignored():
    assert feed(b'a=[1]&b=%5b2%5d').max_array_name == 0


def test_unterminated_name_is_counted_while_streaming():
    counter = feed(b'a=1&n[' + b'x' * 10_000, 4096)
    assert counter.max_array_name == 10_002
