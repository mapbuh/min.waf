from classes.MultipartCounter import MultipartCounter


BODY = (
    b'preamble\r\n'
    b'--xyz\r\n'
    b'Content-Disposition: form-data; name="a"\r\n'
    b'\r\n'
    b'value\r\n'
    b'--xyz\r\n'
    b'Content-Disposition: form-data; name="f[x][y]"; filename=""\r\n'
    b'Content-Type: application/octet-stream\r\n'
    b'\r\n'
    b'\r\n'
    b'--xyz\r\n'
    b'Content-Disposition: form-data; name="g"; filename="a.txt"\r\n'
    b'Content-Type: text/plain\r\n'
    b'\r\n'
    b'--xy is not a delimiter\r\n'
    b' --xyz is not a delimiter\r\n'
    b'--xyz--\r\n'
)


def feed(data: bytes, size: int | None = None, boundary: bytes = b'xyz') -> MultipartCounter:
    counter = MultipartCounter(boundary)
    size = size or len(data)
    for i in range(0, len(data), size):
        counter.feed(data[i:i + size])
    return counter


def test_counts_parts_and_structure():
    counter = feed(BODY)
    # the closing delimiter counts too, like PHP's find_boundary
    assert counter.parts == 4
    assert counter.empty_files == 1
    assert counter.nesting == 2
    assert not counter.long_header


def test_bytewise_feed_gives_same_counts():
    whole, bytewise = feed(BODY), feed(BODY, 1)
    assert (bytewise.parts, bytewise.empty_files, bytewise.nesting) == (whole.parts, whole.empty_files, whole.nesting)


def test_counts_headers_of_current_part():
    body = b'--xyz\r\nContent-Disposition: form-data; name="a"\r\n' + b'X-A: 1\r\n' * 50
    assert feed(body).part_headers == 51
    assert feed(body + b'\r\ndata\r\n--xyz\r\nA: 1\r\n').part_headers == 1


def test_empty_filename_variants():
    for disposition in (
        b'form-data; name="a"; filename=""',
        b"form-data; name='a'; FILENAME=''",
        b'form-data; name="a"; filename=',
        b'form-data; name="a"; filename= ;',
        b'form-data; name="a"; filename = "C:\\path\\"',
        b'form-data; name="a"; filename="/"',
        b'form-data; name="a"; filename="',
    ):
        body = b'--xyz\r\nContent-Disposition: ' + disposition + b'\r\n\r\n\r\n'
        assert feed(body).empty_files == 1, disposition


def test_non_empty_or_missing_filename():
    for disposition in (
        b'form-data; name="a"',
        b'form-data; name="a"; filename="a.txt"',
        b'form-data; name="a"; filename*=UTF-8\'\'',
    ):
        body = b'--xyz\r\nContent-Disposition: ' + disposition + b'\r\n\r\n\r\n'
        assert feed(body).empty_files == 0, disposition


def test_folded_empty_filename():
    body = b'--xyz\r\nContent-Disposition: form-data; name="a";\r\n filename=""\r\n\r\n\r\n'
    assert feed(body).empty_files == 1


def test_empty_filename_does_not_cross_headers():
    body = b'--xyz\r\nContent-Disposition: form-data; name="a"; filename=\r\nContent-Type: x\r\n\r\n\r\n'
    assert feed(body).empty_files == 1


def test_many_empty_files():
    body = b'--xyz\r\nContent-Disposition: form-data; name="a[]"; filename=""\r\n\r\n\r\n' * 30
    assert feed(body, 7).empty_files == 30


def test_long_header_is_flagged():
    long_name = b'A' * (MultipartCounter.max_line + 1)
    assert feed(b'--xyz\r\nContent-Disposition: form-data; name="' + long_name + b'"\r\n').long_header
    folded = b'--xyz\r\nContent-Disposition: form-data;\r\n' + (b' name="' + b'A' * 5000 + b'"\r\n') * 2
    assert feed(folded).long_header


def test_long_data_line_is_not_flagged():
    body = b'--xyz\r\nContent-Disposition: form-data; name="a"\r\n\r\n' + b'A' * 100_000 + b'\r\n--xyz--\r\n'
    counter = feed(body, 8192)
    assert not counter.long_header
    assert counter.parts == 2


def test_boundary_parsing_follows_php():
    assert MultipartCounter.boundary(b'multipart/form-data; boundary=xyz') == b'xyz'
    assert MultipartCounter.boundary(b'multipart/form-data; boundary="x;y"; a=b') == b'x;y'
    assert MultipartCounter.boundary(b'multipart/form-data; boundary=xyz; charset=utf-8') == b'xyz'
    assert MultipartCounter.boundary(b'multipart/form-data; boundary=xyz,abc') == b'xyz'
    assert MultipartCounter.boundary(b'multipart/form-data; BOUNDARY=xyz') == b'xyz'
    # the first "boundary" wins, case-sensitive match first
    assert MultipartCounter.boundary(b'multipart/form-data; xboundary=a; boundary=b') == b'a'
    assert MultipartCounter.boundary(b'multipart/form-data; BOUNDARY=a; boundary=b') == b'b'
    assert MultipartCounter.boundary(b'multipart/form-data') is None
    assert MultipartCounter.boundary(b'multipart/form-data; boundary') is None
    assert MultipartCounter.boundary(b'multipart/form-data; boundary="xyz') is None
