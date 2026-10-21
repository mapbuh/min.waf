from classes.ChunkedDecoder import ChunkedDecoder


def feed_bytewise(decoder: ChunkedDecoder, data: bytes) -> bytes:
    return b''.join(decoder.feed(data[i:i + 1]) for i in range(len(data)))


def test_decodes_chunks():
    body = b'5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n'
    assert ChunkedDecoder().feed(body) == b'hello world'
    assert feed_bytewise(ChunkedDecoder(), body) == b'hello world'


def test_signature_split_across_chunks_is_joined():
    body = b'b\r\nPHP_SESSION\r\n10\r\n_UPLOAD_PROGRESS\r\n0\r\n\r\n'
    assert ChunkedDecoder().feed(body) == b'PHP_SESSION_UPLOAD_PROGRESS'


def test_lf_only_line_endings():
    assert ChunkedDecoder().feed(b'3\nabc\n0\n\n') == b'abc'


def test_trailers_and_following_data_pass_through():
    decoder = ChunkedDecoder()
    assert decoder.feed(b'3\r\nabc\r\n0\r\nX-Trailer: 1\r\n\r\n') == b'abc'
    assert decoder.feed(b'GET /next HTTP/1.1\r\n') == b'GET /next HTTP/1.1\r\n'


def test_invalid_size_passes_through():
    decoder = ChunkedDecoder()
    assert decoder.feed(b'zz\r\nexec(') == b'zz\nexec('
    assert decoder.feed(b'more') == b'more'


def test_missing_crlf_after_data_passes_through():
    assert ChunkedDecoder().feed(b'3\r\nabcdef\r\n') == b'abcdef\n'


def test_overlong_size_line_passes_through():
    long_line = b'1' * (ChunkedDecoder.max_line + 1)
    assert ChunkedDecoder().feed(long_line) == long_line
