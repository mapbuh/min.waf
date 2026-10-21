import re

from classes.Checks import Checks
from classes.ChunkedDecoder import ChunkedDecoder
from classes.Config import Config
from classes.HttpHeaders import HttpHeaders
from classes.MultipartScanner import MultipartScanner


class RequestInspector:
    """Runs the content checks over a request as it streams in.

    Chunked bodies are decoded first, so chunk framing cannot split a signature.
    For multipart bodies the part headers are checked over the whole body, not
    only the first max_inspect_size bytes.
    """

    _head_end = re.compile(rb'\r?\n\r?\n')
    _chunked = re.compile(rb'^transfer-encoding:[^\n]*chunked', re.IGNORECASE | re.MULTILINE)
    _multipart = re.compile(rb'^content-type:[^\n]*multipart/', re.IGNORECASE | re.MULTILINE)

    def __init__(self, config: Config, httpHeaders: HttpHeaders) -> None:
        self.config = config
        self.httpHeaders = httpHeaders
        self.inspected: bytes = b''
        self.clean_upto: int = 0
        self.in_body: bool = False
        self.chunked: ChunkedDecoder | None = None
        self.multipart: MultipartScanner | None = None

    def feed(self, data: bytes) -> bool:
        max_inspect_size = self.config.config.getint("main", "max_inspect_size")
        if self.in_body and len(self.inspected) >= max_inspect_size and not self.multipart:
            return True
        if not self.in_body:
            self.inspected += data
            match = self._head_end.search(self.inspected)
            if not match:
                return self._content()
            self.in_body = True
            head = self.inspected[:match.end()]
            data = self.inspected[match.end():]
            self.inspected = head
            if self._chunked.search(head):
                self.chunked = ChunkedDecoder()
            if self._multipart.search(head):
                self.multipart = MultipartScanner()
        if self.chunked:
            data = self.chunked.feed(data)
        if len(self.inspected) < max_inspect_size:
            self.inspected += data
            if not self._content():
                return False
        if self.multipart:
            return Checks.multipart_headers(self.config, self.httpHeaders, self.multipart.feed(data))
        return True

    def _content(self) -> bool:
        clean, self.clean_upto = Checks.content(self.config, self.httpHeaders, self.inspected, self.clean_upto)
        return clean
