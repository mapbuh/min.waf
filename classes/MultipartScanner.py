import re


class MultipartScanner:
    """Extracts Content-Disposition part headers from a streamed multipart body.

    Follows PHP's rfc1867 header parsing: a line starting with whitespace, or
    without ':', continues the previous header and is appended without a
    separator, so a field name split over several lines is reassembled.
    Boundaries are not tracked; matching lines inside file data are reported
    too, which can only over-match.
    """

    max_line: int = 8192

    _start = re.compile(rb'^[ \t]*content-disposition[ \t]*:', re.IGNORECASE | re.MULTILINE)

    def __init__(self) -> None:
        self.line: bytes = b''
        self.header: bytes | None = None

    def feed(self, data: bytes) -> list[bytes]:
        headers: list[bytes] = []
        pos = 0
        while pos < len(data):
            if self.header is None and not self.line:
                # at a line start: skip ahead to the next Content-Disposition line
                match = self._start.search(data, pos)
                if match:
                    pos = match.start()
                else:
                    nl = data.rfind(b'\n', pos)
                    if nl != -1:
                        pos = nl + 1
            nl = data.find(b'\n', pos)
            end = len(data) if nl == -1 else nl
            room = MultipartScanner.max_line - len(self.line)
            if room > 0:
                self.line += data[pos:min(end, pos + room)]
            if nl == -1:
                break
            pos = nl + 1
            self._end_line(headers)
        return headers

    def _end_line(self, headers: list[bytes]) -> None:
        line = self.line.removesuffix(b'\r')
        self.line = b''
        if self.header is not None and line and (line[:1].isspace() or b':' not in line):
            self.header = (self.header + line)[:MultipartScanner.max_line]
            headers.append(self.header)
            return
        self.header = None
        key, sep, _ = line.partition(b':')
        if sep and key.strip().lower() == b'content-disposition':
            self.header = line
            headers.append(line)
