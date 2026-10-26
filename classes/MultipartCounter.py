import re


class MultipartCounter:
    """Measures the structure of a streamed multipart body.

    Follows PHP's rfc1867 parser: a part starts at a line beginning with
    '--' + boundary and its headers end at the first empty line. A header line
    starting with whitespace, or without ':', continues the previous header.
    Counts the parts, the header lines of the current part, the parts with an
    empty filename and the '[' nesting of part headers, which drive PHP's
    memory use while parsing the body.
    """

    max_line: int = 8192

    _filename = re.compile(rb'filename[ \t]*=[ \t]*(?:"([^"]*)"?|\'([^\']*)\'?|([^\s;]*))', re.IGNORECASE)

    def __init__(self, boundary: bytes) -> None:
        self.delimiter: bytes = b'--' + boundary
        self._start = re.compile(rb'^' + re.escape(self.delimiter), re.MULTILINE)
        self.line: bytes = b''
        self.line_size: int = 0
        self.in_headers: bool = False
        self.header: bytes | None = None
        self.empty_file: bool = False
        self.parts: int = 0
        self.part_headers: int = 0
        self.empty_files: int = 0
        self.nesting: int = 0
        self.long_header: bool = False

    @staticmethod
    def boundary(content_type: bytes) -> bytes | None:
        """Extracts the boundary from a Content-Type value the way PHP does."""
        start = content_type.find(b'boundary')
        if start == -1:
            start = content_type.lower().find(b'boundary')
        if start == -1:
            return None
        eq = content_type.find(b'=', start)
        if eq == -1:
            return None
        value = content_type[eq + 1:]
        if value.startswith(b'"'):
            end = value.find(b'"', 1)
            if end == -1:
                return None
            return value[1:end]
        return re.split(rb'[,;]', value, maxsplit=1)[0]

    def feed(self, data: bytes) -> None:
        pos = 0
        while pos < len(data):
            if not self.in_headers and not self.line_size:
                # at a line start in part data: skip ahead to the next delimiter line
                match = self._start.search(data, pos)
                if match:
                    pos = match.start()
                else:
                    nl = data.rfind(b'\n', pos)
                    if nl != -1:
                        pos = nl + 1
            nl = data.find(b'\n', pos)
            end = len(data) if nl == -1 else nl
            room = MultipartCounter.max_line - len(self.line)
            if room > 0:
                self.line += data[pos:min(end, pos + room)]
            self.line_size += end - pos
            if nl == -1:
                break
            pos = nl + 1
            self._end_line()

    def _end_line(self) -> None:
        line = self.line.removesuffix(b'\r')
        line_size = self.line_size
        self.line = b''
        self.line_size = 0
        if not self.in_headers:
            if line.startswith(self.delimiter):
                self.parts += 1
                self.part_headers = 0
                self.in_headers = True
            return
        if not line:
            self._end_header()
            if self.empty_file:
                self.empty_files += 1
            self.empty_file = False
            self.in_headers = False
            return
        self.part_headers += 1
        if line_size > MultipartCounter.max_line:
            self.long_header = True
        if self.header is not None and (line[:1].isspace() or b':' not in line):
            self.header += line
            if len(self.header) > MultipartCounter.max_line:
                self.long_header = True
                self.header = self.header[:MultipartCounter.max_line]
            return
        self._end_header()
        self.header = line

    def _end_header(self) -> None:
        if self.header is None:
            return
        self.nesting = max(self.nesting, self.header.count(b'['))
        for filename in MultipartCounter.filenames(self.header):
            if not filename.replace(b'\\', b'/').rsplit(b'/', 1)[-1]:
                self.empty_file = True
        self.header = None

    @staticmethod
    def filenames(header: bytes) -> list[bytes]:
        """Extracts the filename values from a Content-Disposition header."""
        return [
            next((group for group in match.groups() if group is not None), b'')
            for match in MultipartCounter._filename.finditer(header)
        ]
