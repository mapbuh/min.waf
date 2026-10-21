import re


class ChunkedDecoder:
    """Incrementally decodes a Transfer-Encoding: chunked request body.

    After the terminating chunk, or on invalid framing, the remaining bytes are
    passed through unchanged so they are still inspected.
    """

    max_line: int = 4096

    SIZE = 0
    DATA = 1
    DATA_END = 2
    TRAILER = 3
    PASSTHROUGH = 4

    _size = re.compile(rb'[0-9a-fA-F]+')

    def __init__(self) -> None:
        self.state: int = ChunkedDecoder.SIZE
        self.line: bytes = b''
        self.remaining: int = 0

    def feed(self, data: bytes) -> bytes:
        out = bytearray()
        pos = 0
        while pos < len(data):
            if self.state == ChunkedDecoder.PASSTHROUGH:
                out += data[pos:]
                break
            if self.state == ChunkedDecoder.DATA:
                chunk = data[pos:pos + self.remaining]
                out += chunk
                pos += len(chunk)
                self.remaining -= len(chunk)
                if self.remaining == 0:
                    self.state = ChunkedDecoder.DATA_END
                continue
            # SIZE, DATA_END and TRAILER are line based
            nl = data.find(b'\n', pos)
            end = len(data) if nl == -1 else nl
            self.line += data[pos:end]
            pos = end
            if len(self.line) > ChunkedDecoder.max_line:
                self._passthrough(out)
                continue
            if nl == -1:
                break
            pos = nl + 1
            line = self.line.removesuffix(b'\r')
            self.line = b''
            if self.state == ChunkedDecoder.SIZE:
                size = line.split(b';', 1)[0].strip()
                if not self._size.fullmatch(size):
                    self.line = line + b'\n'
                    self._passthrough(out)
                    continue
                self.remaining = int(size, 16)
                self.state = ChunkedDecoder.DATA if self.remaining else ChunkedDecoder.TRAILER
            elif self.state == ChunkedDecoder.DATA_END:
                if line:
                    self.line = line + b'\n'
                    self._passthrough(out)
                    continue
                self.state = ChunkedDecoder.SIZE
            elif not line:  # TRAILER ends with an empty line
                self.state = ChunkedDecoder.PASSTHROUGH
        return bytes(out)

    def _passthrough(self, out: bytearray) -> None:
        out += self.line
        self.line = b''
        self.state = ChunkedDecoder.PASSTHROUGH
