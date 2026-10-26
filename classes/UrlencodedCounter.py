class UrlencodedCounter:
    """Measures the field names of a streamed form-urlencoded body.

    Follows PHP's treat_data: fields are separated by '&' and a field's name
    runs up to its first '='. Tracks the longest field name using array syntax
    ('[', also as %5B), the shape PHP parses with an allocation per level
    (PHP2Shell, CVE-2026-109618). Plain names take a different path in PHP.
    """

    def __init__(self) -> None:
        self.in_name: bool = True
        self.name_size: int = 0
        self.name_tail: bytes = b''
        self.name_array: bool = False
        self.max_array_name: int = 0

    def feed(self, data: bytes) -> None:
        pos = 0
        while pos < len(data):
            amp = data.find(b'&', pos)
            end = len(data) if amp == -1 else amp
            if self.in_name:
                eq = data.find(b'=', pos, end)
                name_end = end if eq == -1 else eq
                self._name(data[pos:name_end])
                if eq != -1:
                    self._end_name()
                    self.in_name = False
            if amp == -1:
                break
            if self.in_name:
                self._end_name()
            self.in_name = True
            pos = amp + 1

    def _name(self, chunk: bytes) -> None:
        self.name_size += len(chunk)
        if not self.name_array:
            # keep a short tail so a %5B split between reads is still seen
            window = (self.name_tail + chunk).lower()
            self.name_array = b'[' in window or b'%5b' in window
            self.name_tail = window[-2:]
        if self.name_array:
            self.max_array_name = max(self.max_array_name, self.name_size)

    def _end_name(self) -> None:
        self.name_size = 0
        self.name_tail = b''
        self.name_array = False
