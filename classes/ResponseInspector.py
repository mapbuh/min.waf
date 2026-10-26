import re

from classes.Checks import Checks
from classes.Config import Config
from classes.HttpHeaders import HttpHeaders


class ResponseInspector:
    """Holds back the response headers until they have been checked.

    Interim 1xx responses are released unchecked and the final response's
    headers are held, up to max_head bytes, so a rejected response never
    reaches the client. The body is released as it comes.
    """

    max_head: int = 65536

    _head_end = re.compile(rb'\r?\n\r?\n')
    _interim = re.compile(rb'^HTTP/\S+ 1\d\d\b')

    def __init__(self, config: Config, httpHeaders: HttpHeaders) -> None:
        self.config = config
        self.httpHeaders = httpHeaders
        self.head: bytes = b''
        self.checked: bool = False

    def feed(self, data: bytes) -> tuple[bool, bytes]:
        """Returns whether the response is clean and the bytes to release.

        Empty data marks the end of the response and releases what is held.
        """
        if self.checked:
            return True, data
        self.head += data
        released = b''
        while match := self._head_end.search(self.head):
            if not self._interim.match(self.head):
                break
            released += self.head[:match.end()]
            self.head = self.head[match.end():]
        if data and not match and len(self.head) < ResponseInspector.max_head:
            return True, released
        self.checked = True
        if not Checks.response_headers(self.config, self.httpHeaders, self.head):
            return False, b''
        released += self.head
        self.head = b''
        return True, released
