import os
import sys

from Config import Config
from MinProxy import MinProxy
from MinWaf import MinWaf


class MinWafProxy(MinWaf):
    def __init__(self, config: Config) -> None:
        super().__init__(config)
        if self.config.background:
            print("Running in background mode")
            pid = os.fork()
            if pid > 0:
                # Exit parent process
                sys.exit(0)

    def run(self) -> None:
        self.min_proxy = MinProxy(self.config, self.rts)
