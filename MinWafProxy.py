from Config import Config
from MinProxy import MinProxy
from MinWaf import MinWaf


class MinWafProxy(MinWaf):
    def __init__(self, config: Config) -> None:
        super().__init__(config)

    def run(self) -> None:
        self.min_proxy = MinProxy(self.config, self.rts)
