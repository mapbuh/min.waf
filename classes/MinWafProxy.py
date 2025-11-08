from classes.Config import Config
from classes.MinProxy import MinProxy
from classes.MinWaf import MinWaf


class MinWafProxy(MinWaf):
    def __init__(self, config: Config) -> None:
        super().__init__(config)

    def run(self) -> None:
        self.min_proxy = MinProxy(self.config, self.rts)
