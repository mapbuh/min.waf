from functools import lru_cache
from classes.Config import Config

class Bots:

    @staticmethod
    @lru_cache(maxsize=1024)
    def good_bot(config: Config, user_agent: str) -> bool:
        for bot_signatures in config.good_bots.values():
            for bot_signature in bot_signatures:
                if bot_signature.lower() in user_agent.lower():
                    return True
        return False

    @staticmethod
    @lru_cache(maxsize=1024)
    def bad_bot(config: Config, user_agent: str) -> bool:
        for _, bot_signatures in config.bad_bots.items():
            for bot_signature in bot_signatures:
                if bot_signature.lower() in user_agent.lower():
                    return True
        return False
