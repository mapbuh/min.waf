from functools import lru_cache
from classes.Config import Config


class Bots:

    @staticmethod
    @lru_cache(maxsize=1024)
    def good_bot(config: Config, user_agent: str) -> bool:
        for bot_signature in config.getlist('bots', 'good_bots'):
            if bot_signature.lower() in user_agent.lower():
                return True
        return False

    @staticmethod
    @lru_cache(maxsize=1024)
    def bad_bot(config: Config, user_agent: str) -> bool:
        for bot_signature in config.getlist('bots', 'bad_bots'):
            if bot_signature.lower() in user_agent.lower():
                return True
        return False
