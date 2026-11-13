from functools import lru_cache
from classes.Config import Config


class Bots:

    @staticmethod
    def clear_caches() -> None:
        """Drop cached verdicts so a config reload takes effect immediately."""
        Bots.good_bot.cache_clear()
        Bots.bad_bot.cache_clear()

    @staticmethod
    @lru_cache(maxsize=1024)
    def good_bot(config: Config, user_agent: str) -> bool:
        ua_lower = user_agent.lower()
        for bot_signature in config.getlist('bots', 'good_bots'):
            if bot_signature.lower() in ua_lower:
                return True
        return False

    @staticmethod
    @lru_cache(maxsize=1024)
    def bad_bot(config: Config, user_agent: str) -> bool:
        ua_lower = user_agent.lower()
        for bot_signature in config.getlist('bots', 'bad_bots'):
            if bot_signature.lower() in ua_lower:
                return True
        return False
