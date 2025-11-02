from LogLine import LogLine
from Config import Config


class Bots:

    @staticmethod
    def good_bot(config: Config, log_line: LogLine) -> bool:
        ua = log_line.ua.lower()
        for bot_signatures in config.good_bots.values():
            for bot_signature in bot_signatures:
                if bot_signature.lower() in ua:
                    return True
        return False

    @staticmethod
    def bad_bot(config: Config, log_line: LogLine) -> str | None:
        ua = log_line.ua.lower()
        for bot_name, bot_signatures in config.bad_bots.items():
            for bot_signature in bot_signatures:
                if bot_signature.lower() in ua:
                    return f"Bad bot detected: {bot_name} - {log_line.ua}"
        return None
