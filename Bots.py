from LogLine import LogLine
import logging


class Bots:
    good_bots: dict[str, list[str]] = {
        'Ad.Min': [
            'https://ad.min.solutions',
        ],
        'Babbar': [
            'https://babbar.tech/crawler',
        ],
        'Bing': [
            'http://www.bing.com/bingbot.htm',
        ],
        'Facebook': [
            'https://developers.facebook.com/docs/sharing/webmasters/crawler',
            'http://www.facebook.com/bot.html',
            'http://www.facebook.com/externalhit_uatext.php',
        ],
        'Google': [
            'http://www.google.com/adsbot.html',
            'http://www.google.com/bot.html',
        ],
        'Majestic': [
            'http://mj12bot.com/',
        ],
        'Monit': [
            'Monit/5.33.0',
        ],
        'SentryUptimeBot': [
            'http://docs.sentry.io/product/alerts/uptime-monitoring/',
        ],
    }
    bad_bots: dict[str, list[str]] = {
        # not Mozila, but Mozlila ;)
        'Mozlila': [
            'Mozlila/5.0',
        ],
        'Python': [
            'python-urllib',
            'python-requests',
            'python-http',
        ],
        'Go-http-client': [
            'Go-http-client/',
        ],
    }

    @staticmethod
    def good_bot(log_line: LogLine) -> bool:
        ua = log_line.ua.lower()
        for bot_signatures in Bots.good_bots.values():
            for bot_signature in bot_signatures:
                if bot_signature.lower() in ua:
                    return True
        return False

    @staticmethod
    def bad_bot(log_line: LogLine) -> bool:
        ua = log_line.ua.lower()
        for bot_name, bot_signatures in Bots.bad_bots.items():
            for bot_signature in bot_signatures:
                if bot_signature.lower() in ua:
                    logging.info(f"Bad bot detected: {log_line.ip} - {bot_name} - {log_line.ua}")
                    return True
        return False
