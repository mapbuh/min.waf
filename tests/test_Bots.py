from classes.Bots import Bots
from classes.Config import Config


def test_good_bot():
    config = Config("test.conf")

    assert Bots.good_bot(
        config,
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    ) is True
    assert Bots.good_bot(
        config,
        'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)'
    ) is True
    assert Bots.good_bot(
        config,
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/58.0.3029.110 Safari/537.3'
    ) is False
    assert Bots.good_bot(
        config,
        'BadBot/1.0 (+http://www.badbot.com)'
    ) is False


def test_bad_bot():
    config = Config("test.conf")

    assert Bots.bad_bot(
        config,
        'BadBot/1.0 (+http://www.badbot.com)'
    ) is True
    assert Bots.bad_bot(
        config,
        'EvilScraper/2.3 (+http://www.evilscraper.com)'
    ) is True
    assert Bots.bad_bot(
        config,
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    ) is False
    assert Bots.bad_bot(
        config,
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/58.0.3029.110 Safari/537.3'
    ) is False


def test_clear_caches_drops_cached_verdicts():
    config = Config("test.conf")
    ua = 'CachedBot/1.0'

    Bots.good_bot(config, ua)
    Bots.clear_caches()
    assert Bots.good_bot.cache_info().currsize == 0
    assert Bots.bad_bot.cache_info().currsize == 0
    # the caches work again after clearing
    assert Bots.good_bot(config, ua) is False
    assert Bots.good_bot.cache_info().currsize == 1
