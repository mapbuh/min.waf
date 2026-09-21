import configparser
import logging
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from classes.Checks import Checks
from classes.Config import Config
from classes.HttpHeaders import HttpHeaders
from classes.Proxy import Proxy


@pytest.fixture
def config():
    # Load local defaults without fetching bot ranges or blacklists.
    config = Config.__new__(Config)
    config.config = configparser.ConfigParser()
    config.config.read('defaults.conf')
    config.bot_whitelist = Mock(check=Mock(return_value=False))
    return config


@pytest.fixture
def rts():
    return SimpleNamespace(
        banned_ips={}, bans=0,
        _banned_ips_lock=threading.Lock(), _counters_lock=threading.Lock(),
        ip_whitelist=Mock(is_whitelisted=Mock(return_value=False)),
        ip_blacklist=Mock(is_ip_blacklisted=Mock(return_value=False)),
    )


@pytest.mark.parametrize('method', ['internal', 'iptables'])
@pytest.mark.parametrize('ip', ['203.0.113.10', '2001:db8::10'])
@pytest.mark.parametrize('enabled', [True, False])
def test_new_ban_logging(config, rts, monkeypatch, caplog, method, ip, enabled):
    config.config.set('main', 'ban_method', method)
    config.config.set('log', 'bans', str(enabled))
    run = Mock()
    monkeypatch.setattr('classes.IpTables.subprocess.run', run)
    caplog.set_level(logging.INFO, logger='min.waf')

    Proxy.ban(ip, rts, config, 'test reason')
    assert ip in rts.banned_ips
    rts.banned_ips[ip] = 0
    Proxy.ban(ip, rts, config, 'repeat reason')
    assert rts.banned_ips[ip] > 0
    assert caplog.messages == ([f'{ip} banned; test reason'] if enabled else [])
    assert run.call_count == (2 if method == 'iptables' else 0)


@pytest.mark.parametrize('trigger,reason', [
    ('url', 'Harmful signature detected in URL: exec('),
    ('content', 'Harmful signature detected in content: exec('),
    ('bot', 'Bad bot detected: python-requests'),
    ('blacklist', 'found in blacklist'),
])
def test_early_ban_includes_ip_and_reason(config, rts, monkeypatch, caplog, trigger, reason):
    config.config.set('main', 'ban_method', 'internal')
    # Central ban logging must work even when category logging is disabled.
    config.config.set('log', 'bad_bots', 'False')
    config.config.set('log', 'blacklist', 'False')
    headers = HttpHeaders(ip='203.0.113.10', host='example.com', path='/')
    request = b'GET / HTTP/1.1\r\n\r\n'
    if trigger == 'url':
        headers.path = '/?q=exec('
    elif trigger == 'content':
        request += b'exec('
    elif trigger == 'bot':
        headers.ua = 'python-requests'
    else:
        rts.ip_blacklist.is_ip_blacklisted.return_value = True
    proxy = Proxy.__new__(Proxy)
    proxy.config, proxy.rts = config, rts
    monkeypatch.setattr(proxy, 'read_headers', lambda *args: request)
    monkeypatch.setattr(proxy, 'parse_headers', lambda *args: headers)
    client = Mock()
    caplog.set_level(logging.INFO, logger='min.waf')

    proxy.proxy_handle_client(client, ('127.0.0.1', 12345))

    client.close.assert_called_once()
    assert headers.ip in rts.banned_ips
    assert [m for m in caplog.messages if ' banned;' in m] == [f'{headers.ip} banned; {reason}']


def test_response_rejection_reason(config, rts, caplog):
    headers = HttpHeaders(ip='203.0.113.10', host='example.com', path='/.env', http_status=404)
    config.config.set('main', 'ban_method', 'internal')
    config.config.set('main', 'url_stats', 'False')
    config.config.set('main', 'ua_stats', 'False')
    rts.ip_stats = Mock()
    rts.ip_stats.get_or_create.return_value = SimpleNamespace(
        log_lines=Mock(), http_status_bad=0, steal_time=0,
    )
    caplog.set_level(logging.INFO, logger='min.waf')

    assert not Checks.headers_with_status(headers, config, rts)
    Proxy.ban(headers.ip, rts, config, headers.ban_reason)
    assert caplog.messages[-1] == '203.0.113.10 banned; Known attack detected: example.com/.env'
