#!/usr/bin/env python3

import atexit
from typing import Any
import click
import logging
import os
import subprocess
import sys
import time

from ExpiringDict import ExpiringDict
from ExpiringList import ExpiringList
from Nginx import Nginx
from PrintStats import PrintStats
from IpData import IpData
# from KnownAttacks import KnownAttacks

ip_ignored: list[str] = []
times_by_url: dict[str, ExpiringList] = {}
status_by_ip: dict[str, ExpiringList] = {}
times_by_ua: dict[str, ExpiringList] = {}
banned_ips: dict[str, float] = {}
ip_stats: ExpiringDict
url_by_ip: ExpiringDict

config: dict[str, Any] = {
    'columns': {
        'remote_addr': -1,
        'host': -1,
        'time_local': -1,
        'request': -1,
        'status': -1,
        'upstream_response_time': -1,
        'http_referer': -1,
        'http_user_agent': -1,
    },
    'time_frame': 300,
    'ban_time': 600,
    'background': False,
    'url_stats': False,
    'ua_stats': False,
    'referer_stats': False,
    'lockfile': '/var/run/min.waf.lock',
    'detail_lines': 10,
    'start_time': None,
    'lines_parsed': 0,
}



log_file_path: str = ''

times_by_url_stats: dict[str, dict[str, Any]] = {}
ua_stats: dict[str, dict[str, Any]] = {}
referer_data: dict[str, ExpiringList] = {}


def init() -> None:
    global log_file_path, ip_stats, url_by_ip
    nginx_config = Nginx.config_get()
    log_file_path = nginx_config['log_file_path']
    log_format = nginx_config['log_format']
    config['columns'] = Nginx.parse_log_format(log_format)
    for config_line in config['columns']:
        if config['columns'][config_line] == -1:
            print(f"Could not find column for {config_line} in log_format")
            sys.exit(1)

    ip_stats = ExpiringDict(config['time_frame'])
    url_by_ip = ExpiringDict(config['time_frame'])
    lockfile_init()
    atexit.register(lockfile_remove)
    iptables_init()
    atexit.register(iptables_clear)
    logging.basicConfig(filename="/var/log/min.waf.log", filemode='a', format='%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
    config['start_time'] = time.time()
    logging.info("min.waf started")


def lockfile_remove():
    if os.path.exists(config['lockfile']):
        os.remove(config['lockfile'])

def lockfile_init():
    if os.path.exists(config['lockfile']):
        print(f"Lockfile {config['lockfile']} exists, another instance may be running. Exiting.")
        sys.exit(1)
    with open(config['lockfile'], 'w') as f:
        f.write(str(os.getpid()))


def iptables_clear() -> None:
    # IPv4
    subprocess.run(['iptables', '-D', 'INPUT', '-j', 'MINWAF'], stderr=subprocess.DEVNULL)
    subprocess.run(['iptables', '-F', 'MINWAF'], stderr=subprocess.DEVNULL)
    subprocess.run(['iptables', '-X', 'MINWAF'], stderr=subprocess.DEVNULL)
    # IPv6
    subprocess.run(['ip6tables', '-D', 'INPUT', '-j', 'MINWAF'], stderr=subprocess.DEVNULL)
    subprocess.run(['ip6tables', '-F', 'MINWAF'], stderr=subprocess.DEVNULL)
    subprocess.run(['ip6tables', '-X', 'MINWAF'], stderr=subprocess.DEVNULL)


def iptables_init():
    iptables_clear()
    # IPv4
    subprocess.run(['iptables', '-N', 'MINWAF'])
    subprocess.run(['iptables', '-I', 'INPUT', '-j', 'MINWAF'])
    # IPv6
    subprocess.run(['ip6tables', '-N', 'MINWAF'])
    subprocess.run(['ip6tables', '-I', 'INPUT', '-j', 'MINWAF'])

def iptables_slow(ip_address: str):
    if ip_address in banned_ips:
        banned_ips[ip_address] = time.time()
        return
    banned_ips[ip_address] = time.time()
    if ':' in ip_address:
        subprocess.run(['ip6tables', '-A', 'MINWAF', '-s', ip_address, '-p', 'tcp', '--dport', '80', '-j', 'TARPIT'])
        subprocess.run(['ip6tables', '-A', 'MINWAF', '-s', ip_address, '-p', 'tcp', '--dport', '443', '-j', 'TARPIT'])
        return
    subprocess.run(['iptables', '-A', 'MINWAF', '-s', ip_address, '-p', 'tcp', '--dport', '80', '-j', 'TARPIT'])
    subprocess.run(['iptables', '-A', 'MINWAF', '-s', ip_address, '-p', 'tcp', '--dport', '443', '-j', 'TARPIT'])

def iptables_ban(ip_address: str):
    if ip_address in banned_ips:
        banned_ips[ip_address] = time.time()
        return
    banned_ips[ip_address] = time.time()
    if ':' in ip_address:
        subprocess.run(['ip6tables', '-A', 'MINWAF', '-s', ip_address, '-p', 'tcp', '--dport', '80', '-j', 'DROP'])
        subprocess.run(['ip6tables', '-A', 'MINWAF', '-s', ip_address, '-p', 'tcp', '--dport', '443', '-j', 'DROP'])
        return
    subprocess.run(['iptables', '-A', 'MINWAF', '-s', ip_address, '-p', 'tcp', '--dport', '80', '-j', 'DROP'])
    subprocess.run(['iptables', '-A', 'MINWAF', '-s', ip_address, '-p', 'tcp', '--dport', '443', '-j', 'DROP'])


def iptables_unban_expired():
    current_time = time.time()
    for ip in list(banned_ips.keys()):
        if current_time - banned_ips[ip] > config['ban_time']:
            del banned_ips[ip]
            if ':' in ip:
                subprocess.run(['ip6tables', '-D', 'MINWAF', '-s', ip, '-p', 'tcp', '--dport', '80', '-j', 'DROP'])
                subprocess.run(['ip6tables', '-D', 'MINWAF', '-s', ip, '-p', 'tcp', '--dport', '443', '-j', 'DROP'])
            else:
                subprocess.run(['iptables', '-D', 'MINWAF', '-s', ip, '-p', 'tcp', '--dport', '80', '-j', 'DROP'])
                subprocess.run(['iptables', '-D', 'MINWAF', '-s', ip, '-p', 'tcp', '--dport', '443', '-j', 'DROP'])
            logging.info(f"Unbanned IP {ip} after {config['ban_time']}s")


def tail_f(filename: str):
    refresh_ts = time.time()
    with open(filename, 'r') as f:
        # Go to the end of the file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)  # Sleep briefly
                continue
            parse_line(line)
            if (time.time() - refresh_ts) > config['refresh_time']:
                if not config['background']:
                    PrintStats.print_stats(config, banned_ips, ip_stats, times_by_url_stats, ua_stats)
                iptables_unban_expired()
                clear_lists()
                refresh_ts = time.time()


def ignore_ip(ip: str, ua: str) -> bool:
    if ip in ip_ignored:
        return True
    # ignore known bots
    if 'http://www.bing.com/bingbot.htm' in ua:
        logging.debug(f"Ignoring bingbot from: {ip}")
        ip_ignored.append(ip)
        return True
    if 'http://www.google.com/bot.html' in ua:
        logging.debug(f"Ignoring googlebot from: {ip}")
        ip_ignored.append(ip)
        return True
    if 'http://www.google.com/adsbot.html' in ua:
        logging.debug(f"Ignoring google ads bot from: {ip}")
        ip_ignored.append(ip)
        return True
    if 'http://www.facebook.com/externalhit_uatext.php' in ua:
        logging.debug(f"Ignoring facebook bot from: {ip}")
        ip_ignored.append(ip)
        return True
    if 'http://mj12bot.com/' in ua:
        logging.debug(f"Ignoring majestic bot from: {ip}")
        ip_ignored.append(ip)
        return True
    if 'https://babbar.tech/crawler' in ua:
        logging.debug(f"Ignoring babbar bot from: {ip}")
        ip_ignored.append(ip)
        return True
    if 'Monit/5.33.0' in ua:
        logging.debug(f"Ignoring monit from: {ip}")
        ip_ignored.append(ip)
        return True
    if 'https://developers.facebook.com/docs/sharing/webmasters/crawler' in ua:
        logging.debug(f"Ignoring facebook bot from: {ip}")
        ip_ignored.append(ip)
        return True
    if 'https://ad.min.solutions' in ua:
        logging.debug(f"Ignoring ad.min bot from: {ip}")
        ip_ignored.append(ip)
        return True

    return False

def parse_line(line: str) -> None:
    global ip_stats, url_by_ip

    log_line = Nginx.parse_log_line(line, config['columns'])
    if not log_line:
        return
    config['lines_parsed'] += 1
    req_ts = log_line.req_ts
    http_status = log_line.http_status
    req = log_line.req
    ua = log_line.ua
    referer = log_line.referer

    if ignore_ip(log_line.ip, ua):
        return
    if not req in times_by_url:
        times_by_url[req] = ExpiringList(expiration_time=config['time_frame'])
    times_by_url[req].append(req_ts, {"upstream_response_time": float(log_line.upstream_response_time), "log_line": line})
    if not log_line.ip in status_by_ip:
        status_by_ip[log_line.ip] = ExpiringList(expiration_time=config['time_frame'])
    status_by_ip[log_line.ip].append(req_ts, {"http_status": float(http_status), "log_line": line, "req": req})
    if not ua in times_by_ua:
        times_by_ua[ua] = ExpiringList(expiration_time=config['time_frame'])
    times_by_ua[ua].append(req_ts, {"upstream_response_time": float(log_line.upstream_response_time), "log_line": line})
    if config['referer_stats']:
        if not log_line.ip in referer_data and config['referer_stats']:
            referer_data[log_line.ip] = ExpiringList(expiration_time=config['time_frame'])
        if '://' in referer:
            referer = referer.split('://')[1].split('?')[0]
        referer_entry =  {"http_request": req, "http_referer": referer, "log_line": line}
        referer_data[log_line.ip].append(req_ts, referer_entry)
        #print(f"referer {referer_entry['http_referer']} for request {referer_entry['http_request']}")
    data = url_by_ip.get(log_line.ip, [])
    data.append(req)
    url_by_ip.create(ts = req_ts, key = log_line.ip, value=data)

    if log_line.ip in ip_stats.keys():
        ip_data = ip_stats.get(log_line.ip)
    else:
        ip_data = IpData({
            'score': 0.0,
            'request_count': 0,
            'total_time': 0.0,
            'http_status_good': 0,
            'http_status_bad': 0,
            'attacks': 0,
            'min_ts': req_ts,
            'max_ts': req_ts,
            'lines': [],
        })
    ip_data.request_count += 1
    ip_data.total_time += float(log_line.upstream_response_time)
    ip_data.max_ts = req_ts
    ip_data.lines.append(line)

    if ip_data.avail_time >= 10:
        steal_ratio = ip_data.total_time / ip_data.avail_time
        steal_time = ip_data.avail_time - ip_data.total_time
        if steal_time < -30 and ip_data.total_time > 5:
            logging.debug(f"IP {log_line.ip} is stealing time: {steal_time:.2f}s over {ip_data.total_time:.2f}s with {ip_data.request_count} requests ratio: {steal_ratio:.6f}")

    if config['url_stats']:
        values = times_by_url[req].get_values_by_key('upstream_response_time')
        times_by_url_stats[req] = {}
        times_by_url_stats[req]['avg_time'] = sum(values) / len(values)
        times_by_url_stats[req]['request_count'] = len(values)
        times_by_url_stats[req]['total_time'] = sum(values)

    good_statuses: list[int] = [200, 206, 499]
    ignore_statuses: list[int] = [302, 303, 304, 307, 308]
    # wonder about 301, all wp related return 301
    if log_line in ignore_statuses:
        pass
    elif log_line.http_status in good_statuses:
        ip_data.http_status_good += 1
    else:
        ip_data.http_status_bad += 1

    if ip_data.request_count >= 10:
        ip_data.score += (ip_data.http_status_bad_perc / 100)
    if ip_data.request_count > 10 and ip_data.http_status_bad_perc > 75.0 and not log_line.ip in banned_ips:
        iptables_ban(log_line.ip)
        logging.info(f"Banned IP {log_line.ip} - High percentage of bad HTTP statuses: {ip_data.http_status_bad_perc:.2f}% ({ip_data.http_status_bad} bad out of {ip_data.request_count} total)")
        for line in ip_data.lines:
            logging.debug(f"{line}".strip())

    if config['ua_stats']:
        values = times_by_ua[ua].get_values_by_key('upstream_response_time')
        ua_stats[ua] = {
            'total_time': sum(values),
            'count': len(values),
            'avg_time': sum(values) / len(values),
        }

    if config['referer_stats']:
        ip_data.referer = {
            'no_referer': 0,
            'related': 0,
            'unrelated': 0
        }
        status = 'unrelated'
        for data in referer_data[log_line.ip].get_values():
            referer1 = data['http_referer']
            if referer1 == '-':
                status = 'no_referer'
            else:
                for data in referer_data[log_line.ip].get_values():
                    request2 = data['http_request']
                    if request2 in referer1:
                        status = 'related'
                        break
            ip_data.referer[status] += 1
    if ip_data.request_count < 10:
        pass
    else:
        ip_data.score += 0.34 * ip_data.referer['unrelated'] / ip_data.request_count
        ip_data.score += 0.66 * ip_data.referer['no_referer'] / ip_data.request_count

#    for url in url_by_ip.get(ip, []):
#        if KnownAttacks.is_known(url):
#            ip_data['attacks'] += 1
#    if ip_data['attacks'] >= 3:
#        score_add = 10 * ip_data['attacks'] / ip_data['request_count']
#        logging.info(f"IP {ip} has {ip_data['attacks']} known attacks in {ip_data['request_count']} requests, score: #{ip_data['score']:.2f}+{score_add:.2f}")
#        ip_data['score'] += score_add

#        for line in requests_by_ip[ip].get_values_by_key('log_line'):
#            logging.debug(f"{line}".strip())

    # combined rules
    # xmlrpc.php for a site that does not use it is always bad
    if 'xmlrpc.php' in req and int(http_status) >= 300 and int(http_status) != 403:
        iptables_ban(log_line.ip)
        logging.info(f"Banned IP {log_line.ip} - xmlrpc.php access with status {http_status}")
        for line in ip_data.lines:
            logging.debug(f"{line}".strip())
    # wp-login for site that does not use it is always bad
    if 'wp-login.php' in req and int(http_status) == 404:
        iptables_ban(log_line.ip)
        logging.info(f"Banned IP {log_line.ip} - wp-login.php access with status {http_status}")
        for line in ip_data.lines:
            logging.debug(f"{line}".strip())
    # 3 times for wp-login is quite enough (times 2, one for get, one for post)
    # status_by_ip[log_line.ip].append(req_ts, {"http_status": float(http_status), "log_line": line, "req": req})
    counter = 0
    if not log_line.ip in banned_ips and 'wp-login.php' in req:
        for value in status_by_ip[log_line.ip].get_values():
            if not 'wp-login.php' in value['req']:
                continue
            counter += 1
        if counter >= 6 and not log_line.ip in banned_ips:
            iptables_ban(log_line.ip)
            logging.info(f"Banned IP {log_line.ip} - Multiple wp-login.php access attempts")
            for line in ip_data.lines:
                logging.debug(f"{line}".strip())
    # that's just lazy
    if 'python-requests' in ua or 'python-urllib' in ua:
        iptables_ban(log_line.ip)
        logging.info(f"Banned IP {log_line.ip} - python requests detected in User-Agent")
        for line in ip_data.lines:
            logging.debug(f"{line}".strip())

    # store data
    if log_line.ip in banned_ips:
        ip_data.score += 100.0
    ip_stats.create(ts=req_ts, key=log_line.ip, value=ip_data)


def clear_lists():
    for url in list(times_by_url.keys()):
        times_by_url[url].expire()
        if times_by_url[url].len() == 0:
            del times_by_url[url]
            if url in times_by_url_stats:
                del times_by_url_stats[url]
    for ip in list(status_by_ip.keys()):
        status_by_ip[ip].expire()
        if status_by_ip[ip].len() == 0:
            del status_by_ip[ip]
    for ua in list(times_by_ua.keys()):
        times_by_ua[ua].expire()
        if times_by_ua[ua].len() == 0:
            del times_by_ua[ua]
            if ua in ua_stats:
                del ua_stats[ua]


@click.command()
@click.option('--time-frame', default=300, help='Time frame in seconds to analyze logs (default: 300)')
@click.option('--ban-time', default=600, help='Ban time in seconds for IP addresses (default: 600)')
@click.option('--background', is_flag=True, help='Run in background (daemon mode)')
@click.option('--skip-url-stats', is_flag=True, help="Don't show URL stats")
@click.option('--skip-ua-stats', is_flag=True, help='Don\'t show User-Agent stats')
@click.option('--skip-referer', is_flag=True, help='Don\t show Referer stats')
@click.option('--refresh-time', default=1, help='Screen refresh time in seconds (default: 1)')
def main(
    time_frame: int,
    ban_time: int,
    background: bool,
    skip_url_stats: bool,
    skip_ua_stats: bool,
    skip_referer: bool,
    refresh_time: int
):
    global log_file_path
    config['time_frame'] = time_frame
    config['ban_time'] = ban_time
    config['background'] = background
    config['url_stats'] = not skip_url_stats
    config['ua_stats'] = not skip_ua_stats
    config['referer_stats'] = not skip_referer
    config['refresh_time'] = refresh_time
    init()
    if config['background']:
        print("Running in background mode")
        pid = os.fork()
        if pid > 0:
            # Exit parent process
            sys.exit(0)
    tail_f(log_file_path)


if __name__ == '__main__':
    main()
