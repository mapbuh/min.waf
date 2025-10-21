#!/usr/bin/env python3

import atexit
import click
import datetime
import logging
import numpy as np
import os
import re
import shlex
import subprocess
import sys
import time

from ExpiringList import ExpiringList
from PrintStats import PrintStats

requests_by_ip: dict[str, ExpiringList] = {}
ip_stats: dict[str, dict] = {}
ip_worst: dict = {'ip': '', 'ratio': 0.0001}
ip_ignored: list[str] = []
times_by_url: dict[str, ExpiringList] = {}
status_by_ip: dict[str, ExpiringList] = {}
times_by_ua: dict[str, ExpiringList] = {}
banned_ips: dict[str, float] = {}

config: dict = {
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

times_by_url_stats: dict[str, dict] = {}
status_by_ip_stats: dict[str, dict] = {}
ua_stats: dict[str, dict] = {}
referer_data: dict[str, ExpiringList] = {}
referer_stats: dict[str, dict] = {}


def init() -> None:
    global log_file_path
    nginx_config: str = subprocess.run(['nginx', '-T'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode('utf-8')
    output = re.search(r'access_log\s+([^\s]+)\s+([^\s]+)\s*;', nginx_config, flags=re.IGNORECASE)
    if output is None:
        print("Could not find access_log directive in nginx config")
        sys.exit(1)
    log_file_format = 'combined'
    if output is not None:
        log_file_path = output.group(1)
        log_file_format = output.group(2)
    output = re.search(f'log_format\\s+{log_file_format}([^;]+);', nginx_config, flags=re.IGNORECASE | re.DOTALL)
    if output is None:
        print(f"Could not find log_format {log_file_format} in nginx config")
        sys.exit(1)
    log_format = ''
    for line in output.group(1).splitlines():
        line = line.strip()
        if line[0] == '\'' and line.endswith('\''):
            line = line[1:-1]
        log_format += line + ' '
    log_format = re.sub(r'\s+', ' ', log_format).strip()
    columns = shlex.split(log_format)
    offset = 0
    for i, col in enumerate(columns):
        if re.search(r'^\$remote_addr$', col):
            config['columns']['remote_addr'] = i + offset
        elif re.search(r'^\$host$', col):
            config['columns']['host'] = i + offset
        elif re.search(r'\$time_local', col):
            config['columns']['time_local'] = i + offset
            offset += 1  # time_local is two columns in the log
        elif re.search(r'^\$request$', col):
            config['columns']['request'] = i + offset
        elif re.search(r'^\$status$', col):
            config['columns']['status'] = i + offset
        elif re.search(r'^\$upstream_response_time$', col):
            config['columns']['upstream_response_time'] = i + offset
        elif re.search(r'^\$http_user_agent$', col):
            config['columns']['http_user_agent'] = i + offset
        elif re.search(r'^\$http_referer$', col):
            config['columns']['http_referer'] = i + offset
    for config_line in config['columns']:
        if config['columns'][config_line] == -1:
            print(f"Could not find column for {config_line} in log_format")
            sys.exit(1)
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
    subprocess.run(['iptables', '-D', 'INPUT', '-j', 'MINWAF'])
    subprocess.run(['iptables', '-F', 'MINWAF'])
    subprocess.run(['iptables', '-X', 'MINWAF'])
    # IPv6
    subprocess.run(['ip6tables', '-D', 'INPUT', '-j', 'MINWAF'])
    subprocess.run(['ip6tables', '-F', 'MINWAF'])
    subprocess.run(['ip6tables', '-X', 'MINWAF'])


def iptables_init():
    iptables_clear()
    # IPv4
    subprocess.run(['iptables', '-N', 'MINWAF'])
    subprocess.run(['iptables', '-I', 'INPUT', '-j', 'MINWAF'])
    # IPv6
    subprocess.run(['ip6tables', '-N', 'MINWAF'])
    subprocess.run(['ip6tables', '-I', 'INPUT', '-j', 'MINWAF'])

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


def parse_url(domain, request):
    # request is like: "GET /path/to/resource HTTP/1.1"
    try:
        path = request.split(' ')[1].split('?')[0]
    except IndexError:
        # "20.65.193.163" _ [18/Oct/2025:04:23:16 +0300] "MGLNDD_144.76.163.188_443" 400 157 0 309 "-" "-" 0.122 "-" "US" "-" 1541953 1 2025-10-18T04:23:16+03:00
        path = request
    return domain + path


def tail_f(filename):
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
                    PrintStats.print_stats(config, banned_ips, ip_stats, status_by_ip_stats, referer_stats, times_by_url_stats, ua_stats)
                iptables_unban_expired()
                clear_lists()
                refresh_ts = time.time()


def ignore_ip(ip, ua) -> bool:
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

    return False

def parse_line(line):
    try:
        columns = shlex.split(line)
    except ValueError:
        # cannot parse line
        return
    config['lines_parsed'] += 1
    ip = columns[config['columns']['remote_addr']]
    upstream_response_time = columns[config['columns']['upstream_response_time']]
    req_ts = columns[config['columns']['time_local']] + ' ' + columns[config['columns']['time_local'] + 1]
    req_ts = datetime.datetime.strptime(req_ts, "[%d/%b/%Y:%H:%M:%S %z]").timestamp()
    http_status = columns[config['columns']['status']]
    req = parse_url(columns[config['columns']['host']], columns[config['columns']['request']])
    ua = columns[config['columns']['http_user_agent']]
    referer = columns[config['columns']['http_referer']]
    if upstream_response_time == '-':
        upstream_response_time = 0.1

    if ignore_ip(ip, ua):
        return
    if not ip in requests_by_ip:
        requests_by_ip[ip] = ExpiringList(expiration_time=config['time_frame'])
    requests_by_ip[ip].append(req_ts, {"upstream_response_time": float(upstream_response_time), "log_line": line})
    if not req in times_by_url:
        times_by_url[req] = ExpiringList(expiration_time=config['time_frame'])
    times_by_url[req].append(req_ts, {"upstream_response_time": float(upstream_response_time), "log_line": line})
    if not ip in status_by_ip:
        status_by_ip[ip] = ExpiringList(expiration_time=config['time_frame'])
    status_by_ip[ip].append(req_ts, {"http_status": float(http_status), "log_line": line})
    if not ua in times_by_ua:
        times_by_ua[ua] = ExpiringList(expiration_time=config['time_frame'])
    times_by_ua[ua].append(req_ts, {"upstream_response_time": float(upstream_response_time), "log_line": line})
    if config['referer_stats']:
        if not ip in referer_data and config['referer_stats']:
            referer_data[ip] = ExpiringList(expiration_time=config['time_frame'])
        if '://' in referer:
            referer = referer.split('://')[1].split('?')[0]
        referer_entry =  {"http_request": req, "http_referer": referer, "log_line": line}
        referer_data[ip].append(req_ts, referer_entry)
        #print(f"referer {referer_entry['http_referer']} for request {referer_entry['http_request']}")

    requests = requests_by_ip[ip].get_values()
    ip_stats[ip] = {'total_time': 0.0, 'request_count': 0, 'avail_time': 0.0, 'ratio': 0.0, 'steal': 0.0}
    for request in requests:
        ip_stats[ip]['request_count'] += 1
        ip_stats[ip]['total_time'] += float(request['upstream_response_time'])
        ip_stats[ip]['avail_time'] = requests_by_ip[ip].max_ts() - requests_by_ip[ip].min_ts()
        if ip_stats[ip]['avail_time'] == 0:
            ip_stats[ip]['ratio'] = 0
            ip_stats[ip]['steal'] = 0
        else:
            ip_stats[ip]['ratio'] = ip_stats[ip]['total_time'] / ip_stats[ip]['avail_time']
            ip_stats[ip]['steal'] = ip_stats[ip]['avail_time'] - ip_stats[ip]['total_time']
    if ip_stats[ip]['steal'] < -30 and ip_stats[ip]['total_time'] > 5:
        logging.debug(f"IP {ip} is stealing time: {ip_stats[ip]['steal']:.2f}s over {ip_stats[ip]['total_time']:.2f}s with {ip_stats[ip]['request_count']} requests ratio: {ip_stats[ip]['ratio']:.6f}")
        if ip_stats[ip]['ratio'] > ip_worst['ratio']:
            ip_worst['ratio'] = ip_stats[ip]['ratio']
            ip_worst['ip'] = ip
            logging.debug(f"worst_ip : {ip_worst['ip']} with ratio {ip_worst['ratio']:.6f} from ({ip_stats[ip]['request_count']})r")

    if config['url_stats']:
        values = times_by_url[req].get_values_by_key('upstream_response_time')
        times_by_url_stats[req] = {}
        times_by_url_stats[req]['avg_time'] = sum(values) / len(values)
        times_by_url_stats[req]['request_count'] = len(values)
        times_by_url_stats[req]['total_time'] = sum(values)

    good_statuses: list[int] = [200, 206, 499]
    ignore_statuses: list[int] = [302, 303, 304, 307, 308]
    # wonder about 301, all wp related return 301
    values = status_by_ip[ip].get_values_by_key('http_status')
    status_by_ip_stats[ip] = {"count": 0, "good": 0, "bad": 0, "bad_perc": 0.0, "good_perc": 0.0}
    for status in values:
        if int(status) in ignore_statuses:
            continue
        if not status in status_by_ip_stats[ip]:
            status_by_ip_stats[ip][status] = 0
        status_by_ip_stats[ip][status] = status_by_ip_stats[ip][status] + 1
        status_by_ip_stats[ip]["count"] += 1
        if status in good_statuses:
            status_by_ip_stats[ip]["good"] += 1
        else:
            status_by_ip_stats[ip]["bad"] += 1
        status_by_ip_stats[ip]["good_perc"] = (status_by_ip_stats[ip]["good"] / status_by_ip_stats[ip]["count"]) * 100
        status_by_ip_stats[ip]["bad_perc"] = (status_by_ip_stats[ip]["bad"] / status_by_ip_stats[ip]["count"]) * 100
        if status_by_ip_stats[ip]['count'] > 10 and status_by_ip_stats[ip]['bad_perc'] > 75.0 and not ip in banned_ips:
            iptables_ban(ip)
            logging.info(f"Banned IP {ip} - High percentage of bad HTTP statuses: {status_by_ip_stats[ip]['bad_perc']:.2f}% ({status_by_ip_stats[ip]['bad']} bad out of {status_by_ip_stats[ip]['count']} total)")
            for line in requests_by_ip[ip].get_values_by_key('log_line'):
                logging.debug(f"{line}".strip())

    if config['ua_stats']:
        values = times_by_ua[ua].get_values_by_key('upstream_response_time')
        ua_stats[ua] = {
            'total_time': sum(values),
            'count': len(values),
            'avg_time': sum(values) / len(values),
        }

    if config['referer_stats']:
        referer_stats[ip] = {
            'count': 0,
            'no_referer': 0,
            'related': 0,
            'unrelated': 0
        }
        status = 'unrelated'
        for data in referer_data[ip].get_values():
            referer1 = data['http_referer']
            if referer1 == '-':
                status = 'no_referer'
            else:
                for data in referer_data[ip].get_values():
                    request2 = data['http_request']
                    if request2 in referer1:
                        status = 'related'
                        break
            referer_stats[ip][status] += 1
            referer_stats[ip]['count'] += 1


def clear_lists():
    current_time = time.time()
    for ip in list(requests_by_ip.keys()):
        requests_by_ip[ip].expire()
        if requests_by_ip[ip].len() == 0:
            del requests_by_ip[ip]
            if ip in ip_stats:
                del ip_stats[ip]
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
            if ip in status_by_ip_stats:
                del status_by_ip_stats[ip]
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
def main(time_frame, ban_time, background, skip_url_stats, skip_ua_stats, skip_referer, refresh_time):
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
