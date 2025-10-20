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
from functools import lru_cache

from ExpiringList import ExpiringList

requests_by_ip: dict[str, ExpiringList] = {}
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
        'http_user_agent': -1,
    },
    'time_frame': 300,
    'ban_time': 600,
    'background': False,
    'url_stats': False,
    'ua_stats': False,
    'lockfile': '/var/run/min.waf.lock',
    'detail_lines': 10,
}


column_1_width: int = 45
column_2_width: int = 15
column_3_width: int = 17
refresh_time: int = 1

start_time: float = time.time()
log_file_path: str = ''

ip_stats: dict[str, dict] = {}
times_by_url_stats: dict[str, dict] = {}
status_by_ip_stats: dict[str, dict] = {}
ua_stats: dict[str, dict] = {}
lines_parsed: int = 0


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
    for config_line in config['columns']:
        if config['columns'][config_line] == -1:
            print(f"Could not find column for {config_line} in log_format")
            sys.exit(1)
    lockfile_init()
    atexit.register(lockfile_remove)
    iptables_init()
    atexit.register(iptables_clear)
    logging.basicConfig(filename="/var/log/min.waf.log", filemode='a', format='%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)


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
    

def print_stats():
    current_time = time.time()
    print("\033c", end="")  # Clear screen
    print(f"Running: {time.time() - start_time:.2f} seconds  |  Parsed: {lines_parsed} lines  |  Time frame: {config['time_frame']} seconds")
    print(f"{'IP Address':<{column_1_width}} {'Upstream Time':<{column_2_width}} {'Requests':<{column_3_width}}")
    print("=" * 100)

    # sort by total_time
    counter = 0
    for ip, stats in sorted(ip_stats.items(), key=lambda item: item[1]['total_time'], reverse=True):
#    for ip, stats in ip_stats.items():
        counter += 1
        if counter > config['detail_lines']:
            break
        message = f"{ip:<{column_1_width}.{column_1_width}} {stats['total_time']:>{column_2_width}.3f}/{stats['avail_time']:<15.3f} {stats['request_count']:5d}rq"
        if ip in banned_ips:
            print_red(message)
        elif stats['total_time'] > stats['avail_time'] * 0.5 and stats['request_count'] > 10:
            print_yellow(message)
        else:
            print(message)

    print()
    counter = 0
    for ip, data in sorted(status_by_ip_stats.items(), key=lambda item: (item[1]['bad_perc'], item[1]['count']), reverse=True):
        #for ip, data in status_by_ip_stats[ip].items():
        if counter > config['detail_lines']:
            break
        counter += 1
        message = f"{ip:<{column_1_width}.{column_1_width}}: All: {data['count']:>10}, Good: {data['good_perc']:>8.2f}%, Bad: {data['bad_perc']:>8.2f}%"
        if ip in banned_ips:
            print_red(message)
        elif data['bad_perc'] > 10.0:
            print_yellow(message)
        else:
            print(message)

    if config['url_stats']:
        print()
        counter = 0
        for url, stats in sorted(times_by_url_stats.items(), key=lambda item: item[1]['total_time'], reverse=True):
            #if stats['total_time'] < 1:
            #    continue
            counter += 1
            if counter > config['detail_lines']:
                break
            message = f"{url:<100.100} Total: {stats['total_time']:>6.2f}, Avg: {stats['avg_time']:>6.2f}s 95p: {stats['p95_time']:>6.2f} {stats['request_count']:>6}rq"
            if stats['total_time'] > 1:
                print_yellow(message)
            else:
                print(message)

    if config['ua_stats']:
        print()
        counter = 0
        for ua, stats in sorted(ua_stats.items(), key=lambda item: item[1]['total_time'], reverse=True):
            #if stats['total_time'] < 1:
            #    continue
            counter += 1
            if counter > config['detail_lines']:
                break
            message = f"{ua:<100.100} Total: {stats['total_time']:>6.2f}, Avg: {stats['avg_time']:>6.2f}s 95p: {stats['p95_time']:>6.2f} {stats['count']:>6}rq"
            if stats['total_time'] > 1:
                print_yellow(message)
            else:
                print(message)

    print()
    for ip in banned_ips:
        print(f"{ip} banned for {config['ban_time'] - (current_time - banned_ips[ip]):.0f}s", end=', ')
    print()


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
            if (time.time() - refresh_ts) > refresh_time:
                if not config['background']:
                    print_stats()
                iptables_unban_expired()
                clear_lists()
                refresh_ts = time.time()



def parse_line(line):
    global lines_parsed
    try:
        columns = shlex.split(line)
    except ValueError:
        # cannot parse line
        return
    lines_parsed += 1
    ip = columns[config['columns']['remote_addr']]
    upstream_response_time = columns[config['columns']['upstream_response_time']]
    req_ts = columns[config['columns']['time_local']] + ' ' + columns[config['columns']['time_local'] + 1]
    req_ts = datetime.datetime.strptime(req_ts, "[%d/%b/%Y:%H:%M:%S %z]").timestamp()
    http_status = columns[config['columns']['status']]
    req = parse_url(columns[config['columns']['host']], columns[config['columns']['request']])
    ua = columns[config['columns']['http_user_agent']]
    if upstream_response_time == '-':
        upstream_response_time = 0.1
    if not ip in requests_by_ip:
        requests_by_ip[ip] = ExpiringList(expiration_time=config['time_frame'])
    requests_by_ip[ip].append(upstream_response_time)
    if not req in times_by_url:
        times_by_url[req] = ExpiringList(expiration_time=config['time_frame'])
    times_by_url[req].append(float(upstream_response_time))
    if not ip in status_by_ip:
        status_by_ip[ip] = ExpiringList(expiration_time=config['time_frame'])
    status_by_ip[ip].append(float(http_status))
    if not ua in times_by_ua:
        times_by_ua[ua] = ExpiringList(expiration_time=config['time_frame'])
    times_by_ua[ua].append(float(upstream_response_time))

    requests = requests_by_ip[ip].get_values()
    ip_stats[ip] = {'total_time': 0.0, 'request_count': 0}
    for upstream_time in requests:
        ip_stats[ip]['request_count'] += 1
        ip_stats[ip]['total_time'] += float(upstream_time)
        ip_stats[ip]['avail_time'] = requests_by_ip[ip].max_ts() - requests_by_ip[ip].min_ts()

    if config['url_stats']:
        values = times_by_url[req].get_values()
        times_by_url_stats[req] = {}
        times_by_url_stats[req]['avg_time'] = sum(values) / len(values)
        times_by_url_stats[req]['request_count'] = len(values)
        times_by_url_stats[req]['total_time'] = sum(values)
        times_by_url_stats[req]['p95_time'] = np.percentile(values, 95)

    good_statuses: list[int] = [200, 499]
    ignore_statuses: list[int] = [302, 303, 304, 307, 308]
    # wonder about 301, all wp related return 301
    values = status_by_ip[ip].get_values()
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
            status_by_ip_stats[ip]["bad_bayes"] = 1
        status_by_ip_stats[ip]["good_perc"] = (status_by_ip_stats[ip]["good"] / status_by_ip_stats[ip]["count"]) * 100
        status_by_ip_stats[ip]["bad_perc"] = (status_by_ip_stats[ip]["bad"] / status_by_ip_stats[ip]["count"]) * 100
#        if status_by_ip_stats[ip]['bad'] > 0 and bad_actor_http_status(status_by_ip_stats[ip]['bad']):
#            line = f"Ban IP {ip} - High percentage of bad HTTP statuses: {status_by_ip_stats[ip]['bad_perc']:.2f}% ({status_by_ip_stats[ip]['bad']} bad out of {status_by_ip_stats[ip]['count']} total)"
        if status_by_ip_stats[ip]['count'] > 10 and status_by_ip_stats[ip]['bad_perc'] > 50.0 and not ip in banned_ips:
            iptables_ban(ip)
            logging.info(f"Banned IP {ip} - High percentage of bad HTTP statuses: {status_by_ip_stats[ip]['bad_perc']:.2f}% ({status_by_ip_stats[ip]['bad']} bad out of {status_by_ip_stats[ip]['count']} total)")

    if config['ua_stats']:
        values = times_by_ua[ua].get_values()
        ua_stats[ua] = {
            'total_time': sum(values),
            'count': len(values),
            'avg_time': sum(values) / len(values),
            'p95_time': np.percentile(values, 95)
        }


def clear_lists():
    current_time = time.time()
    for ip in list(requests_by_ip.keys()):
        requests_by_ip[ip].expire(current_time)
        if requests_by_ip[ip].len() == 0:
            del requests_by_ip[ip]
            if ip in ip_stats:
                del ip_stats[ip]
    for url in list(times_by_url.keys()):
        times_by_url[url].expire(current_time)
        if times_by_url[url].len() == 0:
            del times_by_url[url]
            if url in times_by_url_stats:
                del times_by_url_stats[url]
    for ip in list(status_by_ip.keys()):
        status_by_ip[ip].expire(current_time)
        if status_by_ip[ip].len() == 0:
            del status_by_ip[ip]
            if ip in status_by_ip_stats:
                del status_by_ip_stats[ip]
    for ua in list(times_by_ua.keys()):
        times_by_ua[ua].expire(current_time)
        if times_by_ua[ua].len() == 0:
            del times_by_ua[ua]
            if ua in ua_stats:
                del ua_stats[ua]

def print_red(message, end = '\n'):
    sys.stdout.write('\x1b[1;31m' + message + '\x1b[0m' + end)

def print_green(message, end = '\n'):
    sys.stdout.write('\x1b[1;32m' + message + '\x1b[0m' + end)

def print_yellow(message, end = '\n'):
    sys.stderr.write('\x1b[1;33m' + message + '\x1b[0m' + end)

@lru_cache(maxsize=256)
def bad_actor_http_status(bad_statuses: int) -> float:
    p = {
        'good_actor': {
            'prior': 0.999,
            'bad_status': 0.1,
        },
        'bad_actor': {
            'prior': 0.001,
            'bad_status': 0.2
        },
    }
    p_good_actor = p['good_actor']['prior'] * pow(p['good_actor']['bad_status'], bad_statuses)
    p_bad_actor = p['bad_actor']['prior'] * pow(p['bad_actor']['bad_status'], bad_statuses)
    print(f"Bad statuses: {bad_statuses}, P(good_actor)={p_good_actor:.3f}, P(bad_actor)={p_bad_actor:.3f}")
    if p_good_actor > p_bad_actor:
        return False
    else:
        return True

def ftest_bayes():
    for bad_statuses in range(1, 11):
        result = bad_actor_http_status(bad_statuses)
        print(f"Bad statuses: {bad_statuses}, Bad actor: {result}")

@click.command()
@click.option('--time-frame', default=300, help='Time frame in seconds to analyze logs (default: 300)')
@click.option('--ban-time', default=600, help='Ban time in seconds for IP addresses (default: 600)')
@click.option('--background', is_flag=True, help='Run in background (daemon mode)')
@click.option('--skip-url-stats', is_flag=True, help='Show URL stats')
@click.option('--skip-ua-stats', is_flag=True, help='Show User-Agent stats')
@click.option('--test-bayes', is_flag=True, help='Test Bayesian filtering and exit')
def main(time_frame, ban_time, background, skip_url_stats, skip_ua_stats, test_bayes):
    if test_bayes:
        ftest_bayes()
        sys.exit(0)
    global log_file_path
    config['time_frame'] = time_frame
    config['ban_time'] = ban_time
    config['background'] = background
    config['url_stats'] = not skip_url_stats
    config['ua_stats'] = not skip_ua_stats
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
