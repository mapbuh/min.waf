#!/usr/bin/python3

import click
import datetime
import numpy as np
import os
import re
import shlex
import subprocess
import sys
import time

class ExpiringList:
    def __init__(self, expiration_time: int):
        self.expiration_time = expiration_time
        self.data: list[tuple[float, float]] = []

    def append(self, value: float):
        current_time = time.time()
        self.data.append((current_time, value))
        self.expire(current_time)

    def expire(self, current_time: float):
        self.data = [(ts, val) for ts, val in self.data if current_time - ts <= self.expiration_time]

    def get_values(self) -> list[float]:
        current_time = time.time()
        self.expire(current_time)
        return [val for ts, val in self.data]

    def len(self) -> int:
        current_time = time.time()
        self.expire(current_time)
        return len(self.data)

requests_by_ip: dict[str, ExpiringList] = {}
times_by_url: dict[str, ExpiringList] = {}
status_by_ip: dict[str, ExpiringList] = {}
ban_reasons: list[str] = []

config = {
    'columns': {
        'remote_addr': -1,
        'host': -1,
        'time_local': -1,
        'request': -1,
        'status': -1,
        'upstream_response_time': -1,
    },
    'time_frame': 300,
    'ban_time': 600,
    'background': False,
    'url_stats': False,
}


lines_to_print: int = 10
column_1_width: int = 45
column_2_width: int = 15
column_3_width: int = 17
refresh_time: int = 1

start_time = time.time()
log_file_path = None

ip_stats: dict[str, dict] = {}
times_by_url_stats: dict[str, dict] = {}
status_by_ip_stats: dict[str, dict] = {}
lines_parsed: int = 0



def init():
    global log_file_path
    nginx_config = subprocess.run(['nginx', '-T'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode('utf-8')
    output = re.search('access_log\s+([^\s]+)\s+([^\s]+)\s*;', nginx_config, flags=re.IGNORECASE)
    if output is None:
        print("Could not find access_log directive in nginx config")
        sys.exit(1)
    if output is not None:
        log_file_path = output.group(1)
        log_file_format = output.group(2)
    output = re.search(f'log_format\s+{log_file_format}([^;]+);', nginx_config, flags=re.IGNORECASE | re.DOTALL)
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
    for config_line in config['columns']:
        if config['columns'][config_line] == -1:
            print(f"Could not find column for {config_line} in log_format")
            sys.exit(1)
    iptables_init()


def iptables_init():
    subprocess.run(['iptables', '-D', 'INPUT', '-j', 'MINWAF'])
    subprocess.run(['iptables', '-F', 'MINWAF'])
    subprocess.run(['iptables', '-X', 'MINWAF'])
    subprocess.run(['iptables', '-N', 'MINWAF'])
    subprocess.run(['iptables', '-I', 'INPUT', '-j', 'MINWAF'])

    subprocess.run(['ip6tables', '-D', 'INPUT', '-j', 'MINWAF'])
    subprocess.run(['ip6tables', '-F', 'MINWAF'])
    subprocess.run(['ip6tables', '-X', 'MINWAF'])
    subprocess.run(['ip6tables', '-N', 'MINWAF'])
    subprocess.run(['ip6tables', '-I', 'INPUT', '-j', 'MINWAF'])

banned_ips = {}
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
        if counter > lines_to_print:
            break
        message = f"{ip:<{column_1_width}.{column_1_width}} {stats['total_time']:<{column_2_width}.3f} {stats['request_count']:5d}rq"
        if ip in banned_ips:
            print_red(message)
        elif stats['total_time'] > 1:
            print_yellow(message)
        else:
            print(message)

    print()
    counter = 0
    for ip, data in sorted(status_by_ip_stats.items(), key=lambda item: (item[1]['bad_perc'], item[1]['count']), reverse=True):
        #for ip, data in status_by_ip_stats[ip].items():
        if counter > lines_to_print:
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
            if counter > lines_to_print * 2:
                break
            message = f"{url:<100.100} Total: {stats['total_time']:>6.2f}, Avg: {stats['avg_time']:>6.2f}s 95p: {stats['p95_time']:>6.2f} {stats['request_count']:>6}rq"
            if stats['total_time'] > 1:
                print_yellow(message)
            else:
                print(message)

    print()
    for ip in banned_ips:
        print(f"{ip} is banned for {config['ban_time'] - (current_time - banned_ips[ip]):.0f}s", end=', ')
    print()
    print()
    for line in ban_reasons:
        print(f"ban: {line.strip()}")


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
    global ban_reasons
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

    requests = requests_by_ip[ip].get_values()
    ip_stats[ip] = {'total_time': 0.0, 'request_count': 0}
    for upstream_time in requests:
        ip_stats[ip]['request_count'] += 1
        ip_stats[ip]['total_time'] += float(upstream_time)

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
        status_by_ip_stats[ip]["good_perc"] = (status_by_ip_stats[ip]["good"] / status_by_ip_stats[ip]["count"]) * 100
        status_by_ip_stats[ip]["bad_perc"] = (status_by_ip_stats[ip]["bad"] / status_by_ip_stats[ip]["count"]) * 100
        # 50% is not good, because sometimes there is redirect and then 404
        if status_by_ip_stats[ip]['count'] > 10 and status_by_ip_stats[ip]['bad_perc'] > 45.0 and not ip in banned_ips:
            iptables_ban(ip)
            ban_reasons.append(line)
            ban_reasons = ban_reasons[-lines_to_print:]


def clear_lists():
    current_time = time.time()
    for ip in list(requests_by_ip.keys()):
        requests_by_ip[ip].expire(current_time)
        if requests_by_ip[ip].len() == 0:
            del requests_by_ip[ip]
    for url in list(times_by_url.keys()):
        times_by_url[url].expire(current_time)
        if times_by_url[url].len() == 0:
            del times_by_url[url]
    for ip in list(status_by_ip.keys()):
        status_by_ip[ip].expire(current_time)
        if status_by_ip[ip].len() == 0:
            del status_by_ip[ip]

def print_red(message, end = '\n'):
    sys.stdout.write('\x1b[1;31m' + message + '\x1b[0m' + end)

def print_green(message, end = '\n'):
    sys.stdout.write('\x1b[1;32m' + message + '\x1b[0m' + end)

def print_yellow(message, end = '\n'):
    sys.stderr.write('\x1b[1;33m' + message + '\x1b[0m' + end)

@click.command()
@click.option('--time-frame', default=300, help='Time frame in seconds to analyze logs')
@click.option('--ban-time', default=600, help='Ban time in seconds for IP addresses')
@click.option('--background', is_flag=True, help='Run in background (daemon mode)')
@click.option('--url-stats', is_flag=True, help='Show URL stats')
def main(time_frame, ban_time, background, url_stats):
    global log_file_path
    config['time_frame'] = time_frame
    config['ban_time'] = ban_time
    config['background'] = background
    config['url_stats'] = url_stats
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
