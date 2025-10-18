#!/usr/bin/python3

import click
import datetime
import numpy as np
import shlex
import subprocess
import sys
import time
import re

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

requests_by_ip: dict[str, dict] = {}
times_by_url: dict[str, ExpiringList] = {}
status_by_ip: dict[str, ExpiringList] = {}

config = {
    'columns': {
        'remote_addr': -1,
        'host': -1,
        'time_local': -1,
        'request': -1,
        'status': -1,
        'upstream_response_time': -1,
        'connection': -1,
        'connection_requests': -1,
    }
}


time_frame: int = 300  # seconds
lines_to_print: int = 10
column_1_width: int = 30
column_2_width: int = 15
column_3_width: int = 17
refresh_time: int = 1

start_time = time.time()
refresh_ts = 0
log_file_path = "/var/log/nginx/access.log"


@click.command()
def tail():
    for line in sys.stdin:
        parse_print(line)


def init():
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
        elif re.search(r'^\$connection$', col):
            config['columns']['connection'] = i + offset
        elif re.search(r'^\$connection_requests$', col):
            config['columns']['connection_requests'] = i + offset
    for config_line in config['columns']:
        if config['columns'][config_line] == -1:
            print(f"Could not find column for {config_line} in log_format")
            sys.exit(1)


def print_stats():
    current_time = time.time()
    print("\033c", end="")  # Clear screen
    print(f"Running time: {time.time() - start_time:.2f} seconds      Time frame: {time_frame} seconds")
    print(f"{'IP Address':<{column_1_width}} {'Upstream Time':<{column_2_width}} {'Requests':<{column_3_width}}")
    print("=" * 100)
    ip_stats = {}
    for ip in list(requests_by_ip.keys()):
        data = requests_by_ip[ip]
        for connection in list(data.keys()):
            cdata = data[connection]
            upstream_time = 0.0
            for ind in list(sorted(cdata.keys())):
                ts = cdata[ind]['ts']
                if current_time - ts > time_frame:
                    del cdata[ind]
                    continue
                if ip not in ip_stats:
                    ip_stats[ip] = {'total_time': 0.0, 'request_count': 0, 'first_ts': ts}
                # suspected bug in nginx, time seem cumulative per connection but sometimes resets
                if cdata[ind]['ts'] < upstream_time:
                    ip_stats[ip]['total_time'] += upstream_time
                upstream_time = cdata[ind]['upstream_response_time']
                ip_stats[ip]['request_count'] += 1
            # only take the last request time for this connection
            if ip in ip_stats:
                ip_stats[ip]['total_time'] += upstream_time

    # sort by total_time
    counter = 0
    for ip, stats in sorted(ip_stats.items(), key=lambda item: item[1]['total_time'], reverse=True):
#    for ip, stats in ip_stats.items():
        if stats['request_count'] < 2:
            continue
        #if stats['total_time'] < 1:
        #    continue
        counter += 1
        if counter > lines_to_print:
            break
        print(f"{ip:<{column_1_width}.{column_1_width}} {stats['total_time']:<{column_2_width}.3f} {stats['request_count']:5d}rq in {(current_time - stats['first_ts']):3.0f}s {100 * stats['total_time'] / (current_time - stats['first_ts']):.2f}% ")

    print()
    times_by_url_stats = {}
    for url, times in times_by_url.items():
        values = times.get_values()
        if len(values) == 0:
            continue
        if url not in times_by_url_stats:
            times_by_url_stats[url] = {}
        times_by_url_stats[url]['avg_time'] = sum(values) / len(values)
        times_by_url_stats[url]['request_count'] = len(values)
        times_by_url_stats[url]['total_time'] = sum(values)
        times_by_url_stats[url]['p95_time'] = np.percentile(values, 95)
    counter = 0
    for url, stats in sorted(times_by_url_stats.items(), key=lambda item: item[1]['total_time'], reverse=True):
        #if stats['total_time'] < 1:
        #    continue
        counter += 1
        if counter > lines_to_print:
            break
        print(f"{url:<100.100} Total: {stats['total_time']:>6.2f}, Avg: {stats['avg_time']:>6.2f}s 95p: {stats['p95_time']:>6.2f} {stats['request_count']:>6}rq")

    print()
    status_by_ip_stats = {}
    good_statuses: list[int] = [200, 499]
    for ip, data in status_by_ip.items():
        statuses: list[float] = data.get_values()
        if ip not in status_by_ip_stats:
            status_by_ip_stats[ip] = {"count": 0, "good": 0, "bad": 0, "bad_perc": 0.0, "good_perc": 0.0}
        for status in statuses:
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
    counter = 0
    for ip, data in sorted(status_by_ip_stats.items(), key=lambda item: item[1]['bad_perc'], reverse=True):
        #for ip, data in status_by_ip_stats[ip].items():
        counter += 1
        if counter > lines_to_print:
            break
        if data['count'] < 10:
            continue
        print(f"{ip:<20.20}: All: {data['count']:>10}, Good: {data['good_perc']:>8.2f}%, Bad: {data['bad_perc']:>8.2f}%")




def parse_url(domain, request):
    # request is like: "GET /path/to/resource HTTP/1.1"
    try:
        path = request.split(' ')[1].split('?')[0]
    except IndexError:
        # "20.65.193.163" _ [18/Oct/2025:04:23:16 +0300] "MGLNDD_144.76.163.188_443" 400 157 0 309 "-" "-" 0.122 "-" "US" "-" 1541953 1 2025-10-18T04:23:16+03:00
        path = request
    return domain + path


def parse_print(line):
    global refresh_ts
    columns = shlex.split(line)
    ip = columns[column_ip]
    upstream_response_time = columns[column_upstream_response_time]
    connection = columns[column_connection]
    connection_index = columns[column_connection_index]
    req_ts = columns[column_time] + ' ' + columns[column_time + 1]
    http_status = columns[column_status]
    req = parse_url(columns[column_domain], columns[column_request])
    if upstream_response_time == '-':
        upstream_response_time = 0.1
    if not ip in requests_by_ip:
        requests_by_ip[ip] = {}
    if not connection in requests_by_ip[ip]:
        requests_by_ip[ip][connection] = {}
    requests_by_ip[ip][connection][int(connection_index)] = {
        'upstream_response_time': float(upstream_response_time),
        'ts': datetime.datetime.strptime(req_ts, "[%d/%b/%Y:%H:%M:%S %z]").timestamp()
    }
    if not req in times_by_url:
        times_by_url[req] = ExpiringList(expiration_time=time_frame)
    times_by_url[req].append(float(upstream_response_time))
    if not ip in status_by_ip:
        status_by_ip[ip] = ExpiringList(expiration_time=time_frame)
    status_by_ip[ip].append(float(http_status))


if __name__ == '__main__':
    init()
    tail_f(log_file_path)
