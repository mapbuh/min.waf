#!/usr/bin/env python3

from glob import glob
import click
from Nginx import Nginx
import gzip
from LogLine import LogLine

data: dict[str, dict[str, dict[str, int]]] = {}


def analyze(log_line: LogLine | None):
    global data
    if log_line is None or int(log_line.http_status) != 404:
        return
    if log_line.path not in data:
        data[log_line.path] = {}
    if log_line.host not in data[log_line.path]:
        data[log_line.path][log_line.host] = {}
    if log_line.ip not in data[log_line.path][log_line.host]:
        data[log_line.path][log_line.host][log_line.ip] = 0
    data[log_line.path][log_line.host][log_line.ip] += 1


def data_print():
    global data
    for req, hosts in data.items():
        total_ips = sum(len(ips) for ips in hosts.values())
        domains = len(hosts)
        if domains < 2:
            continue
        # if total_ips < 5:
        #    continue
        print(f"Request: {req} - Total unique IPs: {total_ips}")
        for host, ips in hosts.items():
            print(f"  Host: {host} - Unique IPs: {len(ips)}")
            for ip, count in ips.items():
                print(f"    IP: {ip} - Requests: {count}")


def data_write():
    """
    create CSV file with request, total unique IPs and unique domains
    404_analysis.csv
    """
    global data
    with open("404_analysis.csv", "w") as f:
        f.write("request,total_unique_ips,unique_domains\n")
        for req, hosts in data.items():
            total_ips = sum(len(ips) for ips in hosts.values())
            domains = len(hosts)
            if domains < 3:
                continue
            if total_ips < 3:
                continue
            if "." not in req:
                continue
            # exclude certain file types
            if req.endswith((".txt", ".jpg", ".png", ".css", ".js", ".ico")):
                continue
            f.write(f"{req},{total_ips},{domains}\n")


@click.command()
def main():
    nginx_config = Nginx.config_get()
    log_file_path = nginx_config["log_file_path"]
    config_columns = Nginx.parse_log_format(nginx_config["log_format"])
    for file in glob(log_file_path + "*"):
        print(f"Processing log file: {file}")
        if file.endswith(".gz"):
            with gzip.open(file, "rt") as f:
                for line in f:
                    analyze(Nginx.parse_log_line(line, config_columns))
        else:
            with open(file) as f:
                for line in f:
                    analyze(Nginx.parse_log_line(line, config_columns))
        data_print()
        data_write()


if __name__ == "__main__":
    main()
