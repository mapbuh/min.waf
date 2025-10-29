#!/usr/bin/env python3

from glob import glob
import click
from Nginx import Nginx
import gzip
from LogLine import LogLine

data: dict[str, dict[str, dict[str, int]]] = {}

def analyze(log_line: LogLine|None):
    global data
    if log_line is None:
        return
    if log_line.host not in data:
        data[log_line.host] = {}
    if str(log_line.http_status) not in data[log_line.host]:
        data[log_line.host][str(log_line.http_status)] = {}
    if log_line.path not in data[log_line.host][str(log_line.http_status)]:
        data[log_line.host][str(log_line.http_status)][log_line.path] = 0
    data[log_line.host][str(log_line.http_status)][log_line.path] += 1


def data_print():
    global data
    for host, statuses in data.items():
        for status, paths in statuses.items():
            counter = 0
            for path, count in sorted(paths.items(), key=lambda item: item[1], reverse=True):
                print(f"Host: {host} - HTTP Status: {status} - Path: {path} - Count: {count}")
                counter += 1
                if counter >= 10:
                    break
            print(10 * "-")
        print(10 * "=")


def data_write():
    """
    create CSV file with request, total unique IPs and unique domains
    404_analysis.csv
    """
    global data
    with open("http_status__by_host_analysis.csv", "w") as f:
        f.write("host,http_status,path,request_count\n")
        for host, statuses in data.items():
            for status, paths in statuses.items():
                for path, count in sorted(paths.items(), key=lambda item: item[1], reverse=True):
                    f.write(f"{host},{status},{path},{count}\n")

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
