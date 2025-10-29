#!/usr/bin/env python3

from glob import glob
import click
from Nginx import Nginx
import gzip
from LogLine import LogLine

data: dict[str, int] = {}


def analyze(log_line: LogLine | None):
    global data
    if log_line is None:
        return
    if log_line.ua not in data:
        data[log_line.ua] = 0
    data[log_line.ua] += 1


def data_print():
    global data
    for ua, count in sorted(data.items(), key=lambda item: item[1], reverse=True):
        print(f"User Agent: {ua} - Count: {count}")


def data_write():
    global data
    with open("ua_analysis.csv", "w") as f:
        f.write("user_agent,request_count\n")
        for ua, count in sorted(data.items(), key=lambda item: item[1], reverse=True):
            f.write(f"{ua},{count}\n")


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
