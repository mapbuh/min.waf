#!/usr/bin/env python3

import atexit
from typing import Any
import click
import logging
import os
import subprocess
import sys
import time
import inotify.adapters  # type: ignore

from Bots import Bots
from ExpiringDict import ExpiringDict
from ExpiringList import ExpiringList
from Nginx import Nginx
from PrintStats import PrintStats
from IpData import IpData
from Checks import Checks

log_file_path: str = ""

ip_whitelist: dict[str, list[str]] = {}
banned_ips: dict[str, float] = {}
ip_stats: ExpiringDict[IpData]
url_stats: ExpiringDict[IpData]
ua_stats: ExpiringDict[IpData]

config: dict[str, Any] = {
    "columns": {
        "remote_addr": -1,
        "host": -1,
        "time_local": -1,
        "request": -1,
        "status": -1,
        "upstream_response_time": -1,
        "http_referer": -1,
        "http_user_agent": -1,
    },
    "time_frame": 300,
    "ban_time": 600,
    "background": False,
    "url_stats": False,
    "ua_stats": False,
    "referer_stats": False,
    "lockfile": "/var/run/min.waf.lock",
    "detail_lines": 12,
    "start_time": None,
    "lines_parsed": 0,
    "bans": 0,
    'whitelist_triggers': {
        'www.gift-tube.com': [
            {
                'path': '/adming/dashboards/main',
                'http_status': 200,
            },
        ],
    },
}


def init() -> None:
    global log_file_path, ip_stats, url_stats, ua_stats
    nginx_config = Nginx.config_get()
    log_file_path = nginx_config["log_file_path"]
    log_format = nginx_config["log_format"]
    config["columns"] = Nginx.parse_log_format(log_format)
    for config_line in config["columns"]:
        if config["columns"][config_line] == -1:
            print(f"Could not find column for {config_line} in log_format")
            sys.exit(1)

    ip_stats = ExpiringDict[IpData](config["time_frame"])
    url_stats = ExpiringDict(config["time_frame"])
    ua_stats = ExpiringDict(config["time_frame"])
    lockfile_init()
    atexit.register(lockfile_remove)
    iptables_init()
    atexit.register(iptables_clear)
    logging.basicConfig(
        filename="/var/log/min.waf.log",
        filemode="a",
        format="%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.DEBUG,
    )
    logging.getLogger("inotify").setLevel(logging.WARNING)
    config["start_time"] = time.time()
    logging.info("min.waf started")


def lockfile_remove():
    if os.path.exists(config["lockfile"]):
        os.remove(config["lockfile"])


def lockfile_init():
    if os.path.exists(config["lockfile"]):
        print(
            f"Lockfile {config['lockfile']} exists, another instance may be running. Exiting."
        )
        sys.exit(1)
    with open(config["lockfile"], "w") as f:
        f.write(str(os.getpid()))


def iptables_clear() -> None:
    # IPv4
    subprocess.run(
        ["iptables", "-D", "INPUT", "-j", "MINWAF"], stderr=subprocess.DEVNULL
    )
    subprocess.run(["iptables", "-F", "MINWAF"], stderr=subprocess.DEVNULL)
    subprocess.run(["iptables", "-X", "MINWAF"], stderr=subprocess.DEVNULL)
    # IPv6
    subprocess.run(
        ["ip6tables", "-D", "INPUT", "-j", "MINWAF"], stderr=subprocess.DEVNULL
    )
    subprocess.run(["ip6tables", "-F", "MINWAF"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip6tables", "-X", "MINWAF"], stderr=subprocess.DEVNULL)


def iptables_init():
    iptables_clear()
    # IPv4
    subprocess.run(["iptables", "-N", "MINWAF"])
    subprocess.run(["iptables", "-I", "INPUT", "-j", "MINWAF"])
    # IPv6
    subprocess.run(["ip6tables", "-N", "MINWAF"])
    subprocess.run(["ip6tables", "-I", "INPUT", "-j", "MINWAF"])


def iptables_slow(ip_address: str):
    if ip_address in banned_ips:
        banned_ips[ip_address] = time.time()
        return
    banned_ips[ip_address] = time.time()
    if ":" in ip_address:
        subprocess.run([
            "ip6tables", "-A", "MINWAF", "-s", ip_address, "-p", "tcp", "--dport", "80", "-j", "TARPIT",
        ])
        subprocess.run([
            "ip6tables", "-A", "MINWAF", "-s", ip_address, "-p", "tcp", "--dport", "443", "-j", "TARPIT"
        ])
        return
    subprocess.run([
        "iptables", "-A", "MINWAF", "-s", ip_address, "-p", "tcp", "--dport", "80", "-j", "TARPIT",
    ])
    subprocess.run([
        "iptables", "-A", "MINWAF", "-s", ip_address, "-p", "tcp", "--dport", "443", "-j", "TARPIT",
    ])


def iptables_ban(ip_address: str, raw_lines: ExpiringList[str] | None = None):
    if ip_address in banned_ips:
        banned_ips[ip_address] = time.time()
        return
    config['bans'] += 1
    banned_ips[ip_address] = time.time()
    if ":" in ip_address:
        subprocess.run([
            "ip6tables", "-A", "MINWAF", "-s", ip_address, "-p", "tcp", "--dport", "80", "-j", "DROP",
        ])
        subprocess.run([
            "ip6tables", "-A", "MINWAF", "-s", ip_address, "-p", "tcp", "--dport", "443", "-j", "DROP",
        ])
        return
    subprocess.run([
        "iptables", "-A", "MINWAF", "-s", ip_address, "-p", "tcp", "--dport", "80", "-j", "DROP",
    ])
    subprocess.run([
        "iptables", "-A", "MINWAF", "-s", ip_address, "-p", "tcp", "--dport", "443", "-j", "DROP",
    ])
    logging.info(f"{ip_address} - banned for {config['ban_time']}s")
    if raw_lines is not None:
        for raw_line in raw_lines.values():
            logging.debug(f"{raw_line}".strip())
    return


def iptables_unban_expired():
    current_time = time.time()
    for ip in list(banned_ips.keys()):
        if current_time - banned_ips[ip] > config["ban_time"]:
            del banned_ips[ip]
            if ":" in ip:
                subprocess.run([
                    "ip6tables", "-D", "MINWAF", "-s", ip, "-p", "tcp", "--dport", "80", "-j", "DROP",
                ])
                subprocess.run([
                    "ip6tables", "-D", "MINWAF", "-s", ip, "-p", "tcp", "--dport", "443", "-j", "DROP",
                ])
            else:
                subprocess.run([
                    "iptables", "-D", "MINWAF", "-s", ip, "-p", "tcp", "--dport", "80", "-j", "DROP",
                ])
                subprocess.run([
                    "iptables", "-D", "MINWAF", "-s", ip, "-p", "tcp", "--dport", "443", "-j", "DROP",
                ])
            logging.info(f"Unbanned IP {ip} after {config['ban_time']}s")


def refresh_cb():
    global ip_stats, url_stats, ua_stats, banned_ips
    if not config["background"]:
        PrintStats.print_stats(config, banned_ips, ip_stats, url_stats, ua_stats)
    iptables_unban_expired()


def tail_f(filename: str):
    while True:
        tail_f_read(filename)


def tail_f_read(filename: str):
    refresh_ts = time.time()
    with open(filename, "r") as f:
        # Go to the end of the file
        f.seek(0, 2)
        i = inotify.adapters.Inotify()  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType]
        i.add_watch(filename)  # pyright: ignore[reportUnknownMemberType]
        rotated = False
        for event in i.event_gen(yield_nones=False):  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
            (_, type_names, _, _) = event  # pyright: ignore[reportGeneralTypeIssues, reportUnknownVariableType]

            if "IN_MOVE_SELF" in type_names:
                rotated = True
                break
            if "IN_MODIFY" in type_names:
                while (line := f.readline()) != '':
                    parse_line(line)
            if (time.time() - refresh_ts) > config["refresh_time"]:
                refresh_ts = time.time()
                refresh_cb()
        if rotated:
            logging.info("Log file rotated, reopening")
            time.sleep(3)
            return


def parse_line(line: str) -> None:
    global ip_stats, url_stats, ua_stats, banned_ips
    ua_data: IpData | None = None
    url_data: IpData | None = None

    log_line = Nginx.parse_log_line(line, config["columns"])
    if not log_line:
        return
    config["lines_parsed"] += 1
    if log_line.ip in ip_whitelist.get(log_line.host, []):
        return
    if Bots.good_bot(log_line):
        return
    if Bots.bad_bot(log_line):
        logging.info(f"Bad bot detected: {log_line.ip} - {log_line.ua}")
        iptables_ban(log_line.ip)
        return
    if config['whitelist_triggers'].get(log_line.host):
        for trigger in config['whitelist_triggers'][log_line.host]:
            if log_line.path == trigger['path'] and log_line.http_status == trigger['http_status']:
                if log_line.host not in ip_whitelist:
                    ip_whitelist[log_line.host] = []
                ip_whitelist[log_line.host].append(log_line.ip)
                logging.info(
                    f"Whitelisting IP {log_line.ip} for host {log_line.host} "
                    f"due to trigger on path {log_line.path} with status "
                    f"{log_line.http_status}")
                return

    ip_data = ip_stats.get(log_line.ip)
    if ip_data is None:
        ip_data = IpData(
            log_line.ip,
            'ip',
            {
                "raw_lines": ExpiringList(expiration_time=config["time_frame"]),
                "log_lines": ExpiringList(expiration_time=config["time_frame"]),
            }
        )
    ip_data.raw_lines.append(log_line.req_ts, line)
    ip_data.log_lines.append(log_line.req_ts, log_line)

    if config['url_stats']:
        url_data = url_stats.get(log_line.path)
        if url_data is None:
            url_data = IpData(
                log_line.path,
                'path',
                {
                    "raw_lines": ExpiringList(expiration_time=config["time_frame"]),
                    "log_lines": ExpiringList(expiration_time=config["time_frame"]),
                }
            )
        url_data.raw_lines.append(log_line.req_ts, line)
        url_data.log_lines.append(log_line.req_ts, log_line)

    if config['ua_stats']:
        ua_data = ua_stats.get(log_line.ua)
        if ua_data is None:
            ua_data = IpData(
                log_line.ua,
                'user_agent',
                {
                    "raw_lines": ExpiringList(expiration_time=config["time_frame"]),
                    "log_lines": ExpiringList(expiration_time=config["time_frame"]),
                }
            )
        ua_data.raw_lines.append(log_line.req_ts, line)
        ua_data.log_lines.append(log_line.req_ts, log_line)

    if Checks.bad_req(log_line):
        iptables_ban(log_line.ip, ip_data.raw_lines)

    # store data
    ip_stats.create(ts=log_line.req_ts, key=log_line.ip, value=ip_data)
    if config['url_stats'] and url_data is not None:
        url_stats.create(ts=log_line.req_ts, key=log_line.path, value=url_data)
    if config['ua_stats'] and ua_data is not None:
        ua_stats.create(ts=log_line.req_ts, key=log_line.ua, value=ua_data)

    if Checks.bad_stats(log_line, ip_data):
        iptables_ban(log_line.ip, ip_data.raw_lines)


@click.command()
@click.option(
    "--time-frame",
    default=300,
    help="Time frame in seconds to analyze logs (default: 300)",
)
@click.option(
    "--ban-time",
    default=600,
    help="Ban time in seconds for IP addresses (default: 600)",
)
@click.option("--background", is_flag=True, help="Run in background (daemon mode)")
@click.option("--url-stats", is_flag=True, help="Show URL stats")
@click.option("--ua-stats", is_flag=True, help="Show User-Agent stats")
@click.option("--skip-referer", is_flag=True, help="Don't show Referer stats")
@click.option(
    "--refresh-time", default=1, help="Screen refresh time in seconds (default: 1)"
)
def main(
    time_frame: int,
    ban_time: int,
    background: bool,
    url_stats: bool,
    ua_stats: bool,
    skip_referer: bool,
    refresh_time: int,
):
    global log_file_path
    config["time_frame"] = time_frame
    config["ban_time"] = ban_time
    config["background"] = background
    config["url_stats"] = url_stats
    config["ua_stats"] = ua_stats
    config["referer_stats"] = not skip_referer
    config["refresh_time"] = refresh_time
    init()
    if config["background"]:
        print("Running in background mode")
        pid = os.fork()
        if pid > 0:
            # Exit parent process
            sys.exit(0)
    tail_f(log_file_path)


if __name__ == "__main__":
    main()
