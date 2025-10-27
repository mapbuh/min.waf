#!/usr/bin/env python3

import atexit
from typing import Any
import click
import logging
import os
import subprocess
import sys
import time
import inotify.adapters

from Bots import Bots
from ExpiringDict import ExpiringDict
from ExpiringList import ExpiringList
from Nginx import Nginx
from PrintStats import PrintStats
from IpData import IpData

# from KnownAttacks import KnownAttacks

log_file_path: str = ""

ip_ignored: list[str] = []
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
    "detail_lines": 10,
    "start_time": None,
    "lines_parsed": 0,
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
    

def iptables_ban(ip_address: str):
    if ip_address in banned_ips:
        banned_ips[ip_address] = time.time()
        return
    logging.info(f"Banning IP {ip_address} for {config['ban_time']}s")
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
    if not config["background"]:
        PrintStats.print_stats(config, banned_ips, ip_stats, url_stats, ua_stats)
    iptables_unban_expired()

def tail_f(filename: str):
    refresh_ts = time.time()
    while True:
        with open(filename, "r") as f:
            # Go to the end of the file
            f.seek(0, 2)
            i = inotify.adapters.Inotify()
            i.add_watch(filename)
            rotated = False
            for event in i.event_gen(yield_nones=False):
                (_, type_names, _, _) = event

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
                time.sleep(3)
                break
    return


def ignore_ip(ip: str, ua: str) -> bool:
    if ip in ip_ignored:
        return True
    # ignore known bots
    for bot, signatures in Bots.good_bots.items():
        if any(signature in ua for signature in signatures):
            logging.debug(f"Ignoring {bot} from: {ip}")
            ip_ignored.append(ip)
            return True
    return False


def parse_line(line: str) -> None:
    global ip_stats, url_by_ip

    log_line = Nginx.parse_log_line(line, config["columns"])
    if not log_line:
        return
    if ignore_ip(log_line.ip, log_line.ua):
        return
    config["lines_parsed"] += 1

    ip_data = ip_stats.get(log_line.ip)
    if ip_data is None:
        ip_data = IpData(
            {
                "raw_lines": ExpiringList(expiration_time=config["time_frame"]),
                "log_lines": ExpiringList(expiration_time=config["time_frame"]),
            }
        )
    ip_data.raw_lines.append(log_line.req_ts, line)
    ip_data.log_lines.append(log_line.req_ts, log_line)

    url_data = url_stats.get(log_line.path)
    if url_data is None:
        url_data = IpData(
            {
                "raw_lines": ExpiringList(expiration_time=config["time_frame"]),
                "log_lines": ExpiringList(expiration_time=config["time_frame"]),
            }
        )
    url_data.raw_lines.append(log_line.req_ts, line)
    url_data.log_lines.append(log_line.req_ts, log_line)

    ua_data = ua_stats.get(log_line.ua)
    if ua_data is None:
        ua_data = IpData(
            {
                "raw_lines": ExpiringList(expiration_time=config["time_frame"]),
                "log_lines": ExpiringList(expiration_time=config["time_frame"]),
            }
        )
    ua_data.raw_lines.append(log_line.req_ts, line)
    ua_data.log_lines.append(log_line.req_ts, log_line)

    # combined rules
    # xmlrpc.php for a site that does not use it is always bad
    if (
        "xmlrpc.php" in log_line.path
        and log_line.http_status >= 300
        and log_line.http_status != 403
    ):
        iptables_ban(log_line.ip)
        logging.info(
            f"Banned IP {log_line.ip} - xmlrpc.php access with status {log_line.http_status}"
        )
        for raw_line in ip_data.raw_lines.values():
            logging.debug(f"{raw_line}".strip())
    # wp-login for site that does not use it is always bad
    if "wp-login.php" in log_line.path and log_line.http_status == 404:
        iptables_ban(log_line.ip)
        logging.info(
            f"Banned IP {log_line.ip} - wp-login.php access with status {log_line.http_status}"
        )
        for raw_line in ip_data.raw_lines.values():
            logging.debug(f"{line}".strip())
    # that's just lazy
    if "python-requests" in log_line.ua or "python-urllib" in log_line.ua:
        iptables_ban(log_line.ip)
        logging.info(
            f"Banned IP {log_line.ip} - python requests detected in User-Agent"
        )
        for raw_line in ip_data.raw_lines.values():
            logging.debug(f"{raw_line}".strip())

    # store data
    ip_stats.create(ts=log_line.req_ts, key=log_line.ip, value=ip_data)
    url_stats.create(ts=log_line.req_ts, key=log_line.path, value=url_data)
    ua_stats.create(ts=log_line.req_ts, key=log_line.ua, value=ua_data)

    ip_stats_ip = ip_stats.get(log_line.ip)
    if ip_stats_ip is not None:
        if (
            ip_stats_ip.request_count >= 10
            and ip_stats_ip.http_status_bad_perc > 75.0
            and not log_line.ip in banned_ips
        ):
            logging.debug(
                f"IP {log_line.ip} - Requests: {ip_stats_ip.request_count}, Bad HTTP Statuses: {ip_stats_ip.http_status_bad} ({ip_stats_ip.http_status_bad_perc:.2f}%)"
            )
        if ip_stats_ip.steal_time < -30 and ip_data.total_time > 5:
            logging.debug(
                f"IP {log_line.ip} is stealing time: {ip_stats_ip.steal_time:.2f}s over {ip_data.total_time:.2f}s with {ip_data.request_count} requests ratio: {ip_data.steal_ratio:.6f}"
            )


#    for url in url_by_ip.get(ip, []):
#        if KnownAttacks.is_known(url):
#            ip_data['attacks'] += 1
#    if ip_data['attacks'] >= 3:
#        score_add = 10 * ip_data['attacks'] / ip_data['request_count']
#        logging.info(f"IP {ip} has {ip_data['attacks']} known attacks in {ip_data['request_count']} requests, score: #{ip_data['score']:.2f}+{score_add:.2f}")
#        ip_data['score'] += score_add

#        for line in requests_by_ip[ip].get_values_by_key('log_line'):
#            logging.debug(f"{line}".strip())

#    # 3 times for wp-login is quite enough (times 2, one for get, one for post)
#    # status_by_ip[log_line.ip].append(req_ts, {"http_status": float(http_status), "log_line": line, "req": req})
#    counter = 0
#    if not log_line.ip in banned_ips and 'wp-login.php' in req:
#        for value in status_by_ip[log_line.ip].get_values():
#            if not 'wp-login.php' in value['req']:
#                continue
#            counter += 1
#        if counter >= 6 and not log_line.ip in banned_ips:
#            iptables_ban(log_line.ip)
#            logging.info(f"Banned IP {log_line.ip} - Multiple wp-login.php access attempts")
#            for line in ip_data.lines:
#                logging.debug(f"{line}".strip())


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
@click.option("--skip-url-stats", is_flag=True, help="Don't show URL stats")
@click.option("--skip-ua-stats", is_flag=True, help="Don't show User-Agent stats")
@click.option("--skip-referer", is_flag=True, help="Don\t show Referer stats")
@click.option(
    "--refresh-time", default=1, help="Screen refresh time in seconds (default: 1)"
)
def main(
    time_frame: int,
    ban_time: int,
    background: bool,
    skip_url_stats: bool,
    skip_ua_stats: bool,
    skip_referer: bool,
    refresh_time: int,
):
    global log_file_path
    config["time_frame"] = time_frame
    config["ban_time"] = ban_time
    config["background"] = background
    config["url_stats"] = not skip_url_stats
    config["ua_stats"] = not skip_ua_stats
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
