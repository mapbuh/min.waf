#!/usr/bin/env python3

import atexit
import click
import logging
import os
import subprocess
import sys
import time
import inotify.adapters  # type: ignore

from Bots import Bots
from ExpiringList import ExpiringList
from Nginx import Nginx
from PrintStats import PrintStats
from IpData import IpData
from Checks import Checks
from RunTimeStats import RunTimeStats
from IpTables import IpTables
from Config import Config

log_file_path: str = ""

config: Config = Config()
rts: RunTimeStats = RunTimeStats(config)


def init() -> None:
    global log_file_path, rts, config
    nginx_config = Nginx.config_get()
    log_file_path = nginx_config["log_file_path"]
    log_format = nginx_config["log_format"]
    config.columns = Nginx.parse_log_format(log_format)
    for config_line in config.columns:
        if config.columns[config_line] == -1:
            print(f"Could not find column for {config_line} in log_format")
            sys.exit(1)

    lockfile_init()
    atexit.register(lockfile_remove)
    IpTables.init()
    atexit.register(IpTables.clear)
    logging.basicConfig(
        filename="/var/log/min.waf.log",
        filemode="a",
        format="%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.DEBUG,
    )
    logging.getLogger("inotify").setLevel(logging.WARNING)
    rts.start_time = time.time()
    logging.info("min.waf started")


def lockfile_remove():
    if os.path.exists(config.lockfile):
        os.remove(config.lockfile)


def lockfile_init():
    if os.path.exists(config.lockfile):
        print(
            f"Lockfile {config.lockfile} exists, another instance may be running. Exiting."
        )
        sys.exit(1)
    with open(config.lockfile, "w") as f:
        f.write(str(os.getpid()))


def iptables_unban_expired():
    global rts, config
    current_time = time.time()
    for ip in list(rts.banned_ips.keys()):
        if current_time - rts.banned_ips[ip] > config.ban_time:
            del rts.banned_ips[ip]
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
            logging.info(f"Unbanned IP {ip} after {config.ban_time}s")


def refresh_cb():
    global rts
    if not config.background:
        PrintStats.print_stats(config, rts)
    iptables_unban_expired()


def logstats_cb():
    global rts
    PrintStats.log_stats(rts)


def tail_f(filename: str):
    while True:
        tail_f_read(filename)


def tail_f_read(filename: str):
    refresh_ts: float = time.time()
    logstats_ts: float = time.time()
    with open(filename, "r") as f:
        # Go to the end of the file
        f.seek(0, 2)
        i = inotify.adapters.Inotify()  # type: ignore
        i.add_watch(filename)  # type: ignore
        rotated = False
        partial_line: str = ""
        for event in i.event_gen(yield_nones=False):  # type: ignore
            (_, type_names, _, _) = event  # type: ignore
            if "IN_MOVE_SELF" in type_names:
                rotated = True
                break
            if "IN_MODIFY" in type_names:
                while (line := f.readline()) != "":
                    if line.endswith("\n"):
                        parse_line(partial_line + line)
                        partial_line = ""
                    else:
                        logging.debug(f"Partial line: {line}")
                        partial_line = line
            if (time.time() - refresh_ts) > config.refresh_time:
                refresh_ts = time.time()
                refresh_cb()
            if (time.time() - logstats_ts) > config.time_frame:
                logstats_ts = time.time()
                logstats_cb()
        if rotated:
            logging.info("Log file rotated, reopening")
            time.sleep(3)
            return


def parse_line(line: str) -> None:
    global rts, config
    ua_data: IpData | None = None
    url_data: IpData | None = None

    log_line = Nginx.parse_log_line(line, config.columns)
    if not log_line:
        return
    rts.lines_parsed += 1
    if log_line.ip in rts.ip_whitelist.get(log_line.host, []):
        return
    if Bots.good_bot(log_line):
        return
    if Bots.bad_bot(log_line):
        logging.info(f"Bad bot detected: {log_line.ip} - {log_line.ua}")
        IpTables.ban(log_line.ip, rts, config, None)
        return
    if config.whitelist_triggers.get(log_line.host):
        for trigger in config.whitelist_triggers[log_line.host]:
            if log_line.path == trigger['path'] and str(log_line.http_status) == str(trigger['http_status']):
                if log_line.host not in rts.ip_whitelist:
                    rts.ip_whitelist[log_line.host] = []
                rts.ip_whitelist[log_line.host].append(log_line.ip)
                logging.info(
                    f"Whitelisting IP {log_line.ip} for host {log_line.host} "
                    f"due to trigger on path {log_line.path} with status "
                    f"{log_line.http_status}")
                return

    ip_data = rts.ip_stats.get(log_line.ip)
    if ip_data is None:
        ip_data = IpData(
            log_line.ip,
            'ip',
            {
                "raw_lines": ExpiringList(expiration_time=config.time_frame),
                "log_lines": ExpiringList(expiration_time=config.time_frame),
            }
        )
    ip_data.raw_lines.append(log_line.req_ts, line)
    ip_data.log_lines.append(log_line.req_ts, log_line)

    if config.url_stats:
        url_data = rts.url_stats.get(log_line.path)
        if url_data is None:
            url_data = IpData(
                log_line.path,
                'path',
                {
                    "raw_lines": ExpiringList(expiration_time=config.time_frame),
                    "log_lines": ExpiringList(expiration_time=config.time_frame),
                }
            )
        url_data.raw_lines.append(log_line.req_ts, line)
        url_data.log_lines.append(log_line.req_ts, log_line)

    if config.ua_stats:
        ua_data = rts.ua_stats.get(log_line.ua)
        if ua_data is None:
            ua_data = IpData(
                log_line.ua,
                'user_agent',
                {
                    "raw_lines": ExpiringList(expiration_time=config.time_frame),
                    "log_lines": ExpiringList(expiration_time=config.time_frame),
                }
            )
        ua_data.raw_lines.append(log_line.req_ts, line)
        ua_data.log_lines.append(log_line.req_ts, log_line)

    if Checks.bad_req(log_line):
        IpTables.ban(log_line.ip, rts, config, ip_data.raw_lines)
    else:
        Checks.log_probes(log_line, line, rts)

    # store data
    rts.ip_stats.create(ts=log_line.req_ts, key=log_line.ip, value=ip_data)
    if config.url_stats and url_data is not None:
        rts.url_stats.create(ts=log_line.req_ts, key=log_line.path, value=url_data)
    if config.ua_stats and ua_data is not None:
        rts.ua_stats.create(ts=log_line.req_ts, key=log_line.ua, value=ua_data)

    if Checks.bad_stats(log_line, ip_data):
        IpTables.ban(log_line.ip, rts, config, ip_data.raw_lines)


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
    config.time_frame = time_frame
    config.ban_time = ban_time
    config.background = background
    config.url_stats = url_stats
    config.ua_stats = ua_stats
    config.referer_stats = not skip_referer
    config.refresh_time = refresh_time
    if config.background:
        print("Running in background mode")
        pid = os.fork()
        if pid > 0:
            # Exit parent process
            sys.exit(0)
    init()
    tail_f(log_file_path)


if __name__ == "__main__":
    main()
