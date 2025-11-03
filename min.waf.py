#!/usr/bin/env python3

import atexit
import click
import logging
import os
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


def at_exit(config: Config, rts: RunTimeStats) -> None:
    lockfile_remove(config)
    IpTables.clear()
    logging.info(f"min.waf stopped after {time.time() - rts.start_time:.2f}s")


def init(config: Config, rts: RunTimeStats) -> None:
    nginx_config = Nginx.config_get()
    config.log_file_path = nginx_config["log_file_path"]
    log_format = nginx_config["log_format"]
    config.columns = Nginx.parse_log_format(log_format)
    for config_line in config.columns:
        if config.columns[config_line] == -1:
            print(f"Could not find column for {config_line} in log_format")
            sys.exit(1)

    lockfile_init(config)
    IpTables.init()
    atexit.register(at_exit, config, rts)
    logging.basicConfig(
        format="%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.INFO if config.silent else logging.DEBUG,
    )
    logging.getLogger("inotify").setLevel(logging.WARNING)
    rts.start_time = time.time()
    logging.info("min.waf started")


def lockfile_remove(config: Config) -> None:
    if os.path.exists(config.lockfile):
        os.remove(config.lockfile)


def check_pid(pid: int) -> bool:
    """ Check For the existence of a unix pid. """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


def lockfile_init(config: Config) -> None:
    if os.path.exists(config.lockfile):
        with open(config.lockfile, "r") as f:
            pid = f.read().strip()
            if pid.isdigit() and check_pid(int(pid)):
                print(
                    f"Lockfile {config.lockfile} exists, another instance may be running. Exiting."
                )
                sys.exit(1)
        lockfile_remove(config)
    with open(config.lockfile, "w") as f:
        f.write(str(os.getpid()))


def refresh_cb(config: Config, rts: RunTimeStats) -> None:
    if not config.background and not config.silent:
        PrintStats.print_stats(config, rts)
    IpTables.unban_expired(rts, config)


def logstats_cb(rts: RunTimeStats) -> None:
    PrintStats.log_stats(rts)


def tail_f(config: Config, rts: RunTimeStats):
    while True:
        tail_f_read(config, rts)


def tail_f_read(config: Config, rts: RunTimeStats):
    refresh_ts: float = time.time()
    logstats_ts: float = time.time()
    with open(config.log_file_path, "r") as f:
        # Go to the end of the file
        f.seek(0, 2)
        i = inotify.adapters.Inotify()  # type: ignore
        i.add_watch(config.log_file_path)  # type: ignore
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
                        parse_line(config, rts, partial_line + line)
                        partial_line = ""
                    else:
                        logging.debug(f"Partial line: {line}")
                        partial_line = line
            if (time.time() - refresh_ts) > config.refresh_time:
                refresh_ts = time.time()
                refresh_cb(config, rts)
            if (time.time() - logstats_ts) > 3600:
                logstats_ts = time.time()
                logstats_cb(rts)
        if rotated:
            logging.info("Log file rotated, reopening")
            time.sleep(3)
            return


def parse_line(config: Config, rts: RunTimeStats, line: str) -> None:
    ua_data: IpData | None = None
    url_data: IpData | None = None

    log_line = Nginx.parse_log_line(line, config.columns)
    if not log_line:
        return
    rts.lines_parsed += 1
    if log_line.ip in rts.ip_whitelist.get(log_line.host, []):
        return
    if Bots.good_bot(config, log_line):
        return
    if reason := Bots.bad_bot(config, log_line):
        IpTables.ban(log_line.ip, rts, config, None, reason)
        return
    if config.whitelist_triggers.get(log_line.host):
        for trigger in config.whitelist_triggers[log_line.host]:
            if log_line.path == trigger['path'] and str(log_line.http_status) == str(trigger['http_status']):
                if log_line.host not in rts.ip_whitelist:
                    rts.ip_whitelist[log_line.host] = []
                rts.ip_whitelist[log_line.host].append(log_line.ip)
                logging.info(
                    f"{log_line.ip} whitelisted due to trigger "
                    f"on path {log_line.host}{log_line.path} with status "
                    f"{log_line.http_status}")
                return
    if log_line.path.endswith(tuple(config.ignore_extensions)):
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

    if reason := Checks.bad_req(log_line):
        IpTables.ban(log_line.ip, rts, config, ip_data.raw_lines, reason)
    else:
        Checks.log_probes(log_line, line, rts)

    # logging.info(f"Parsed line: {line.strip()}")
    # store data
    rts.ip_stats.create(ts=log_line.req_ts, key=log_line.ip, value=ip_data)
    if config.url_stats and url_data is not None:
        rts.url_stats.create(ts=log_line.req_ts, key=log_line.path, value=url_data)
    if config.ua_stats and ua_data is not None:
        rts.ua_stats.create(ts=log_line.req_ts, key=log_line.ua, value=ua_data)

    if reason := Checks.bad_stats(log_line, ip_data):
        IpTables.ban(log_line.ip, rts, config, ip_data.raw_lines, reason)


@click.command()
@click.option("--config", default="/etc/min.waf.yaml", help="Path to config file")
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
@click.option("--background", is_flag=True, default=None, help="Run in background (daemon mode)")
@click.option("--url-stats", is_flag=True, default=None, help="Show URL stats")
@click.option("--ua-stats", is_flag=True, default=None, help="Show User-Agent stats")
@click.option(
    "--refresh-time", default=None, help="Screen refresh time in seconds (default: 1)"
)
@click.option("--silent", is_flag=True, default=None, help="Silent mode, no output to console")
def main(
    config: str,
    time_frame: int | None,
    ban_time: int | None,
    background: bool | None,
    url_stats: bool | None,
    ua_stats: bool | None,
    refresh_time: int | None,
    silent: bool | None,
):
    configObj: Config = Config()
    # Load config file
    configObj.load(config)
    if time_frame is not None:
        configObj.time_frame = time_frame
    if ban_time is not None:
        configObj.ban_time = ban_time
    if background is not None:
        configObj.background = background
    if url_stats is not None:
        configObj.url_stats = url_stats
    if ua_stats is not None:
        configObj.ua_stats = ua_stats
    if refresh_time is not None:
        configObj.refresh_time = refresh_time
    if silent is not None:
        configObj.silent = silent
    rtsObj: RunTimeStats = RunTimeStats(configObj)
    if configObj.background:
        print("Running in background mode")
        pid = os.fork()
        if pid > 0:
            # Exit parent process
            sys.exit(0)
    init(configObj, rtsObj)
    tail_f(configObj, rtsObj)


if __name__ == "__main__":
    main()
