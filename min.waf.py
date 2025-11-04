#!/usr/bin/env python3

import atexit
import click
import logging
import os
import sys
import time
import inotify.adapters  # type: ignore

from MinProxy import MinProxy
from Nginx import Nginx
from PrintStats import PrintStats
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
    if not config.background and not config.silent and not config.proxy:
        PrintStats.print_stats(config, rts)
    IpTables.unban_expired(rts, config)


def logstats_cb(rts: RunTimeStats) -> None:
    # Periodically log runtime statistics for monitoring and analysis
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
                        partial_line += line
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


def parse_line(config: Config, rts: RunTimeStats, line: str) -> str:
    """
    Parse a single log line using Nginx log format columns and process it.

    Returns the status of the processed line or STATUS_UNKNOWN if parsing fails.
    """
    log_line = Nginx.parse_log_line(line, config.columns)
    if not log_line:
        return Nginx.STATUS_UNKNOWN
    return Nginx.process_line(config, rts, log_line, line)


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
@click.option("--proxy", is_flag=True, default=None, help="Run as a proxy server")
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
    proxy: bool | None,
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
    if proxy is not None:
        configObj.proxy = proxy
    rtsObj: RunTimeStats = RunTimeStats(configObj)
    if configObj.background:
        print("Running in background mode")
        pid = os.fork()
        if pid > 0:
            # Exit parent process
            sys.exit(0)
    init(configObj, rtsObj)
    if configObj.proxy:
        MinProxy(configObj, rtsObj)
    else:
        tail_f(configObj, rtsObj)


if __name__ == "__main__":
    main()
