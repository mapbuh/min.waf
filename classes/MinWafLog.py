import sys
import os
import time
import inotify.adapters  # type: ignore
import logging

from classes.Config import Config
from classes.Nginx import Nginx
from classes.MinWaf import MinWaf
from classes.PrintStats import PrintStats
from classes.IpTables import IpTables


class MinWafLog(MinWaf):
    def __init__(self, config: Config) -> None:
        if self.config.mode == "log2ban":
            print("Running in background mode")
            pid = os.fork()
            if pid > 0:
                # Exit parent process
                sys.exit(0)
        super().__init__(config)
        nginx_config = Nginx.config_get()
        self.config.log_file_path = nginx_config["log_file_path"]
        log_format = nginx_config["log_format"]
        self.config.columns = Nginx.parse_log_format(log_format)
        for config_line in self.config.columns:
            if self.config.columns[config_line] == -1:
                print(f"Could not find column for {config_line} in log_format")
                sys.exit(1)

    def run(self) -> None:
        while True:
            self.tail_f()

    def tail_f(self):
        refresh_ts: float = time.time()
        logstats_ts: float = time.time()
        with open(self.config.log_file_path, "r") as f:
            # Go to the end of the file
            f.seek(0, 2)
            i = inotify.adapters.Inotify()  # type: ignore
            i.add_watch(self.config.log_file_path)  # type: ignore
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
                            self.parse_line(partial_line + line)
                            partial_line = ""
                        else:
                            partial_line += line
                if (time.time() - refresh_ts) > self.config.refresh_time:
                    refresh_ts = time.time()
                    self.refresh_cb()
                if (time.time() - logstats_ts) > 3600:
                    logstats_ts = time.time()
                    self.logstats_cb()
            if rotated:
                logging.info("Log file rotated, reopening")
                time.sleep(3)
                return

    def refresh_cb(self) -> None:
        if self.config.mode == "interactive":
            PrintStats.print_stats(self.config, self.rts)
        IpTables.unban_expired(self.config, self.rts)
        if self.config.ip_blacklist and self.rts.ip_blacklist:
            self.rts.ip_blacklist.refresh_list()

    def parse_line(self, line: str) -> str:
        """
        Parse a single log line using Nginx log format columns and process it.

        Returns the status of the processed line or STATUS_UNKNOWN if parsing fails.
        """
        log_line = Nginx.parse_log_line(line, self.config.columns)
        if not log_line:
            return Nginx.STATUS_UNKNOWN
        return Nginx.process_line(self.config, self.rts, log_line, line)
