import os
import atexit
import signal
import time
import logging
import sys

from Config import Config
from RunTimeStats import RunTimeStats
from IpTables import IpTables
from PrintStats import PrintStats


class MinWaf:
    def __init__(self, config: Config) -> None:
        self.config: Config = config
        self.rts: RunTimeStats = RunTimeStats(config)

    def init(self) -> None:
        logging.basicConfig(
            format="%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            level=logging.DEBUG if self.config.debug else logging.INFO,
        )
        logging.getLogger("inotify").setLevel(logging.WARNING)
        self.lockfile_init()
        IpTables.init(self.config)
        self.rts.init_ip_blacklist(self.config)
        atexit.register(self.at_exit)
        self.rts.start_time = time.time()
        logging.info("min.waf started")
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGUSR1, self.signal_handler)
        signal.signal(signal.SIGHUP, self.signal_handler)

    def signal_handler(self, signum: int, frame: object) -> None:
        if signum == signal.SIGTERM:
            logging.info(f"Received signal {signum}, exiting...")
            self.at_exit()
            sys.exit(0)
        elif signum == signal.SIGUSR1:
            logging.info(f"Received signal {signum}, dumping stats...")
            self.logstats_cb()
        elif signum == signal.SIGHUP:
            logging.info(f"Received signal {signum}, reloading config...")
            self.config.load(self.config.config_file_path)
        else:
            logging.warning(f"Received unknown signal {signum}, ignoring...")

    def at_exit(self) -> None:
        self.lockfile_remove()
        IpTables.clear(self.config)
        logging.info(f"min.waf stopped after {time.time() - self.rts.start_time:.2f}s")

    def lockfile_remove(self) -> None:
        if os.path.exists(self.config.lockfile):
            os.remove(self.config.lockfile)

    def check_pid(self, pid: int) -> bool:
        """ Check For the existence of a unix pid. """
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        else:
            return True

    def lockfile_init(self) -> None:
        if os.path.exists(self.config.lockfile):
            with open(self.config.lockfile, "r") as f:
                pid = f.read().strip()
                if pid.isdigit() and self.check_pid(int(pid)):
                    print(
                        f"Lockfile {self.config.lockfile} exists, another instance may be running. Exiting."
                    )
                    sys.exit(1)
            self.lockfile_remove()
        with open(self.config.lockfile, "w") as f:
            f.write(str(os.getpid()))

    def refresh_cb(self) -> None:
        if self.config.mode == "interactive":
            PrintStats.print_stats(self.config, self.rts)
        IpTables.unban_expired(self.config, self.rts)
        if self.config.ip_blacklist and self.rts.ip_blacklist:
            self.rts.ip_blacklist.refresh_list()

    def logstats_cb(self) -> None:
        # Periodically log runtime statistics for monitoring and analysis
        PrintStats.log_stats(self.rts)
