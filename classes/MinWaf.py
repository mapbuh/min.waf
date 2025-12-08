import atexit
import logging
import os
import signal
import sys
import time
import yappi

from classes.Proxy import Proxy
from classes.Config import Config
from classes.IpTables import IpTables
from classes.PrintStats import PrintStats
from classes.RunTimeStats import RunTimeStats


class MinWaf:
    def __init__(self, config: Config) -> None:
        self.config: Config = config
        self.rts: RunTimeStats = RunTimeStats(config)
        if self.config.config.getboolean("dev", "profiling"):
            yappi.start()
            pass
        self.lockfile_init()
        IpTables.init(self.config)
        self.rts.load()
        atexit.register(self.at_exit)
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGUSR1, self.signal_handler)
        signal.signal(signal.SIGHUP, self.signal_handler)
        self.rts.start_time = time.time()
        logging.info(
            f"min.waf started on {self.config.config.get('main', 'host')}:{self.config.config.get('main', 'port')}"
        )
        self.proxy: Proxy = Proxy(self.config, self.rts)

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
            self.config.load()
            self.rts.load()
        else:
            logging.warning(f"Received unknown signal {signum}, ignoring...")

    def at_exit(self) -> None:
        self.lockfile_remove()
        IpTables.clear(self.config)
        if self.config.config.getboolean("dev", "profiling"):
            yappi.stop()
            yappi.get_func_stats().save("/tmp/min.waf.fun.kgrind", type="callgrind")
        logging.info(f"min.waf stopped after {time.time() - self.rts.start_time:.2f}s")

    def lockfile_remove(self) -> None:
        if os.path.exists(self.config.config.get("main", "lockfile")):
            os.remove(self.config.config.get("main", "lockfile"))

    def check_pid(self, pid: int) -> bool:
        """ Check For the existence of a unix pid. """
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        else:
            return True

    def lockfile_init(self) -> None:
        if os.path.exists(self.config.config.get("main", "lockfile")):
            with open(self.config.config.get("main", "lockfile"), "r") as f:
                pid = f.read().strip()
                if pid.isdigit() and self.check_pid(int(pid)):
                    print(f"Lockfile {self.config.config.get('main', 'lockfile')} exists, "
                          "another instance may be running. Exiting.")
                    sys.exit(1)
            self.lockfile_remove()
        with open(self.config.config.get("main", "lockfile"), "w") as f:
            f.write(str(os.getpid()))

    def logstats_cb(self) -> None:
        # Periodically log runtime statistics for monitoring and analysis
        PrintStats.log_stats(self.rts)
