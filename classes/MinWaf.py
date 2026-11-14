import atexit
import fcntl
import functools
import logging
import os
import signal
import sys
import time
import yappi

from classes.Bots import Bots
from classes.Config import Config
from classes.IpSet import IpSet
from classes.PrintStats import PrintStats
from classes.Proxy import Proxy
from classes.RunTimeStats import RunTimeStats


class MinWaf:
    def __init__(self, config: Config) -> None:
        self.config: Config = config
        self.rts: RunTimeStats = RunTimeStats(config)
        if self.config.config.getboolean("dev", "profiling"):
            yappi.start()
        self.lockfile_init()
        IpSet.init(self.config)
        self.rts.ip_blacklist.load()
        atexit.register(self.at_exit)
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGUSR1, self.signal_handler)
        signal.signal(signal.SIGHUP, self.signal_handler)
        self.rts.start_time = time.time()
        logger = logging.getLogger("min.waf")
        logger.info(
            f"min.waf started on {self.config.config.get('main', 'host')}:{self.config.config.get('main', 'port')}"
        )
        self.proxy: Proxy = Proxy(self.config, self.rts, self.every_10_seconds, self.every_1_hour)

    def every_10_seconds(self) -> None:
        self.rts.inter_domain.expire()
        self.unban_expired(self.config, self.rts)
        self.rts.ip_blacklist.load()
        self.config.bot_whitelist.refresh()

    def every_1_hour(self) -> None:
        PrintStats.log_stats(self.rts)
        self.print_memory_usage()
        self.print_cache_stats()

    def print_cache_stats(self) -> None:
        logger = logging.getLogger("min.waf")
        try:
            info: dict[str, functools._CacheInfo] = {  # pyright: ignore[reportPrivateUsage]
                "bots_bad_bot": Bots.bad_bot.cache_info(),
                "bots_good_bot": Bots.good_bot.cache_info(),
                "config_getlistint": self.config.getlistint.cache_info(),
                "config_harmful_patterns": self.config.harmful_patterns.cache_info(),
                "config_harmful_patterns_encoded": self.config.harmful_patterns_encoded.cache_info(),
                "config_host_has_trigger": self.config.host_has_trigger.cache_info(),
                "config_longest_harmful_pattern": self.config.longest_harmful_pattern.cache_info(),
                "config_whitelist_host_triggers": self.config.whitelist_host_triggers.cache_info(),
                "config_whitelist_triggers": self.config.whitelist_triggers.cache_info(),
            }
            for key, value in info.items():
                logger.debug(
                    f"{key} Cache - Hits: {value.hits}, Misses: {value.misses}, "
                    f"Current Size: {value.currsize}, Max Size: {value.maxsize}, "
                    f"Hit Rate: "
                    f"{value.hits / (value.hits + value.misses) if (value.hits + value.misses) > 0 else 0:.2%}"
                )
        except Exception as e:
            logger.warning(f"Could not retrieve cache stats: {e}")

    def print_memory_usage(self) -> None:
        logger = logging.getLogger("min.waf")
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        logger.info(f"Current memory usage: {line.strip()}")
                        break
        except FileNotFoundError:
            logger.warning("Could not read /proc/self/status to get memory usage.")

    def signal_handler(self, signum: int, frame: object) -> None:
        logger = logging.getLogger("min.waf")
        if signum == signal.SIGTERM:
            logger.info(f"Received signal {signum}, exiting...")
            self.at_exit()
            # leave without waiting for the worker threads: the executor
            # shutdown would wait for idle connections up to the idle timeout
            os._exit(0)
        elif signum == signal.SIGUSR1:
            logger.info(f"Received signal {signum}, dumping stats...")
            self.every_1_hour()
        elif signum == signal.SIGHUP:
            logger.info(f"Received signal {signum}, reloading config...")
            self.config.load()
            Bots.clear_caches()
            self.rts.ip_blacklist.load()
        else:
            logger.warning(f"Received unknown signal {signum}, ignoring...")

    def at_exit(self) -> None:
        logger = logging.getLogger("min.waf")
        self.lockfile_remove()
        if self.config.config.getboolean("dev", "profiling"):
            yappi.stop()
            yappi.get_func_stats().save("/tmp/min.waf.fun.kgrind", type="callgrind")
        logger.info(f"min.waf stopped after {time.time() - self.rts.start_time:.2f}s")

    def lockfile_remove(self) -> None:
        fd = getattr(self, "lockfile_fd", None)
        if fd is not None:
            self.lockfile_fd = None
            os.close(fd)

    def lockfile_init(self) -> None:
        """Hold an exclusive flock on the lockfile for the process lifetime.

        The file itself stays on disk after exit (only the lock is
        released), so a stale pid never blocks a restart and two instances
        starting at the same time cannot both pass the check.
        """
        self.lockfile_fd = os.open(self.config.config.get("main", "lockfile"), os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.flock(self.lockfile_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print(f"Lockfile {self.config.config.get('main', 'lockfile')} is held by another instance. Exiting.")
            sys.exit(1)
        os.ftruncate(self.lockfile_fd, 0)
        os.write(self.lockfile_fd, str(os.getpid()).encode())

    @staticmethod
    def unban_expired(
        config: Config,
        rts: RunTimeStats
    ) -> None:
        # the kernel expires the ipset entries itself; this only forgets them
        ban_duration = config.config.getint('main', 'ban_time')
        current_time = time.time()
        with rts._banned_ips_lock:
            for ip in [ip for ip, ban_time in rts.banned_ips.items() if (current_time - ban_time) > ban_duration]:
                del rts.banned_ips[ip]
