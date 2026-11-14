import fcntl
import os
import subprocess
import time
from classes.Config import Config
from classes.RunTimeStats import RunTimeStats


class IpSet:
    '''Bans IPs by adding them to an ipset that an iptables rule drops.

    All instances share the sets (ipset_name for IPv4, ipset_name + "6" for
    IPv6) and leave them in place on exit, so restarting one instance keeps
    the bans of the others. The kernel drops each entry after ban_time.
    '''

    @staticmethod
    def names(config: Config) -> dict[str, str]:
        '''ipset name per iptables command; one set per address family.'''
        name = config.config.get('main', 'ipset_name')
        return {"iptables": name, "ip6tables": f"{name}6"}

    @staticmethod
    def rule(name: str) -> list[str]:
        return [
            "INPUT",
            "-m", "set", "--match-set", name, "src",
            "-p", "tcp", "-m", "multiport", "--dports", "80,443",
            "-j", "DROP",
        ]

    @staticmethod
    def init(config: Config) -> None:
        '''Create the sets and their DROP rules if they don't exist yet.'''
        lock_path = os.path.join(os.path.dirname(config.config.get('main', 'lockfile')), "min.waf-ipset.lock")
        # instances starting together must not both miss the rule and add it twice
        with open(lock_path, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            for command, name in IpSet.names(config).items():
                family = "inet6" if command == "ip6tables" else "inet"
                subprocess.run([
                    "ipset", "create", name, "hash:ip", "family", family,
                    "timeout", config.config.get('main', 'ban_time'), "-exist",
                ])
                rule = IpSet.rule(name)
                if subprocess.run([command, "-C", *rule], stderr=subprocess.DEVNULL).returncode != 0:
                    subprocess.run([command, "-I", *rule])

    @staticmethod
    def ban(ip_address: str, rts: RunTimeStats, config: Config) -> bool:
        '''Ban an IP; returns whether this instance had not banned it yet.'''
        with rts._banned_ips_lock:
            new_ban = ip_address not in rts.banned_ips
            rts.banned_ips[ip_address] = time.time()
        # always add: -exist refreshes the kernel timeout, which another
        # instance may have set for the same IP
        command = "ip6tables" if ":" in ip_address else "iptables"
        subprocess.run([
            "ipset", "add", IpSet.names(config)[command], ip_address,
            "timeout", config.config.get('main', 'ban_time'), "-exist",
        ])
        return new_ban
