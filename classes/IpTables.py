import subprocess
import time
import logging
from classes.Config import Config
from classes.RunTimeStats import RunTimeStats
from classes.ExpiringList import ExpiringList


class IpTables:
    @staticmethod
    def clear(config: Config) -> None:
        # IPv4
        subprocess.run(
            ["iptables", "-D", "INPUT", "-j", config.iptables_chain], stderr=subprocess.DEVNULL
        )
        subprocess.run(["iptables", "-F", config.iptables_chain], stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-X", config.iptables_chain], stderr=subprocess.DEVNULL)
        # IPv6
        subprocess.run(
            ["ip6tables", "-D", "INPUT", "-j", config.iptables_chain], stderr=subprocess.DEVNULL
        )
        subprocess.run(["ip6tables", "-F", config.iptables_chain], stderr=subprocess.DEVNULL)
        subprocess.run(["ip6tables", "-X", config.iptables_chain], stderr=subprocess.DEVNULL)

    @staticmethod
    def init(config: Config) -> None:
        IpTables.clear(config)
        # IPv4
        subprocess.run(["iptables", "-N", config.iptables_chain])
        subprocess.run(["iptables", "-I", "INPUT", "-j", config.iptables_chain])
        # IPv6
        subprocess.run(["ip6tables", "-N", config.iptables_chain])
        subprocess.run(["ip6tables", "-I", "INPUT", "-j", config.iptables_chain])

    @staticmethod
    def slow(ip_address: str, config: Config, rts: RunTimeStats):
        if ip_address in rts.banned_ips:
            rts.banned_ips[ip_address] = time.time()
            return
        rts.banned_ips[ip_address] = time.time()
        if ":" in ip_address:
            subprocess.run([
                "ip6tables",
                "-A",
                config.iptables_chain,
                "-s",
                ip_address,
                "-p",
                "tcp",
                "--dport",
                "80",
                "-j",
                "TARPIT",
            ])
            subprocess.run([
                "ip6tables",
                "-A",
                config.iptables_chain,
                "-s",
                ip_address,
                "-p",
                "tcp",
                "--dport",
                "443",
                "-j",
                "TARPIT"
            ])
            return
        subprocess.run([
            "iptables", "-A", config.iptables_chain, "-s", ip_address, "-p", "tcp", "--dport", "80", "-j", "TARPIT",
        ])
        subprocess.run([
            "iptables", "-A", config.iptables_chain, "-s", ip_address, "-p", "tcp", "--dport", "443", "-j", "TARPIT",
        ])

    @staticmethod
    def ban(
        ip_address: str,
        rts: RunTimeStats,
        config: Config,
        raw_lines: ExpiringList[str] | None = None
    ) -> None:
        if ip_address in rts.banned_ips:
            rts.banned_ips[ip_address] = time.time()
            return
        rts.bans += 1
        rts.banned_ips[ip_address] = time.time()
        if ":" in ip_address:
            subprocess.run([
                "ip6tables", "-A", config.iptables_chain, "-s", ip_address, "-p", "tcp", "--dport", "80", "-j", "DROP",
            ])
            subprocess.run([
                "ip6tables", "-A", config.iptables_chain, "-s", ip_address, "-p", "tcp", "--dport", "443", "-j", "DROP",
            ])
            return
        subprocess.run([
            "iptables", "-A", config.iptables_chain, "-s", ip_address, "-p", "tcp", "--dport", "80", "-j", "DROP",
        ])
        subprocess.run([
            "iptables", "-A", config.iptables_chain, "-s", ip_address, "-p", "tcp", "--dport", "443", "-j", "DROP",
        ])
        return

    @staticmethod
    def unban_expired(config: Config, rts: RunTimeStats) -> None:
        current_time = time.time()
        for ip in list(rts.banned_ips.keys()):
            if current_time - rts.banned_ips[ip] > config.ban_time:
                del rts.banned_ips[ip]
                if ":" in ip:
                    subprocess.run([
                        "ip6tables", "-D", config.iptables_chain, "-s", ip, "-p", "tcp", "--dport", "80", "-j", "DROP",
                    ])
                    subprocess.run([
                        "ip6tables", "-D", config.iptables_chain, "-s", ip, "-p", "tcp", "--dport", "443", "-j", "DROP",
                    ])
                else:
                    subprocess.run([
                        "iptables", "-D", config.iptables_chain, "-s", ip, "-p", "tcp", "--dport", "80", "-j", "DROP",
                    ])
                    subprocess.run([
                        "iptables", "-D", config.iptables_chain, "-s", ip, "-p", "tcp", "--dport", "443", "-j", "DROP",
                    ])
                logging.debug(f"{ip} unbanned after {config.ban_time}s")
