import subprocess
from RunTimeStats import RunTimeStats
from ExpiringList import ExpiringList
import time
import logging
from Config import Config


class IpTables:
    @staticmethod
    def clear() -> None:
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

    @staticmethod
    def init() -> None:
        IpTables.clear()
        # IPv4
        subprocess.run(["iptables", "-N", "MINWAF"])
        subprocess.run(["iptables", "-I", "INPUT", "-j", "MINWAF"])
        # IPv6
        subprocess.run(["ip6tables", "-N", "MINWAF"])
        subprocess.run(["ip6tables", "-I", "INPUT", "-j", "MINWAF"])

    @staticmethod
    def slow(ip_address: str, rts: RunTimeStats):
        if ip_address in rts.banned_ips:
            rts.banned_ips[ip_address] = time.time()
            return
        rts.banned_ips[ip_address] = time.time()
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

    @staticmethod
    def ban(
        ip_address: str,
        rts: RunTimeStats,
        config: Config,
        raw_lines: ExpiringList[str] | None = None,
        reason: str = ""
    ) -> None:
        if ip_address in rts.banned_ips:
            rts.banned_ips[ip_address] = time.time()
            return
        rts.bans += 1
        rts.banned_ips[ip_address] = time.time()
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
        if reason != "":
            logging.info(f"{ip_address} banned for {config.ban_time}s - Reason: {reason}")
        else:
            logging.info(f"{ip_address} banned for {config.ban_time}s")
        if raw_lines is not None:
            for raw_line in raw_lines.values():
                logging.debug(f"{raw_line}".strip())
        return

    @staticmethod
    def unban_expired(rts: RunTimeStats, config: Config) -> None:
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
