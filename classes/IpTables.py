import subprocess
import time
from classes.Config import Config
from classes.RunTimeStats import RunTimeStats


class IpTables:
    @staticmethod
    def clear(config: Config) -> None:
        # IPv4
        subprocess.run(
            ["iptables", "-D", "INPUT", "-j", config.config.get('main', 'iptables_chain')], stderr=subprocess.DEVNULL
        )
        subprocess.run(["iptables", "-F", config.config.get('main', 'iptables_chain')], stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-X", config.config.get('main', 'iptables_chain')], stderr=subprocess.DEVNULL)
        # IPv6
        subprocess.run(
            ["ip6tables", "-D", "INPUT", "-j", config.config.get('main', 'iptables_chain')], stderr=subprocess.DEVNULL
        )
        subprocess.run(["ip6tables", "-F", config.config.get('main', 'iptables_chain')], stderr=subprocess.DEVNULL)
        subprocess.run(["ip6tables", "-X", config.config.get('main', 'iptables_chain')], stderr=subprocess.DEVNULL)

    @staticmethod
    def init(config: Config) -> None:
        IpTables.clear(config)
        # IPv4
        subprocess.run(["iptables", "-N", config.config.get('main', 'iptables_chain')])
        subprocess.run(["iptables", "-I", "INPUT", "-j", config.config.get('main', 'iptables_chain')])
        # IPv6
        subprocess.run(["ip6tables", "-N", config.config.get('main', 'iptables_chain')])
        subprocess.run(["ip6tables", "-I", "INPUT", "-j", config.config.get('main', 'iptables_chain')])

    @staticmethod
    def ban(
        ip_address: str,
        rts: RunTimeStats,
        config: Config,
    ) -> bool:
        with rts._banned_ips_lock:
            if ip_address in rts.banned_ips:
                rts.banned_ips[ip_address] = time.time()
                return False
            rts.banned_ips[ip_address] = time.time()
        if ":" in ip_address:
            subprocess.run([
                "ip6tables",
                "-A", config.config.get('main', 'iptables_chain'),
                "-s", ip_address,
                "-p", "tcp",
                "--dport", "80",
                "-j", "DROP",
            ])
            subprocess.run([
                "ip6tables",
                "-A", config.config.get('main', 'iptables_chain'),
                "-s", ip_address,
                "-p", "tcp",
                "--dport", "443",
                "-j", "DROP",
            ])
            return True
        subprocess.run([
            "iptables",
            "-A", config.config.get('main', 'iptables_chain'),
            "-s", ip_address,
            "-p", "tcp",
            "--dport", "80",
            "-j", "DROP",
        ])
        subprocess.run([
            "iptables",
            "-A", config.config.get('main', 'iptables_chain'),
            "-s", ip_address,
            "-p", "tcp",
            "--dport", "443",
            "-j", "DROP",
        ])
        return True

    @staticmethod
    def unban_expired(config: Config, rts: RunTimeStats) -> None:
        ban_time = config.config.getint('main', 'ban_time')
        chain = config.config.get('main', 'iptables_chain')
        current_time = time.time()
        # only the bookkeeping runs under the lock; the iptables calls take a
        # few ms each and would hold up every request checking for bans
        with rts._banned_ips_lock:
            expired = [ip for ip, banned_at in rts.banned_ips.items() if current_time - banned_at > ban_time]
            for ip in expired:
                del rts.banned_ips[ip]
        # a ban of the same IP in the meantime appends its own rules, and -D
        # removes one matching rule, so the new ban keeps its rules
        for ip in expired:
            command = "ip6tables" if ":" in ip else "iptables"
            for port in ("80", "443"):
                subprocess.run([
                    command,
                    "-D", chain,
                    "-s", ip,
                    "-p", "tcp",
                    "--dport", port,
                    "-j", "DROP",
                ])
