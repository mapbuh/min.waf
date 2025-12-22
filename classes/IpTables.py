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
    def slow(ip_address: str, config: Config, rts: RunTimeStats):
        if ip_address in rts.banned_ips:
            rts.banned_ips[ip_address] = time.time()
            return
        rts.banned_ips[ip_address] = time.time()
        if ":" in ip_address:
            subprocess.run([
                "ip6tables",
                "-A",
                config.config.get('main', 'iptables_chain'),
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
                config.config.get('main', 'iptables_chain'),
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
            "iptables",
            "-A", config.config.get('main', 'iptables_chain'),
            "-s", ip_address,
            "-p", "tcp",
            "--dport", "80",
            "-j", "TARPIT",
        ])
        subprocess.run([
            "iptables",
            "-A", config.config.get('main', 'iptables_chain'),
            "-s", ip_address,
            "-p", "tcp",
            "--dport", "443",
            "-j", "TARPIT",
        ])

    @staticmethod
    def ban(
        ip_address: str,
        rts: RunTimeStats,
        config: Config,
    ) -> None:
        if ip_address in rts.banned_ips:
            rts.banned_ips[ip_address] = time.time()
            return
        rts.bans += 1
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
            return
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
        return

    @staticmethod
    def unban_expired(config: Config, rts: RunTimeStats) -> None:
        current_time = time.time()
        for ip in list(rts.banned_ips.keys()):
            if current_time - rts.banned_ips[ip] > config.config.getint('main', 'ban_time'):
                del rts.banned_ips[ip]
                if ":" in ip:
                    subprocess.run([
                        "ip6tables",
                        "-D", config.config.get('main', 'iptables_chain'),
                        "-s", ip,
                        "-p", "tcp",
                        "--dport", "80",
                        "-j", "DROP",
                    ])
                    subprocess.run([
                        "ip6tables",
                        "-D", config.config.get('main', 'iptables_chain'),
                        "-s", ip,
                        "-p", "tcp",
                        "--dport", "443",
                        "-j", "DROP",
                    ])
                else:
                    subprocess.run([
                        "iptables",
                        "-D", config.config.get('main', 'iptables_chain'),
                        "-s", ip,
                        "-p", "tcp",
                        "--dport", "80",
                        "-j", "DROP",
                    ])
                    subprocess.run([
                        "iptables",
                        "-D", config.config.get('main', 'iptables_chain'),
                        "-s", ip,
                        "-p", "tcp",
                        "--dport", "443",
                        "-j", "DROP",
                    ])
                # logger.debug(f"{ip} unbanned after {config.ban_time}s")
