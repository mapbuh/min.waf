import time
import sys
from typing import Any
from ExpiringDict import ExpiringDict
from IpData import IpData


class PrintStats:
    column_1_width: int = 105
    column_2_width: int = 10
    column_3_width: int = 15
    column_4_width: int = 17
    column_5_width: int = 17
    column_6_width: int = 7

    @staticmethod
    def print_red(message: str, end: str = "\n"):
        sys.stdout.write("\x1b[1;31m" + message + "\x1b[0m" + end)

    @staticmethod
    def print_green(message: str, end: str = "\n"):
        sys.stdout.write("\x1b[1;32m" + message + "\x1b[0m" + end)

    @staticmethod
    def print_yellow(message: str, end: str = "\n"):
        sys.stderr.write("\x1b[1;33m" + message + "\x1b[0m" + end)

    @staticmethod
    def msg_red(message: str) -> str:
        return ("\x1b[1;31m" + message + "\x1b[0m")
    
    @staticmethod
    def msg_green(message: str) -> str:
        return ("\x1b[1;32m" + message + "\x1b[0m")
    
    @staticmethod
    def msg_yellow(message: str) -> str:
        return ("\x1b[1;33m" + message + "\x1b[0m")

    @staticmethod
    def print_stats(
        config: dict[str, Any],
        banned_ips: dict[str, float],
        ip_stats: ExpiringDict[IpData],
        url_stats: ExpiringDict[IpData],
        ua_stats: ExpiringDict[IpData]
    ) -> None:
        start_time = time.time()
        output = ""
        output += "\033c"  # Clear screen
        running_time = f"Running: {time.time() - config['start_time']:.2f} seconds, Total Bans: {config['bans']}"
        parsed_lines = f"Parsed: {config['lines_parsed']} lines"
        time_frame = f"Time frame: {config['time_frame']} seconds"
        output += (
            f"{running_time:^{PrintStats.column_1_width}.{PrintStats.column_1_width}}|"
            f"{parsed_lines:^{PrintStats.column_2_width + PrintStats.column_3_width}.{PrintStats.column_2_width + PrintStats.column_3_width}} |"
            f"{time_frame:^{PrintStats.column_4_width + PrintStats.column_5_width + PrintStats.column_6_width}.{PrintStats.column_4_width + PrintStats.column_5_width + PrintStats.column_6_width}}  |\n"
        )
        output += "-" * (PrintStats.column_1_width + PrintStats.column_2_width + PrintStats.column_3_width + PrintStats.column_4_width + PrintStats.column_5_width + PrintStats.column_6_width + 6)
        output += "\n"
        output += (
            f"{'IP Address':^{PrintStats.column_1_width}}|"
            f"{'Requests':^{PrintStats.column_2_width}}|"
            f"{'Upstream Time':^{PrintStats.column_3_width}}|"
            f"{'Bad HTTP Status':^{PrintStats.column_4_width}}|"
            f"{'HTTP Referes':^{PrintStats.column_5_width}}|"
            f"{'Score':^{PrintStats.column_6_width}}|\n"
        )
        output += (
            f"{'':^{PrintStats.column_1_width}}|"
            f"{'':^{PrintStats.column_2_width}}|"
            f"{'':^{PrintStats.column_3_width}}|"
            f"{'':^{PrintStats.column_4_width}}|"
            f"{' unknown    none':<{PrintStats.column_5_width}}|"
            f"{'':^{PrintStats.column_6_width}}|\n"
        )
        output += ("=" * (PrintStats.column_1_width + PrintStats.column_2_width + PrintStats.column_3_width + PrintStats.column_4_width + PrintStats.column_5_width + PrintStats.column_6_width + 6))
        output += "\n"

        # sort by total_time
        counter = 0
        for ip, stats in sorted(
            ip_stats.items(),
            key=lambda item: (item[1].score, item[1].total_time),
            reverse=True,
        ):
            counter += 1
            if counter > config["detail_lines"]:
                break
            upstream_stats = f"{stats.total_time:.2f}/{int(stats.avail_time)}"
            status_stats = (
                f"{stats.http_status_bad:.2f} ({stats.http_status_bad:.2f}%)"
            )
            referer_stats = ""        
            message = (
                f"{ip:<{PrintStats.column_1_width}.{PrintStats.column_1_width}}|"
                f"{stats.request_count:>{PrintStats.column_2_width}d}|"
                f"{upstream_stats:>{PrintStats.column_3_width}.{PrintStats.column_3_width}}|"
                f"{status_stats:>{PrintStats.column_4_width}.{PrintStats.column_4_width}}|"
                f"{referer_stats:>{PrintStats.column_5_width}.{PrintStats.column_5_width}}|"
                f"{stats.score:>{PrintStats.column_6_width}.2f}|"
            )
            if ip in banned_ips:
                output += PrintStats.msg_red(message)
#            elif stats.score >= 1:
            elif stats.request_count >= 1:
                output += PrintStats.msg_yellow(message)
            else:
                output += (message)
            output += "\n"


        if config["url_stats"]:
            output += ("=" * (PrintStats.column_1_width + PrintStats.column_2_width + PrintStats.column_3_width + PrintStats.column_4_width + PrintStats.column_5_width + PrintStats.column_6_width + 6))
            output += "\n"
            counter = 0
            for url, stats in sorted(
                url_stats.items(),
                key=lambda item: (item[1].total_time, item[1].total_time),
                reverse=True,
            ):
                counter += 1
                if counter > config["detail_lines"]:
                    break
                upstream_stats = f"{stats.total_time:.2f}/{int(stats.avail_time)}"
                status_stats = (
                    f"{stats.http_status_bad:.2f} ({stats.http_status_bad:.2f}%)"
                )
                referer_stats = ""
                message = (
                    f"{url:<{PrintStats.column_1_width}.{PrintStats.column_1_width}}|"
                    f"{stats.request_count:>{PrintStats.column_2_width}d}|"
                    f"{upstream_stats:>{PrintStats.column_3_width}.{PrintStats.column_3_width}}|"
                    f"{status_stats:>{PrintStats.column_4_width}.{PrintStats.column_4_width}}|"
                    f"{referer_stats:>{PrintStats.column_5_width}.{PrintStats.column_5_width}}|"
                    f"{stats.score:>{PrintStats.column_6_width}.2f}|"
                )
                if stats.total_time > 1:
                    output += PrintStats.msg_yellow(message)
                else:
                    output += (message)
                output += "\n"

        if config["ua_stats"]:
            output += ("=" * (PrintStats.column_1_width + PrintStats.column_2_width + PrintStats.column_3_width + PrintStats.column_4_width + PrintStats.column_5_width + PrintStats.column_6_width + 6))
            output += "\n"
            counter = 0
            for ua, stats in sorted(
                ua_stats.items(), key=lambda item: item[1].score, reverse=True
            ):
                counter += 1
                if counter > config["detail_lines"]:
                    break
                upstream_stats = f"{stats.total_time:.2f}/{int(stats.avail_time)}"
                status_stats = (
                    f"{stats.http_status_bad:.2f} ({stats.http_status_bad:.2f}%)"
                )
                referer_stats = ""
                message = (
                    f"{ua:<{PrintStats.column_1_width}.{PrintStats.column_1_width}}|"
                    f"{stats.request_count:>{PrintStats.column_2_width}d}|"
                    f"{upstream_stats:>{PrintStats.column_3_width}.{PrintStats.column_3_width}}|"
                    f"{status_stats:>{PrintStats.column_4_width}.{PrintStats.column_4_width}}|"
                    f"{referer_stats:>{PrintStats.column_5_width}.{PrintStats.column_5_width}}|"
                    f"{stats.score:>{PrintStats.column_6_width}.2f}|"
                )
                if stats.total_time > 1:
                    output += PrintStats.msg_yellow(message)
                else:
                    output += (message)
                output += "\n"

        output += "\n"
        output += "Banned: "
        output += ", ".join(ip for ip in banned_ips.keys())
        output += "\n"
        output += f"Time taken to generate stats: {time.time() - start_time:.4f} seconds\n"
        print(output)
        sys.stdout.flush()
