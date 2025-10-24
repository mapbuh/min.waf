import time
import sys
from typing import Any
from ExpiringDict import ExpiringDict

class PrintStats:
    column_1_width: int = 30
    column_2_width: int = 10
    column_3_width: int = 15
    column_4_width: int = 17
    column_5_width: int = 17
    column_6_width: int = 7

    @staticmethod
    def print_red(message: str, end: str = '\n'):
        sys.stdout.write('\x1b[1;31m' + message + '\x1b[0m' + end)

    @staticmethod
    def print_green(message: str, end: str = '\n'):
        sys.stdout.write('\x1b[1;32m' + message + '\x1b[0m' + end)

    @staticmethod
    def print_yellow(message: str, end: str = '\n'):
        sys.stderr.write('\x1b[1;33m' + message + '\x1b[0m' + end)

    @staticmethod
    def print_stats(config: dict[str, Any], banned_ips: dict[str, float], ip_stats: ExpiringDict, times_by_url_stats: dict[str, dict[str, Any]], ua_stats: dict[str, dict[str, Any]]) -> None:
        current_time = time.time()
        print("\033c", end="")  # Clear screen
        print(f"Running: {time.time() - config['start_time']:.2f} seconds  |  Parsed: {config['lines_parsed']} lines  |  Time frame: {config['time_frame']} seconds")
        print(
            f"{'IP Address':^{PrintStats.column_1_width}}|"
            f"{'Requests':^{PrintStats.column_2_width}}|"
            f"{'Upstream Time':^{PrintStats.column_3_width}}|"
            f"{'Bad HTTP Status':^{PrintStats.column_4_width}}|"
            f"{'HTTP Referes':^{PrintStats.column_5_width}}|"
            f"{'Score':^{PrintStats.column_6_width}}|"
        )
        print(
            f"{'':^{PrintStats.column_1_width}}|"
            f"{'':^{PrintStats.column_2_width}}|"
            f"{'':^{PrintStats.column_3_width}}|"
            f"{'':^{PrintStats.column_4_width}}|"
            f"{' unknown    none':<{PrintStats.column_5_width}}|"
            f"{'':^{PrintStats.column_6_width}}|"
        )
        print("=" * 127)

        # sort by total_time
        counter = 0
        for ip, stats in sorted(ip_stats.items(), key=lambda item: (item[1].score, item[1].request_count), reverse=True):
            counter += 1
            if counter > config['detail_lines']:
                break
            upstream_stats = f"{stats.total_time:.2f}/{int(stats.avail_time)}"
            status_stats = f"{stats.http_status_bad} ({stats.http_status_bad_perc:.2f}%)"
            referer_stats = f"{stats.referer['unrelated']:6d} {stats.referer['no_referer']:6d} "
            message = (f"{ip:<{PrintStats.column_1_width}.{PrintStats.column_1_width}}|"
                    f"{stats.request_count:>{PrintStats.column_2_width}d}|"
                    f"{upstream_stats:>{PrintStats.column_3_width}.{PrintStats.column_3_width}}|"
                    f"{status_stats:>{PrintStats.column_4_width}.{PrintStats.column_4_width}}|"
                    f"{referer_stats:>{PrintStats.column_5_width}.{PrintStats.column_5_width}}|"
                    f"{stats.score:>{PrintStats.column_6_width}.2f}|"
            )
            if ip in banned_ips:
                PrintStats.print_red(message)
            elif stats.score >= 1:
                PrintStats.print_yellow(message)
            else:
                print(message)

        print()
        counter = 0
        if False:
            for ip, data in sorted(ip_stats.items(), key=lambda item: (item[1]['http_status']['bad_perc'], item[1]['http_status']['count']), reverse=True):
                if counter > config['detail_lines']:
                    break
                counter += 1
                message = f"{ip:<{PrintStats.column_1_width}.{PrintStats.column_1_width}} All: {data['http_status']['count']:>10}, Bad http_status: {data['http_status']['bad_perc']:>8.2f}%"
                if ip in banned_ips:
                    PrintStats.print_red(message)
                elif data['http_status']['bad_perc'] > 10.0:
                    PrintStats.print_yellow(message)
                else:
                    print(message)

        if False and config['referer_stats']:
            print()
            counter = 0
            for ip, stats in sorted(referer_stats.items(), key=lambda item: int(item[1]['unrelated']) + int(item[1]['no_referer']), reverse=True):
                counter += 1
                if counter > config['detail_lines']:
                    break
                message = f"{ip:<{PrintStats.column_1_width}.{PrintStats.column_1_width}} Total: {stats['count']:>6}, No referer: {stats['no_referer']:>6}, Related: {stats['related']:>6}, Unrelated: {stats['unrelated']:>6}"
                if stats['unrelated'] > 0:
                    PrintStats.print_yellow(message)
                else:
                    print(message)

        if config['url_stats']:
            print()
            counter = 0
            for url, stats in sorted(times_by_url_stats.items(), key=lambda item: (item[1]['request_count'], item[1]['total_time']), reverse=True):
                counter += 1
                if counter > config['detail_lines']:
                    break
                message = f"{url:<100.100} Total: {stats['total_time']:>6.2f}, Avg: {stats['avg_time']:>6.2f}s {stats['request_count']:>6}rq"
                if stats['total_time'] > 1:
                    PrintStats.print_yellow(message)
                else:
                    print(message)

        if config['ua_stats']:
            print()
            counter = 0
            for ua, stats in sorted(ua_stats.items(), key=lambda item: item[1]['total_time'], reverse=True):
                #if stats['total_time'] < 1:
                #    continue
                counter += 1
                if counter > config['detail_lines']:
                    break
                message = f"{ua:<100.100} Total: {stats['total_time']:>6.2f}, Avg: {stats['avg_time']:>6.2f}s {stats['count']:>6}rq"
                if stats['total_time'] > 1:
                    PrintStats.print_yellow(message)
                else:
                    print(message)

        print()
        print("Banned: ", end="")
        for ip in banned_ips:
            print(f"{ip}({config['ban_time'] - (current_time - banned_ips[ip]):.0f}s)", end=', ')
        print()

