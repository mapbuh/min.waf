import time
import sys

class PrintStats:
    column_1_width: int = 45
    column_2_width: int = 15
    column_3_width: int = 17

    @staticmethod
    def print_red(message, end = '\n'):
        sys.stdout.write('\x1b[1;31m' + message + '\x1b[0m' + end)

    @staticmethod
    def print_green(message, end = '\n'):
        sys.stdout.write('\x1b[1;32m' + message + '\x1b[0m' + end)

    @staticmethod
    def print_yellow(message, end = '\n'):
        sys.stderr.write('\x1b[1;33m' + message + '\x1b[0m' + end)

    @staticmethod
    def print_stats(config, banned_ips, ip_stats, status_by_ip_stats, referer_stats, times_by_url_stats, ua_stats) -> None:
        current_time = time.time()
        print("\033c", end="")  # Clear screen
        print(f"Running: {time.time() - config['start_time']:.2f} seconds  |  Parsed: {config['lines_parsed']} lines  |  Time frame: {config['time_frame']} seconds")
        print(f"{'IP Address':<{PrintStats.column_1_width}} {'Upstream Time':<{PrintStats.column_2_width}} {'Requests':<{PrintStats.column_3_width}}")
        print("=" * 100)

        # sort by total_time
        counter = 0
        for ip, stats in sorted(ip_stats.items(), key=lambda item: item[1]['total_time'], reverse=True):
            counter += 1
            if counter > config['detail_lines']:
                break
            message = f"{ip:<{PrintStats.column_1_width}.{PrintStats.column_1_width}} {stats['total_time']:>{PrintStats.column_2_width}.3f}/{stats['avail_time']:<15.3f} {stats['request_count']:5d}rq"
            if ip in banned_ips:
                PrintStats.print_red(message)
            elif stats['total_time'] > stats['avail_time'] * 0.5 and stats['request_count'] > 10:
                PrintStats.print_yellow(message)
            else:
                print(message)

        print()
        counter = 0
        for ip, data in sorted(status_by_ip_stats.items(), key=lambda item: (item[1]['bad_perc'], item[1]['count']), reverse=True):
            if counter > config['detail_lines']:
                break
            counter += 1
            message = f"{ip:<{PrintStats.column_1_width}.{PrintStats.column_1_width}} All: {data['count']:>10}, Bad http_status: {data['bad_perc']:>8.2f}%"
            if ip in banned_ips:
                PrintStats.print_red(message)
            elif data['bad_perc'] > 10.0:
                PrintStats.print_yellow(message)
            else:
                print(message)

        if config['referer_stats']:
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
            for url, stats in sorted(times_by_url_stats.items(), key=lambda item: item[1]['total_time'], reverse=True):
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

