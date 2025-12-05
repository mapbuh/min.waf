import requests
import yaml


class Config:
    # when reloading config, these keys will not be changed
    immutables: list[str] = ['mode', 'url_stats', 'ua_stats']
    config_file_path: str = ""
    columns: dict[str, int] = {
        "remote_addr": -1,
        "host": -1,
        "time_local": -1,
        "request": -1,
        "status": -1,
        "upstream_response_time": -1,
        "http_referer": -1,
        "http_user_agent": -1,
    }
    time_frame = 300
    debug: bool = False
    ban_time = 600
    url_stats = False
    ua_stats = False
    lockfile: str = "/var/run/min.waf.pid"
    detail_lines: int = 12
    refresh_time: int = 60
    whitelist_triggers: dict[str, list[dict[str, str]]] = {}
    log_file_path: str = ""
    good_bots: dict[str, list[str]] = {}
    bad_bots: dict[str, list[str]] = {}
    ignore_extensions: list[str] = []
    known_attacks: list[str] = []
    http_status_bad_threshold: float = 0.51
    proxy_listen_host: str = "127.0.0.1"
    proxy_listen_port: int = 9009
    # wait at list this many seconds between first and last request
    steal_over_time: int = 10
    # if total stolen time is more than this, consider it stealing
    steal_total: int = 10
    # if ratio of stolen/available time is more than this, consider it stealing
    steal_ratio: float = 0.3
    ip_blacklist: str = ''
    ip_blacklist_refresh_time: int = 3600
    iptables_chain: str = "MINWAF"
    mode: str = "proxy"  # or "log2ban"
    whitelist_expiration: int = 36000  # 10 hours, a working day plus few hours
    whitelist_permanent: str = ""  # path to permanent whitelist file
    profiling: bool = False  # enable profiling with yappi
    static_files: list[str] = [
        ".css",
        ".eot",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".js",
        ".json",
        ".mp3",
        ".mp4",
        ".ogg",
        ".otf",
        ".png",
        ".svg",
        ".ttf",
        ".txt",
        ".wav",
        ".webm",
        ".woff",
        ".woff2",
        ".xml",
    ]
    dynamic_files: list[str] = [
        ".asp",
        ".aspx",
        ".bin",
        ".cgi",
        ".dll",
        ".exe",
        ".jsp",
        ".php",
        ".pl",
        ".py",
        ".rb",
        ".sh",
    ]
    bots: dict[str, dict[str, str]] = {
        'Bing': {
            'user_agent': 'Bingbot',
            'ip_ranges_url': 'https://www.bing.com/toolbox/bingbot.json',
            'action': 'allow',
        },
        'DuckDuckGo': {
            'user_agent': 'DuckDuckBot',
            'ip_ranges_url': 'https://duckduckgo.com/duckduckbot.json',
            'action': 'allow',
        },
        'Google': {
            'user_agent': 'Google',
            'ip_ranges_url': 'https://developers.google.com/static/search/apis/ipranges/googlebot.json',
            'action': 'allow',
        },
        'OAI-GPTBot': {
            'user_agent': 'GPTBot',
            'ip_ranges_url': 'https://openai.com/gptbot.json',
            'action': 'allow',
        },
        'OAI-SearchBot': {
            'user_agent': 'OAI-SearchBot',
            'ip_ranges_url': 'https://openai.com/searchbot.json',
            'action': 'allow',
        },
    }
    whitelist_log: bool = False

    def __init__(self) -> None:
        pass

    def load(self, filepath: str) -> None:
        self.config_file_path = filepath
        with open(filepath, "r") as f:
            data = yaml.safe_load(f)
            for key, value in data.items():
                if hasattr(self, key):
                    if key in self.immutables:
                        continue
                    setattr(self, key, value)
        print(self.bots)
        for bot in self.bots:
            print(self.bots[bot])
        for bot, bot_data in self.bots.items():
            if 'ip_ranges_url' in bot_data:
                try:
                    Config.bots[bot]['ip_ranges'] = requests.get(bot_data['ip_ranges_url']).json().get('prefixes', [])
                except Exception as e:
                    print(f"Error fetching IP ranges for bot {bot}: {e}")
