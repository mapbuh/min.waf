class Config:
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
    ban_time = 600
    background = False
    url_stats = False
    ua_stats = False
    referer_stats = False
    lockfile: str = "/var/run/min.waf.lock"
    detail_lines: int = 12
    refresh_time: int = 60
    whitelist_triggers: dict[str, list[dict[str, str]]] = {
        'www.gift-tube.com': [
            {
                'path': '/adming/dashboards/main',
                'http_status': '200',
            },
            {
                'path': '/nova-api/nova-notifications',
                'http_status': '200',
            },
        ],
        'partner.gift-tube.com': [
            {
                'path': '/api/fiscal/pending',
                'http_status': '200',
            },
        ],
    }
