# min.waf - poor man's web application firewall

## About

min.waf is a simple firewall that will try to detect and stop malicious http requests.
Main goal is to have virtually no false positives and not to disrupt normal operations.

## Features

1. Can be used with nginx or Apache2 as the frontend proxy
2. Supports whitelist of bots and ip addresses 
3. Supports blacklist of bots and ip addresses
4. Supports list of known attack url patterns
5. Analyzes http statuses from given address and bans when given threshold is reached
6. Supports list of known bad user agents that are banned on sight
7. Performs deep packet inspection and guards against known sql inections, php exploits, node.js exploits (should catch react2shell and php2shell)
8. Analyzes long running responses from upstream and bans if certain threshold is reached by an ip address
9. Support whitelisting triggers: when authorized access is detected to certain url (HTTP status 200), the requester address is added to whitelist for that certain vhost

## Prerequisites

- Linux (min.waf uses epoll)
- Python 3.10 or newer
- Python packages: requests, click, yappi
- Nginx or Apache2 installed and running as a reverse proxy
- iptables (provides `iptables` and `ip6tables`) and ipset
- Root or sudo privileges

## Setup Steps

### 1. Download and Configure min.waf

1. Clone the repo somewhere convenient
```
git clone https://github.com/mapbuh/min.waf.git
```
2. Install the dependencies
```
apt install python3-requests python3-click python3-yappi iptables ipset
```
3. Create configuration using the examples and copy it to /etc/min.waf.conf
```
cp min.waf.conf-example /etc/min.waf.conf
```
4. Edit and copy min.waf.service to /etc/systemd/system/min.waf.service
```
cp min.waf.service /etc/systemd/system
```
5. Copy or make symlink to min.waf.py in /usr/sbin
```
ln -s /usr/local/min.waf/min.waf.py /usr/sbin/min.waf.py
```
6. Enable and start the service.
```
systemctl daemon-reload && systemctl enable --now min.waf.service
```

To run several instances from one config on different ports, use the `min.waf@.service` template instead. The instance name is the port:
```
cp min.waf@.service /etc/systemd/system
systemctl daemon-reload && systemctl enable --now min.waf@9009 min.waf@9010
```
Each instance overrides `port` with `--port` and gets its own lockfile (`/var/run/min.waf-<port>.pid`).

#### Bans

Banned IPs go into an ipset (`minwaf`, plus `minwaf6` for IPv6) that a single INPUT rule drops on ports 80 and 443. All instances share the sets, and the kernel expires entries after `ban_time`, so restarting an instance keeps everyone's bans. The sets and rules are left in place when min.waf stops; to remove them:
```
iptables -D INPUT -m set --match-set minwaf src -p tcp -m multiport --dports 80,443 -j DROP
ip6tables -D INPUT -m set --match-set minwaf6 src -p tcp -m multiport --dports 80,443 -j DROP
ipset destroy minwaf; ipset destroy minwaf6
```

### 2. Configure the frontend proxy

min.waf requires the frontend proxy to inject two headers:
- `X-Real-IP` — the real client IP address
- `MinWaf-Dest` — the upstream address min.waf should forward the request to (e.g. `127.0.0.1:8080`)

#### Nginx

Configure each virtual host to proxy through min.waf. Copy the old `proxy_pass` destination to `MinWaf-Dest`, then point `proxy_pass` at min.waf:

```nginx
location / {
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header MinWaf-Dest <upstream address or hostname>:80;
    proxy_pass http://127.0.0.1:9009;
}
```

#### Apache2

Enable the required modules:

```bash
a2enmod proxy proxy_http headers ssl
```

Configure each virtual host:

```apache
<VirtualHost *:443>
    ServerName example.com

    # TLS config here ...

    RequestHeader set X-Real-IP "%{REMOTE_ADDR}s"
    RequestHeader set MinWaf-Dest "127.0.0.1:8080"

    ProxyPass / http://127.0.0.1:9009/ disablereuse=On
    ProxyPassReverse / http://127.0.0.1:9009/
</VirtualHost>
```

> **Note:** min.waf checks only the first request on a connection, so it asks the app to close the connection after each response. `disablereuse=On` also stops Apache from reusing backend connections, in case the app keeps them open anyway.

> **Note:** If Apache2 itself sits behind another proxy (e.g. a CDN), use `%{HTTP:X-Forwarded-For}e` instead of `%{REMOTE_ADDR}s` to preserve the real client IP.

## Connection timeouts

The `[main]` settings `connect_timeout` (default 10 seconds) and
`connection_idle_timeout` (default 60 seconds) release workers when upstream
connections cannot be established or a relay has no socket activity. Increase
`connection_idle_timeout` if your application needs longer silent responses,
long polling, or idle WebSockets. Active transfers can continue beyond this
interval. Request headers must arrive within 5 seconds.

## Diagram

```
[Client] → [Nginx or Apache2:443] → [min.waf:9009] → [App]
```
