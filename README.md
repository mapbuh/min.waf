# min.waf - poor man's web application firewall

## About

min.waf is a simple firewall that will detect http probing and flooding and will filter further requests to the host.

## Features

1. Can be used with nginx with proxy_pass or reading access.log in real time
2. Can read external list of IP addresses to ban at the moment they make request
3. Supports local list of malicious url patterns
4. Analyzes http statuses and bans users with more than 75% negative responses
5. Detects addresses that frequently request long running urls and bans them (currently only logs them, needs finer tuning)
6. Support whitelisting triggers: when authorized access is detected to certain url (HTTP status 200), the requester address is added to whitelist for that certain vhost

## Prerequisites

- Nginx installed and running as a reverse proxy
- min.waf 
- Root or sudo privileges

## Setup Steps

### 1. Download and Configure min.waf

1. Clone the repo somewhere convenient
2. Create configuration using the examples and copy it to /etc/min.waf.yaml
3. Edit and copy min.waf.service to /etc/systemd/system/min.waf.service
4. systemctl daemon-reload ; systemctl enable --now min.waf.service
5. Configure each nginx virtual host to use min.waf between nginx and the upstream:
```
        location / {
            ...
                # this is important to have, min.waf will use it
                proxy_set_header        X-Real-IP $remote_addr;
                # tell min.waf where to forward it after processing
		        proxy_set_header 	    MinWaf-Dest <upstream address or hostname>:80;
		        proxy_pass 		        http://127.0.0.1:9009;
        }
```

**Example `minwaf.conf`:**
```yaml
proxy_listen_host: 127.0.0.1
proxy_listen_port: 9009
```

## Diagram

```
[Client] → [Nginx:443] → [min.waf:9009] → [App]
```
