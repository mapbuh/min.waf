#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")" || exit

if [[ -f "/tmp/min.waf.deploy" ]]; then
    git pull -r
    cp min.waf.service /etc/systemd/system/min.waf.service
    systemctl daemon-reload
    systemctl restart min.waf.service
    rm "/tmp/min.waf.deploy"
fi