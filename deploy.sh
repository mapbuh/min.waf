#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ -f "deploy.lock" ]]; then
    git pull -r
    cp min.waf.service /etc/systemd/system/min.waf.service
    systemctl daemon-reload
    systemctl restart min.waf.service
    rm "deploy.lock"
fi