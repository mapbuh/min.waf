#!/usr/bin/env python3

import hashlib
import hmac
import json
import os
import pathlib
import sys
import time

SECRET_KEY = '#ffSVv4NohftC~YY'


def error_log(msg: str) -> None:
    sys.stderr.write(msg + '\n')


def get_header(name: str) -> str:
    # WSGI/Flask: HTTP headers are in environ as HTTP_<HEADER_NAME>
    return os.environ.get('HTTP_' + name.upper().replace('-', '_'), '')


def main() -> None:
    # Check for POST request
    request_method = os.environ.get('REQUEST_METHOD', '')
    if request_method != 'POST':
        error_log(f'FAILED - not POST - {request_method}')
        sys.exit(1)

    # Get content type
    content_type = os.environ.get('CONTENT_TYPE', '').strip().lower()
    if content_type != 'application/json':
        error_log(f'FAILED - not application/json - {content_type}')
        sys.exit(1)

    # Get payload
    payload = sys.stdin.read().strip()
    if not payload:
        error_log('FAILED - no payload')
        sys.exit(1)

    # Get header signature
    header_signature = get_header('X_GITEA_SIGNATURE')
    if not header_signature:
        error_log('FAILED - header signature missing')
        sys.exit(1)

    # Calculate payload signature
    payload_signature = hmac.new(
        SECRET_KEY.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    # Check payload signature against header signature
    if header_signature != payload_signature:
        error_log('FAILED - payload signature')
        sys.exit(1)

    # Convert json to dict
    try:
        decoded = json.loads(payload)
        sys.stderr.write(f'DEBUG - decoded payload: {decoded}\n')
    except json.JSONDecodeError as e:
        error_log(f'FAILED - json decode - {e}')
        sys.exit(1)

    # success, do something
    with pathlib.Path("/tmp/min.waf.deploy").open("w") as lock_file:
        lock_file.write(str(time.time()))
        sys.stderr.write('deploy scheduled\n')


if __name__ == '__main__':
    main()
