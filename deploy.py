#!/usr/bin/env python3

import hashlib
import hmac
import json
import os
import sys
import subprocess

SECRET_KEY = '#ffSVv4NohftC~YY'


def error_log(msg: str) -> None:
    sys.stderr.write(msg + '\n')


def get_header(name: str) -> str:
    # WSGI/Flask: HTTP headers are in environ as HTTP_<HEADER_NAME>
    return os.getenv('HTTP_' + name.upper().replace('-', '_'), '')


def main() -> None:
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
    try:
        result = subprocess.run(['git', 'pull', '-r'], capture_output=True, text=True, check=True)
        print('SUCCESS')
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        error_log(f'FAILED - git pull -r: {e.stderr}')
        sys.exit(1)


if __name__ == '__main__':
    main()
