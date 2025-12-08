
"""
Module to check for known attack patterns in request URLs.
would be expanded with more patterns over time.
Ideally we'll identify new patterns by:
    - frequent requests
    - status 404
    - different domains (should be more than 2)
    - different IPs (should be more than 2)
    - one ip checking several of these
    - should have dot in the name (otherwise we'll block /admin /blog etc which are legit)
    - exclude txt, jpg, png, css, js
"""


import logging
from classes.LogLine import LogLine
from classes.Config import Config


class KnownAttacks:
    @staticmethod
    def is_known(config: Config, log_line: LogLine) -> bool:
        if log_line.http_status not in [404, 500]:
            return False
        for attack in config.getlist('main', 'known_attacks'):
            if attack.lower() in log_line.req.lower():
                logging.info(f"{log_line.ip} banned; Known attack detected: {log_line.req}")
                return True
        return False
