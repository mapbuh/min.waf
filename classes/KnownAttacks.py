
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
from classes.Config import Config
from classes.HttpHeaders import HttpHeaders


class KnownAttacks:
    @staticmethod
    def is_known(config: Config, httpHeaders: HttpHeaders) -> bool:
        logger = logging.getLogger("min.waf")
        if httpHeaders.http_status not in [404, 500]:
            return False
        for attack in config.getlist('main', 'known_attacks'):
            if attack.lower() in httpHeaders.req.lower():
                logger.info(f"{httpHeaders.ip} banned; Known attack detected: {httpHeaders.req}")
                return True
        return False
