import logging

'''
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
'''

class KnownAttacks:
    @staticmethod
    def is_known(req: str) -> bool:
        known_attacks = [
                "xmlrpc.php",
                "wp-login.php",
                "administrator/index.php",
                "user/login",
                "admin.php",
                "wp-admin",
                "phpmyadmin",
                "wp-content/plugins/hellopress/wp_filemanager.php",
                '/.env',
                '/app/',
                '/.git/config',
                '/info.php'
        ]
        req_lower = req.lower()
        for attack in known_attacks:
            if attack.lower() in req_lower:
                return True
        return False
