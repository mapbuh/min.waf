#!/usr/bin/env python3

import logging
import os
import click

from classes.Config import Config
from classes.MinWaf import MinWaf


@click.command()
@click.option("--config", default="/etc/min.waf.conf", help="Path to config file")
def main(
    config: str,
) -> None:
    configObj: Config = Config(config)

    log_dir = configObj.config.get('main', 'log_dir')
    if not log_dir:
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "/log")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    logger = logging.getLogger('min.waf')
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(os.path.join(log_dir, 'min.waf.log'))
    fh.setLevel(logging.DEBUG)
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    # add the handlers to logger
    logger.addHandler(ch)
    logger.addHandler(fh)
    MinWaf(configObj)


if __name__ == "__main__":
    main()
