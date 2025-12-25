#!/usr/bin/env python3

import click
import logging

from classes.Config import Config
from classes.MinWaf import MinWaf


@click.command()
@click.option("--config", default="/etc/min.waf.conf", help="Path to config file")
def main(
    config: str,
) -> None:
    configObj: Config = Config(config)

    log_file = configObj.config.get('log', 'file')
    logger = logging.getLogger('min.waf')
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    # create formatter and add it to the handlers
    chformatter = logging.Formatter('%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fhformatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    ch.setFormatter(chformatter)
    fh.setFormatter(fhformatter)
    # add the handlers to logger
    logger.addHandler(ch)
    logger.addHandler(fh)
    MinWaf(configObj)


if __name__ == "__main__":
    main()
