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

    logger = logging.getLogger('min.waf')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    chformatter = logging.Formatter('%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    ch.setFormatter(chformatter)
    # add the handlers to logger
    logger.addHandler(ch)
    MinWaf(configObj)


if __name__ == "__main__":
    main()
