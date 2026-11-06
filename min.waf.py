#!/usr/bin/env python3

import click
import logging

from classes.Config import Config
from classes.MinWaf import MinWaf


@click.command()
@click.option("--config", default="/etc/min.waf.conf", help="Path to config file")
@click.option("--port", type=int, default=None,
              help="Listen on this port instead of the config one; lockfile and iptables chain get the port as suffix")
def main(
    config: str,
    port: int | None,
) -> None:
    configObj: Config = Config(config, port)

    logger = logging.getLogger('min.waf')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    chformatter = logging.Formatter('%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    ch.setFormatter(chformatter)
    # add the handlers to logger
    logger.addHandler(ch)
    MinWaf(configObj)


if __name__ == "__main__":
    main()
