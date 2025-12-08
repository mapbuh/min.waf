#!/usr/bin/env python3

import logging
import click

from classes.Config import Config
from classes.MinWaf import MinWaf


@click.command()
@click.option("--config", default="/etc/min.waf.conf", help="Path to config file")
def main(
    config: str,
) -> None:
    configObj: Config = Config(config)

    logger = logging.getLogger("min.waf")
    logger.setLevel(logging.DEBUG if configObj.config.getboolean('dev', 'debug') else logging.INFO)

    MinWaf(configObj)


if __name__ == "__main__":
    main()
