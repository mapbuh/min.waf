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
    logging.basicConfig(
        format="%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.DEBUG if configObj.config.getboolean("dev", "debug", fallback=False) else logging.INFO,
    )
    MinWaf(configObj)


if __name__ == "__main__":
    main()
