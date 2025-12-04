#!/usr/bin/env python3

import logging
import click

from classes.Config import Config
from classes.MinWafLog import MinWafLog
from classes.MinWafProxy import MinWafProxy


@click.command()
@click.option("--config", default="/etc/min.waf.yaml", help="Path to config file")
@click.option("--log2ban", is_flag=True, default=None, help="Read logs instead of proxy mode")
@click.option("--interactive", is_flag=True, default=None, help="Interactive mode, read logs")
@click.option("--url-stats", is_flag=True, default=None, help="Show URL stats")
@click.option("--ua-stats", is_flag=True, default=None, help="Show User-Agent stats")
def main(
    config: str,
    log2ban: bool | None,
    interactive: bool | None,
    url_stats: bool | None,
    ua_stats: bool | None,
) -> None:
    configObj: Config = Config()
    # Load config file
    configObj.load(config)
    if url_stats is not None:
        configObj.url_stats = url_stats
    if ua_stats is not None:
        configObj.ua_stats = ua_stats
    if log2ban is not None:
        configObj.mode = "log2ban"
    if interactive is not None:
        configObj.mode = 'interactive'
    logging.basicConfig(
        format="%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.DEBUG if configObj.debug else logging.INFO,
    )
    logging.getLogger("inotify").setLevel(logging.WARNING)

    min_waf: MinWafLog | MinWafProxy
    if configObj.mode == "log2ban" or configObj.mode == "interactive":
        min_waf = MinWafLog(configObj)
    else:
        min_waf = MinWafProxy(configObj)
    min_waf.run()


if __name__ == "__main__":
    main()
