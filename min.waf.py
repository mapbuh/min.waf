#!/usr/bin/env python3

import click

from Config import Config
from MinWafLog import MinWafLog
from MinWafProxy import MinWafProxy


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
):
    configObj: Config = Config()
    # Load config file
    configObj.load(config)
    if url_stats is not None:
        configObj.url_stats = url_stats
        configObj.immutables.append("url_stats")
    if ua_stats is not None:
        configObj.ua_stats = ua_stats
        configObj.immutables.append("ua_stats")
    if log2ban is not None:
        configObj.mode = "log2ban"
        configObj.immutables.append("mode")
    if interactive is not None:
        configObj.mode = 'interactive'
        configObj.immutables.append("mode")

    min_waf: MinWafLog | MinWafProxy
    if configObj.mode == "log2ban" or configObj.mode == "interactive":
        min_waf = MinWafLog(configObj)
    else:
        min_waf = MinWafProxy(configObj)
    min_waf.init()
    min_waf.run()


if __name__ == "__main__":
    main()
