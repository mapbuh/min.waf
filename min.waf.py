#!/usr/bin/env python3

import click

from Config import Config
from MinWafLog import MinWafLog
from MinWafProxy import MinWafProxy


@click.command()
@click.option("--config", default="/etc/min.waf.yaml", help="Path to config file")
@click.option("--background", is_flag=True, default=None, help="Run in background (daemon mode)")
@click.option("--proxy", is_flag=True, default=None, help="Run as a proxy server")
@click.option("--url-stats", is_flag=True, default=None, help="Show URL stats")
@click.option("--ua-stats", is_flag=True, default=None, help="Show User-Agent stats")
@click.option("--silent", is_flag=True, default=None, help="Silent mode, no output to console")
def main(
    config: str,
    background: bool | None,
    proxy: bool | None,
    url_stats: bool | None,
    ua_stats: bool | None,
    silent: bool | None,
):
    configObj: Config = Config()
    # Load config file
    configObj.load(config)
    if background is not None:
        configObj.background = background
        configObj.immutables.append("background")
    if url_stats is not None:
        configObj.url_stats = url_stats
        configObj.immutables.append("url_stats")
    if ua_stats is not None:
        configObj.ua_stats = ua_stats
        configObj.immutables.append("ua_stats")
    if silent is not None:
        configObj.silent = silent
        configObj.immutables.append("silent")
    if proxy is not None:
        configObj.proxy = proxy
        configObj.immutables.append("proxy")

    min_waf: MinWafLog | MinWafProxy
    if configObj.proxy:
        min_waf = MinWafProxy(configObj)
    else:
        min_waf = MinWafLog(configObj)
    min_waf.init()
    min_waf.run()


if __name__ == "__main__":
    main()
