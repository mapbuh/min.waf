#!/usr/bin/env python3

import click

from Config import Config
from MinWafLog import MinWafLog
from MinWafProxy import MinWafProxy


@click.command()
@click.option("--config", default="/etc/min.waf.yaml", help="Path to config file")
@click.option(
    "--time-frame",
    default=300,
    help="Time frame in seconds to analyze logs (default: 300)",
)
@click.option(
    "--ban-time",
    default=600,
    help="Ban time in seconds for IP addresses (default: 600)",
)
@click.option("--background", is_flag=True, default=None, help="Run in background (daemon mode)")
@click.option("--proxy", is_flag=True, default=None, help="Run as a proxy server")
@click.option("--url-stats", is_flag=True, default=None, help="Show URL stats")
@click.option("--ua-stats", is_flag=True, default=None, help="Show User-Agent stats")
@click.option(
    "--refresh-time", default=None, help="Screen refresh time in seconds (default: 1)"
)
@click.option("--silent", is_flag=True, default=None, help="Silent mode, no output to console")
def main(
    config: str,
    time_frame: int | None,
    ban_time: int | None,
    background: bool | None,
    proxy: bool | None,
    url_stats: bool | None,
    ua_stats: bool | None,
    refresh_time: int | None,
    silent: bool | None,
):
    configObj: Config = Config()
    # Load config file
    configObj.load(config)
    if time_frame is not None:
        configObj.time_frame = time_frame
    if ban_time is not None:
        configObj.ban_time = ban_time
    if background is not None:
        configObj.background = background
    if url_stats is not None:
        configObj.url_stats = url_stats
    if ua_stats is not None:
        configObj.ua_stats = ua_stats
    if refresh_time is not None:
        configObj.refresh_time = refresh_time
    if silent is not None:
        configObj.silent = silent
    if proxy is not None:
        configObj.proxy = proxy

    min_waf: MinWafLog | MinWafProxy
    if configObj.proxy:
        min_waf = MinWafProxy(configObj)
    else:
        min_waf = MinWafLog(configObj)

    min_waf.init()
    min_waf.run()


if __name__ == "__main__":
    main()
