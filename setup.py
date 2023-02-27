#!/usr/bin/env python3

try:
    from setuptools import setup
except ImportError as error:
    raise SystemExit(error)

version = "0.1.0"
author = "Moein Shafi"
author_email = "mosafer.moein@gmail.com"
entry_points = {
        "console_scripts": ["net-flow-meter = NetFlowMeter.__main__:main"]
        }

setup(
        name="NetFlowMeter",
        version=version,
        author=author,
        author_email=author_email,
        packages=[
            "NetFlowMeter",
            "NetFlowMeter.features",
            "NetFlowMeter.net_flow_capturer",
            "NetFlowMeter.writers",
        ],
        package_dir={
            "NetFlowMeter": "NetFlowMeter",
            "NetFlowMeter.features": "NetFlowMeter/features",
            "NetFlowMeter.writers": "NetFlowMeter/writers",
        },
        entry_points=entry_points,
)
