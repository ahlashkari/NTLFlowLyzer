#!/usr/bin/env python3

try:
    from setuptools import setup
except ImportError as error:
    raise SystemExit(error)

version = "0.1.0"
author = "Moein Shafi"
author_email = "mosafer.moein@gmail.com"
entry_points = {
        "console_scripts": ["nlflowlyzer = NLFlowLyzer.__main__:main"]
        }

setup(
        name="NLFlowLyzer",
        version=version,
        author=author,
        author_email=author_email,
        packages=[
            "NLFlowLyzer",
            "NLFlowLyzer.features",
            "NLFlowLyzer.net_layer_flow_capturer",
            "NLFlowLyzer.writers",
        ],
        package_dir={
            "NLFlowLyzer": "NLFlowLyzer",
            "NLFlowLyzer.features": "NLFlowLyzer/features",
            "NLFlowLyzer.writers": "NLFlowLyzer/writers",
        },
        entry_points=entry_points,
)
