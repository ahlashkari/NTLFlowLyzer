#!/usr/bin/env python3

import setuptools

with open(file="README.md", mode="r", encoding="utf8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="NTLFlowLyzer",
    version="0.1.0",
    author="Moein Shafi",
    author_email="moeinsh@yorku.ca",
    description="The Network and Transport Layer Flow Analyzer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ahlashkari/NTLFlowLyzer",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: York University",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    entry_points={
        "console_scripts": ["ntlflowlyzer = NTLFlowLyzer.__main__:main"]
    },
)
