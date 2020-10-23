#!/bin/env python3

import setuptools


with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="headerexposer",
    version="2020.10.dev1",
    author="Alexandre Janvrin",
    author_email="alexandre.janvrin@reseau.eseo.fr",
    description="Python3 cmd line tool to scan Security HTTP headers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/LivinParadoX/headerexposer",
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Information Technology",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Topic :: Education :: Testing",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security"
    ],
    python_requires='>=3.6',
)
