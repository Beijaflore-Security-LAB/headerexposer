#!/bin/env python3

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="headerexposer",
    version="0.8a15",
    author="Alexandre Janvrin",
    author_email="alexandre.janvrin@reseau.eseo.fr",
    description="Analyse the security of your website's headers!",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/LivinParadoX/headerexposer",
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: GNU Affero General Public License v3 or"
        " later (AGPLv3+)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Topic :: Education :: Testing",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
    ],
    keywords="http headers security analysis owasp recommendations best"
    " practices",
    python_requires=">=3.7",
    install_requires=[
        "ansiwrap",
        "colorama",
        "jsonschema",
        "requests",
        "tabulate",
        "urllib3",
    ],
    entry_points={
        "console_scripts": [
            "headerexposer=headerexposer.__main__:main",
        ],
    },
    include_package_data=True,
)
