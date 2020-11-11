#!/usr/bin/env python3

import __init__ as he


def baseline_demo(baseline):
    """
    This function showcases the module and shows what would be printed after
    analysing example headers with the selected baseline.
    """

    example_headers = {
        "Strict-Transport-Security": [
            "max-age=31536000; includeSubDomains",
            "max-age=potato; includeSubDomains",
            "max-age=-5",
            "max-age=25.8; preload",
            "max-age=212; includeSubDomains; preload",
            "max-age=0",
            "max-age=0; preload",
            "max-age=31536000; includeSubDomains; preload",
            "max-age=31536000",
        ],
        "X-Frame-Options": [
            "DENY",
            "DENIS",
            "Gloubiboulga",
            "ALLOW-FROM China",
            "SAMEORIGIN",
            "SAMEORANGINA",
        ],
        "X-Content-Type-Options": [
            "potato",
            "nosniff",
            "nosnifff",
            "potato; nosniff",
            "yes, sniff",
            "nosniff 67 21",
        ],
        "Content-Security-Policy": ["potato"],
        "X-Permitted-Cross-Domain-Policies": [
            "none",
            "master-only",
            "by-content-type",
            "by-ftp-filename",
            "all",
            "potato"
        ],
        "Referrer-Policy": [
            "no-referrer",
            "potatno-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "original",
            "origin-when-cross-origin",
            "origin-when-potato-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url",
            "",
            "strict-origin-when-cross-origin, unsafe-url",
            "unsafe-url, strict-origin-when-cross-origin",
            "strict-origin-when-cross-origin, no-referrer",
            "no-referrer, no-referrer, no-referrer, unsafe-url",
            "no-referrer, no-referrer, strict-origin-when-cross-origin,"
            " no-referrer, unsafe-url"
        ]
    }

    nice_ratings = {
        "good": he.special_to_ansi("[green][ＧＯＯＤ][normal]"),
        "medium": he.special_to_ansi("[yellow][ＭＥＤ][normal]"),
        "bad": he.special_to_ansi("[red][ＢＡＤ][normal]"),
    }

    print(
        he.special_to_ansi(
            "\n[blue]Example of full output with empty headers:[normal]"
        )
    )
    findings = he.analyse_headers({}, baseline)
    print(he.tabulate_findings(findings))

    print(
        he.special_to_ansi(
            "\n\n[blue]Example output with empty headers and"
            " --short argument:[normal]"
        )
    )
    findings = he.analyse_headers({}, baseline, short=True)
    print(he.tabulate_findings(findings))

    print(
        he.special_to_ansi(
            "\n\n[blue]Example output with empty headers and --short"
            " --no-explanation-colors argument:[normal]"
        )
    )
    colorless_baseline = he.load_baseline("baseline.json", no_colors=True)
    findings = he.analyse_headers({}, colorless_baseline, short=True)
    print(he.tabulate_findings(findings))

    print(
        he.special_to_ansi(
            "\n\n[blue]Example output with various header values and"
            " --short argument:[normal]"
        )
    )

    findings = []
    for name, example_values in example_headers.items():
        for header in baseline["headers"]:
            if header["name"] == name:
                b_header = header
        for value in example_values:
            rating, explanations = he.analyse_header(value, b_header)
            findings += [
                {
                    "header": name,
                    "value": value,
                    "rating": nice_ratings[rating],
                    "explanations": explanations,
                    "references": [],
                }
            ]

    print(he.tabulate_findings(findings))
