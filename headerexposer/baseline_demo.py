#!/usr/bin/env python3

import headerexposer

"""
This function showcases the module and shows what would be printed after
analysing example headers with the selected baseline.
"""

baseline = headerexposer.load_baseline("baseline.json")

example_headers = {
        "Strict-Transport-Security": [
            "max-age=31536000; includeSubDomains",
            "max-age=potato; includeSubDomains",
            "max-age=-5",
            "max-age=25.8; preload",
            "max-age=212; includeSubDomains; preload",
            "max-age=0",
            "max-age=31536000; includeSubDomains; preload"
            ]
        }

nice_ratings = {
        "good":   headerexposer.special_to_ansi("[green][ＧＯＯＤ][normal]"),
        "medium": headerexposer.special_to_ansi("[yellow][ＭＥＤ][normal]"),
        "bad":    headerexposer.special_to_ansi("[red][ＢＡＤ][normal]")
    }

findings = []
for name, example_values in example_headers.items():
    for header in baseline["headers"]:
        if header["name"] == name:
            b_header = header
    for value in example_values:
        rating, explanations = headerexposer.analyse_header(value, b_header)
        findings += [{
                "header": name,
                "value": value,
                "rating": nice_ratings[rating],
                "explanations": explanations,
                "references": []
                }]

print(headerexposer.tabulate_findings(findings))

"""
"X-Frame-Options": "DENY"
"X-Frame-Options": "Gloubiboulga"
"X-Frame-Options": "ALLOW-FROM china"
"X-Frame-Options": "SAMEORIGIN"
"X-Frame-Options": "DENIS"
"X-Frame-Options": "SAMEORANGINA"
"""
