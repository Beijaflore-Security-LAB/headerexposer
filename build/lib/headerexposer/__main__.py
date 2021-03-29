#!/usr/bin/env python3

"""CLI to the HeaderExposer module."""

import argparse
import shutil
from importlib import resources

import requests
import urllib3  # type: ignore

import headerexposer as he  # type: ignore

BANNER = "".join(
    [
        "\n \033[1;94m┌───────────────────────────────\033[37m───────────────",
        "─\033[90m─────┐\n \033[94m│░█░█░█▀\033[34m▀░█▀█░█▀▄░█▀▀░█▀\033[37m▄░",
        "█▀▀░█░█░█▀█░█▀\033[90m█░█▀▀░█▀▀░█▀▄│\n \033[34m│░█▀█░█▀▀░█▀█░█░\033[",
        "37m█░█▀▀░█▀▄░█▀▀░▄▀\033[90m▄░█▀▀░█░█░▀▀█░█▀\033[94m▀░█▀▄│\n \033[34m",
        "│░▀░▀░▀▀\033[37m▀░▀░▀░▀▀░░▀▀▀░▀░\033[90m▀░▀▀▀░▀░▀░▀░░░▀▀\033[94m▀░▀▀",
        "▀░▀▀▀░▀░▀│\n \033[37m└───────────────\033[90m────────────────\033[94",
        "m────────────────\033[34m─────┘\033[0m\n",
    ]
)


def analyse(args, baseline):
    """Analyse a website's headers."""
    request_arguments = {
        "method": args.method,
        "url": args.url,
        "params": he.parse_request_parameters(args.params),
        "data": None,
        "headers": he.parse_request_headers(args.headers),
        "cookies": he.parse_request_cookies(args.cookies),
        "auth": None,
        "timeout": args.timeout,
        "allow_redirects": not args.disallow_redirects,
        "proxies": {"http": args.proxy, "https": args.proxy},
        "verify": args.verify,
        "cert": args.cert,
    }

    if args.data is not None:
        request_arguments["data"] = args.data.encode()

    elif args.file is not None:
        with open(args.file, "rb") as data_file:
            request_arguments["data"] = data_file.read()

    if args.user_agent is not None:
        request_arguments["headers"]["User-Agent"] = args.user_agent

    if args.username is not None and args.password is not None:
        request_arguments["auth"] = (args.username, args.password)

    if not args.short:
        he.print_special("[blue]Request parameters:[normal]")
        print(he.tabulate_dict(request_arguments, args.max_width))

    if not args.verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    response = requests.request(**request_arguments)

    if not args.short:
        he.print_special("\n[blue]Response:[normal]")

        print(
            he.tabulate_dict(
                {
                    "Length": len(response.content),
                    "Status Code": response.status_code,
                    "Reason": response.reason,
                },
                args.max_width,
            )
        )

    if not args.short:
        he.print_special("\n[blue]Response headers:[normal]")
        print(he.tabulate_dict(response.headers, args.max_width))

    findings = he.analyse_headers(response.headers, baseline, args.short)

    he.print_special("\n[blue]Headers analysis:[normal]")
    print(he.tabulate_findings(findings, args.max_width))


def baseline_demo(args, baseline):
    """Show analysis of sample headers.

    Showcases the module and shows what would be printed after
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
            "potato",
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
            " no-referrer, unsafe-url",
        ],
    }

    nice_ratings = {
        "good": he.special_to_ansi("[green][G O O D][normal]"),
        "medium": he.special_to_ansi("[yellow][M E D][normal]"),
        "bad": he.special_to_ansi("[red][B A D][normal]"),
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
    colorless_baseline = he.load_baseline(args.baseline_path, no_colors=True)
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

        b_header = None

        for header in baseline["headers"]:
            if header["name"] == name:
                b_header = header
                break

        if b_header is not None:
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


def show_baseline(args, baseline):
    """TODO."""
    del args, baseline
    print("WIP! This function is not currently implemented. Stay tuned!")


def main():
    """Only called when the module is called directly as a script."""
    main_parser = argparse.ArgumentParser(
        prog="headerexposer",
        description=f"{BANNER}\nAnalyse the security of your website's"
        " headers!",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="If you want to write a new baseline.json,"
        " consider using baseline_schema.json\n"
        f"({he.BASELINE_SCHEMA_PATH}) "
        "as documentation.\n\n"
        "Authors:\n"
        "  * Frédéric Proux, senior pentester at Beijaflore\n"
        "  * Alexandre Janvrin, pentester at Beijaflore\n"
        "    (https://www.beijaflore.com/en/)\n\n"
        "License: AGPLv3+\n\n"
        'This software is provided "as is", without '
        "any warranty of any kind, express or implied.\n"
        "For more information, please consult "
        "https://github.com/LivinParadoX/headerexposer.",
    )

    subparsers = main_parser.add_subparsers(
        title="commands",
        description="Use [command] -h for additional help.",
        dest="command",
    )

    analysis = subparsers.add_parser(
        "analyse", help="Analyse a given url's headers."
    )

    demo = subparsers.add_parser(
        "demo",
        help="Show a demonstration of what would be printed for sample"
        " headers with the selected baseline.json.",
    )

    show = subparsers.add_parser(
        "show", help="Show the selected baseline without doing any analysis."
    )

    analysis.set_defaults(func=analyse)
    demo.set_defaults(func=baseline_demo)
    show.set_defaults(func=show_baseline)

    # Okay this may seem ugly but I want this argument available
    # *everywhere*.
    for parser in [main_parser, analysis, demo, show]:
        with resources.path("headerexposer", "baseline_short.json") as baseline_path:
            parser.add_argument(
                "-b",
                "--baseline-path",
                help="Path to the baseline.json file for the header analysis"
                f" (default: {baseline_path}).",
                default=baseline_path,
            )

    request_options = analysis.add_argument_group("request options")

    request_options.add_argument(
        "-m",
        "--method",
        help='HTTP method to use for the request. Default: "GET".',
        choices=["GET", "OPTIONS", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
        default="GET",
    )

    request_options.add_argument(
        "--params",
        help="Add multiple, ampersand-separated parameters to the request.",
    )

    group = request_options.add_mutually_exclusive_group()

    group.add_argument(
        "-d",
        "--data",
        help="Data to append to the request."
        " Mutually exclusive with --file.",
    )

    group.add_argument(
        "-f",
        "--file",
        help="Path to a file to append to the request."
        " Mutually exclusive with --data.",
    )

    request_options.add_argument(
        "-H",
        "--headers",
        help="Add multiple, newline-separated HTTP headers to the request.",
    )

    request_options.add_argument(
        "-C",
        "--cookies",
        help="Add multiple, semicolon-separated cookies to the request.",
    )

    request_options.add_argument(
        "-U",
        "--username",
        help="username to use in Basic/Digest/Custom HTTP Authentication.",
    )

    request_options.add_argument(
        "-P",
        "--password",
        help="password to use in Basic/Digest/Custom HTTP Authentication.",
    )

    request_options.add_argument(
        "-t",
        "--timeout",
        type=float,
        help="How many seconds to wait for the server to send data"
        " before giving up, as float.",
    )

    request_options.add_argument(
        "-r",
        "--disallow-redirects",
        action="store_true",
        help="Disable GET/OPTIONS/POST/PUT/PATCH/DELETE/HEAD redirection."
        " Defaults to enabled redirection.",
    )

    request_options.add_argument(
        "-p", "--proxy", help="Proxy to use for the request."
    )

    request_options.add_argument(
        "-k",
        "--verify",
        action="store_true",
        help="Verify SSL certificates. Defaults to an insecure behavior.",
    )

    request_options.add_argument(
        "-c",
        "--cert",
        help="Optional path to the SSL client .pem certificate"
        " for client authentication.",
    )

    request_options.add_argument(
        "-a",
        "--user-agent",
        help="User Agent to use."
        " Defaults to a recent Google Chrome user agent.",
        default="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1"
        " (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1",
    )

    analysis.add_argument("url", help="The url to test.")

    # Okay this may seem ugly but I want these argument available
    # *everywhere*. And at the end, not like --baseline-path.
    for parser in [main_parser, analysis, demo, show]:
        output_options = parser.add_argument_group("output options")

        output_options.add_argument(
            "--detailed",
            action="store_true",
            help="Print additional details: the request parameters,"
            " the response details,"
            " headers' descriptions, and references.",
        )

        output_options.add_argument(
            "--no-explanation-colors",
            action="store_true",
            help="Suppress colors in explanations, except in reference links.",
        )

        output_options.add_argument(
            "-w",
            "--max-width",
            type=int,
            help="The maximum width of the output. Defaults to the screen"
            f" width ({shutil.get_terminal_size().columns} columns).",
            default=shutil.get_terminal_size().columns,
        )

    args = main_parser.parse_args()

    if args.command is None:
        main_parser.print_help()

    else:

        # Hack dégeulasse de quand j'ai modifié le comportement par défaut
        args.short = not args.detailed

        baseline = he.load_baseline(
            args.baseline_path, args.no_explanation_colors
        )

        if not args.short:
            print(BANNER)

        args.func(args, baseline)


if __name__ == "__main__":
    main()
