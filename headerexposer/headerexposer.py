#!/usr/bin/env python3

"""
The headerexposer module provides functions to analyse the security of a
website's headers
"""


from sys import exit as sys_exit
from jsonschema import validate as validate_json
from argparse import ArgumentParser
from json import loads as json_loads
from re import compile as regex_compile, IGNORECASE
from textwrap import wrap
from shutil import get_terminal_size
from functools import partial
from typing import Any, Optional, Tuple
from requests import request
from urllib3 import disable_warnings as urllib3_disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from tabulate import tabulate

BANNER = "".join([
    "\n \033[1;34;94m┌───────────────\033[34m────────────────\033[37m────────",
    "────────\033[1;30;90m─────┐\033[0m\n \033[1;34;94m│░█░█░█▀\033[34m▀░█▀█░",
    "█▀▄░█▀▀░█▀\033[37m▄░█▀▀░█░█░█▀█░█▀\033[1;30;90m█░█▀▀░█▀▀░█▀▄│\033[0m\n ",
    "\033[34m│░█▀█░█▀▀░█▀█░█░\033[37m█░█▀▀░█▀▄░█▀▀░▄▀\033[1;30;90m▄░█▀▀░█░█░▀",
    "▀█░█▀\033[1;34;94m▀░█▀▄│\033[0m\n \033[34m│░▀░▀░▀▀\033[37m▀░▀░▀░▀▀░░▀▀▀░",
    "▀░\033[1;30;90m▀░▀▀▀░▀░▀░▀░░░▀▀\033[1;34;94m▀░▀▀▀░▀▀▀░▀░▀│\033[0m\n \033",
    "[37m└───────────────\033[1;30;90m────────────────\033[1;34;94m──────────",
    "──────\033[34m─────┘\033[0m\n"
    ])

def special_to_ansi(string: str) -> str:
    """
    This function replaces special tags such as [red] to their corresponding
    ANSI codes
    """
    string = string.replace('[red]',       '\033[91m')
    string = string.replace('[green]',     '\033[92m')
    string = string.replace('[yellow]',    '\033[93m')
    string = string.replace('[blue]',      '\033[94m')
    string = string.replace('[magenta]',   '\033[95m')
    string = string.replace('[underline]', '\033[4m')
    return string.replace('[normal]',    '\033[0m')

def b_special_to_ansi(bstring: bytes) -> bytes:
    """
    This function replaces special tags such as [red] to their corresponding
    ANSI codes
    """
    bstring = bstring.replace(b'[red]',       b'\\u001b[91m')
    bstring = bstring.replace(b'[green]',     b'\\u001b[92m')
    bstring = bstring.replace(b'[yellow]',    b'\\u001b[93m')
    bstring = bstring.replace(b'[blue]',      b'\\u001b[94m')
    bstring = bstring.replace(b'[magenta]',   b'\\u001b[95m')
    bstring = bstring.replace(b'[underline]', b'\\u001b[4m')
    return bstring.replace(b'[normal]',    b'\\u001b[0m')

def print_special(text: str) -> None:
    """
    This function prints a string after replacing its special tags to their
    corresponding ANSI codes
    """
    print(special_to_ansi(text))

def tabulate_dict(dictionary: dict, max_width: int = None) -> str:
    """
    This function formats a dict as a two-columns table, where the first
    column is the dict keys and the second column is the values.
    It wraps the value column to not produce a table wider than max_width.
    """

    if max_width is None:
        max_width = get_terminal_size().columns

    max_dict_key_len = len(max(dictionary.keys(), key=len))

    # The maximum value width is equal to the maximum dict key width minus the
    # two spaces between columns minus the '\' that is added to each split
    # line to make it evident to the user that the line has been split
    max_v_width = max_width - max_dict_key_len - 3

    # To understand this bit of magic one needs to understand the wrap()
    # function and the "".join() method.
    table = [[str(k), "\\\n".join(wrap(
        str(v), width=max_v_width
        ))] for k, v in dictionary.items()]

    return tabulate(table)

def find_optimal_column_width(findings: list,
        max_width: Optional[int] = None) -> Tuple[int, int]:
    """
    This function does a bit of wizardry to find the optimal widths of
    the Value and Explanation columns of a findings table.
    It compromises between the header names and ratings, which must not be
    broken, the header values, which must make it clear to the user that
    they are being broken by printing '\\' at the end of each broken line,
    the reference links, which must preferably not be broken lest they become
    unclickable, etc. Everything taking into account that the "tabulate"
    function separates columns by two spaces.
    The logic is the following:
     1) find the maximum length of everyone
     2) if the values are short, we are in luck and the explanations have more
     room
     3) if not, we try to give values and explanations about the same width
     4) if this breaks the reference links, we try to shrink the header values
     a bit
     5) if there is not enough room for the header values, we finally resolve
     to breaking the links, as there are no other choices
    """

    if max_width is None:
        max_width = get_terminal_size().columns

    max_header_name_len = 0
    max_header_value_len = 0
    max_rating_len = 0
    max_reference_len = 0

    # in this loop we get the max width of everyone
    for finding in findings:

        try:
            value_len = len(finding["value"])
        except TypeError:
            value_len = 4

        max_header_name_len = max(max_header_name_len, len(finding["header"]))
        max_header_value_len = max(max_header_value_len, value_len)
        max_rating_len = max(max_rating_len, len(finding["rating"]))

        for ref in finding["references"]:
            max_reference_len = max(max_reference_len, len(ref))

    # Now we know that the values and explanations will have to share
    # columns_width characters of space
    columns_width = (max_width - max_header_name_len - max_rating_len - 7)

    # are the values short ? Great, we have room
    if max_header_value_len <= columns_width // 2:
        e_width = columns_width - max_header_value_len - 1
        v_width = max_header_value_len + 1

    # else we try to give everyone the same space
    else:
        v_width = columns_width // 2
        e_width = columns_width // 2

    # Oops, it breaks the links. Can we give the values a little less space ?
    # If not, well, we have no choice but to break the links
    if max_reference_len > e_width:
        if max_reference_len < columns_width - 10:
            e_width = max_reference_len
            v_width = columns_width - e_width

    return e_width, v_width


def tabulate_findings(findings: list, max_width: Optional[int] = None) -> str:
    """
    This function formats the findings in a nice table for printing
    """

    findings_table = []

    # for the table to fit on screen we need to know the widths of the
    # explanation and value columns.
    e_width, v_width = find_optimal_column_width(findings, max_width)

    for finding in findings:

        if finding["value"] is None:
            value = "Absent"
        else:
            value = "\\\n".join(wrap(finding["value"], width=v_width))

        rating = finding["rating"]

        # To understand this, one needs to know that explanations is a list
        # of strings that may or may not contain newlines. We first need to
        # join them around spaces, then split them by newlines, we now have
        # paragraphs. But these paragraphs now need to be split to smaller
        # lines that fit in the explanation column width. Once this is done
        # we again join the lines
        paragraphs = " ".join(finding["explanations"]).splitlines()
        lines = ["\n".join(wrap(p, e_width)) for p in paragraphs]
        explanation = "\n".join(lines)

        # References are annoying because we want them in blue and underlined.
        # But if we simply apply ANSI codes at the start and end of the
        # links, the tabulate function will happily produce an ugly table with
        # long underlined empty spaces. To avoid that we need to split the
        # lines like we did for the explanations, and apply the codes to the
        # start and end of each line.
        references = finding["references"]
        if references != []:
            lines = ["\n".join(wrap(r, e_width)) for r in references]
            ref_lines = "\n".join(lines).splitlines()
            explanation += special_to_ansi("\nReferences:\n[underline][blue]")
            explanation += special_to_ansi("[normal]\n"
                    "[underline][blue]").join(ref_lines)
            explanation += special_to_ansi("[normal]")

        findings_table += [[finding["header"], value, rating, explanation]]

    table_headers = ["Header", "Value", "Rating", "Explanation"]
    return tabulate(findings_table, headers=table_headers)

def string_to_dict(string: str, delimiter_1: str, delimiter_2: str) -> dict:
    """
    This function parses a string into a dict by splitting it around
    delimiters, and eliminating superfluous white spaces.

    For example, "param1: value1; param2: value2" with ':' as delimiter_1 and
    ';' as delimiter_2 will be parsed into
    {
        "param1": "value1",
        "param2": "value2"
    }
    
    WARNING: This function WILL raise IndexError if the input string
    cannot be parsed.
    """
    result_dict = {}
    for couple in string.split(delimiter_2):

        key = couple.split(delimiter_1)[0].strip()
        value = couple.split(delimiter_1)[1].strip()

        result_dict[key] = value

    return result_dict

def parse_request_parameters(params: str) -> dict:
    """
    This function parses parameters such as "param1=value1&param2=value2"
    into a dict of parameters
    """
    try:
        return string_to_dict(params, '=', '&')

    except IndexError:
        print("Parameters must be formatted as couples of values such as"
                " param1=value1&param2=value2 etc.")
        print("Bad parameters: " + params)
        raise

def parse_request_headers(headers: str) -> dict:
    """
    This function parses headers such as:
    header1: value1
    header2: value2
    into a dict of headers
    """
    try:
        return string_to_dict(headers, ':', '\n')

    except IndexError:
        print('Headers must be formatted as couples of values such as'
                ' "header1: value1"  etc.')
        print("Bad headers:")
        print(headers)
        raise

def parse_request_cookies(cookies: str) -> dict:
    """
    This function parses cookies such as "cookie1=value1; cookie2=value2"
    into a dict of cookies
    """
    try:
        return string_to_dict(cookies, '=', ';')

    except IndexError:
        print('Cookies must be formatted as couples of values such as'
                ' "cookie1=value1; cookie2=value2"  etc.')
        print("Bad cookies:")
        print(cookies)
        raise

def load_baseline(baseline_path: str) -> dict:
    """
    This function loads the baseline.json, replaces special markings
    such as [green] to their corresponding ANSI codes, and validates it
    against baseline_schema.json
    """
    with open("baseline_schema.json") as f:
        baseline_schema = json_loads(f.read())

    with open(baseline_path, "rb") as baseline_file:
        baseline = json_loads(b_special_to_ansi(baseline_file.read()))

    validate_json(baseline, baseline_schema)

    return baseline

def analyse_header(header_value: Any,
        header_baseline: dict) -> Tuple[str, list]:
    """
    This function analyses a single non-None header according to its baseline
    value.
    """
    explanations = []

    if header_baseline.get("case_sensitive_patterns", False):
        re_compile = partial(regex_compile)
    else:
        re_compile = partial(regex_compile, flags=IGNORECASE)

    # First we validate the header. If it does not match the validation
    # pattern, we ~~yell at the user's face~~stop the analysis and apply
    # The corresponding rating and explanation.
    # If it does, we can keep analysing it.
    v_pattern = re_compile(header_baseline["validation_pattern"])

    if not v_pattern.match(header_value):
        explanations += [header_baseline.get("invalid_explanation",
            special_to_ansi("[red]The header is malformed.[normal]"))]
        rating = header_baseline.get("invalid_rating", "bad")

    else:
        rating = header_baseline.get("default_rating", "bad")

        for r_pattern in header_baseline.get("rating_patterns", []):

            pattern = re_compile(r_pattern["pattern"])

            if pattern.match(header_value):
                rating = r_pattern["rating"]

        for e_pattern in header_baseline.get("explanation_patterns", []):

            pattern = re_compile(e_pattern["pattern"])

            if pattern.match(header_value):
                exp = pattern.sub(e_pattern["present"], header_value)
                explanations += [exp]

            elif e_pattern.get("absent") is not None:
                explanations += [e_pattern["absent"]]

    return rating, explanations

def analyse_headers(headers: dict, baseline: dict,
        short: bool = False) -> list:
    """
    This function analyses the headers according to the headers to produce
    a security analysis. Basically, it parses the baseline for regex patterns
    to identify in the headers' values, and returns the ratings and
    explanations associated in the baseline
    """
    nice_ratings = {
            "good":   special_to_ansi("[green][ＧＯＯＤ][normal]"),
            "medium": special_to_ansi("[yellow][ＭＥＤ][normal]"),
            "bad":    special_to_ansi("[red][ＢＡＤ][normal]")
        }

    findings = []

    for b_header in baseline["headers"]:

        header_name = b_header["name"]
        header_value = headers.get(header_name)
        explanations = []

        if not short and b_header.get("description") is not None:
            explanations += [b_header["description"]]

        if header_value is None:
            explanations += [b_header.get("absent_explanation",
                    special_to_ansi("[red]The header is absent[normal]"))]
            rating = b_header.get("absent_rating", "bad")

        else:
            rating, h_explanations = analyse_header(header_value, b_header)
            explanations += h_explanations

        if b_header.get("final_explanation") is not None:
            explanations += [b_header["final_explanation"]]

        findings += [{
            "header":       header_name,
            "value":        header_value,
            "rating":       nice_ratings[rating],
            "explanations": explanations,
            "references":   b_header.get("references", []) if not short else []
            }]

    return findings

def baseline_demo(baseline: dict,
        max_width: Optional[int] = get_terminal_size().columns,
        short: Optional[bool] = False) -> None:
    """
    This function showcases the module and shows what would be printed after
    analysing example headers with the selected baseline.
    """
    examples = [
            {
                "Strict-Transport-Security": "max-age=31536000;"
                " includeSubDomains",
                "X-Frame-Options": "DENY"
                },
            {
                "Strict-Transport-Security": "max-age=potato;"
                " includeSubDomains",
                "X-Frame-Options": "Gloubiboulga"
                },
            {
                "Strict-Transport-Security": "max-age=2006;"
                " includeSubDomains; preload",
                "X-Frame-Options": "ALLOW-FROM china"
                },
            {
                "Strict-Transport-Security": "max-age=0;"
                " preload",
                "X-Frame-Options": "SAMEORIGIN"
                },
            {
                "Strict-Transport-Security": "max-age=31536000;"
                " includeSubDomains; preload",
                "X-Frame-Options": "DENIS"
                },
            {
                "Strict-Transport-Security": "includeSubDomains; preload",
                "X-Frame-Options": "SAMEORANGINA"
                },
            {
                },
            ]
    
    for ex_number in range(len(examples)):

        headers = examples[ex_number]
        findings = analyse_headers(headers, baseline, short)

        print_special(f"\n[blue]Example {ex_number} headers analysis:[normal]")
        print(tabulate_findings(findings, max_width))

    sys_exit(0)

def parse_args() -> Any:
    """
    This function parses the commandline arguments
    """
    parser = ArgumentParser()

    parser.add_argument('-m', '--method',
            help='HTTP method to use for the request. Default: "GET"',
            choices=["GET", "OPTIONS", "HEAD", "POST",
                "PUT", "PATCH", "DELETE"],
            default="GET")

    parser.add_argument('--params',
            help="Add multiple, ampersand-separated parameters to the request")

    group = parser.add_mutually_exclusive_group()

    group.add_argument('-d', '--data',
            help="Data to append to the request."
            " Mutually exclusive with --file")

    group.add_argument('-f', '--file',
            help="Path to a file to append to the request."
            " Mutually exclusive with --data")

    parser.add_argument('-H', '--headers',
            help="Add multiple, newline-separated HTTP headers to the request")

    parser.add_argument('-C', '--cookies',
            help="Add multiple, semicolon-separated cookies to the request")

    parser.add_argument('-U', '--username',
            help="username to use in Basic/Digest/Custom HTTP Authentication")

    parser.add_argument('-P', '--password',
            help="password to use in Basic/Digest/Custom HTTP Authentication")

    parser.add_argument('-t', '--timeout', type=float,
            help="How many seconds to wait for the server to send data"
            " before giving up, as float")

    parser.add_argument('-r', '--disallow-redirects', action="store_true",
            help="Disable GET/OPTIONS/POST/PUT/PATCH/DELETE/HEAD redirection."
            " Defaults to enabled redirection")

    parser.add_argument('-p', '--proxy', help="Proxy to use for the request")

    parser.add_argument('-k', '--verify', action="store_true",
            help="Verify SSL certificates. Defaults to an insecure behavior")

    parser.add_argument('-c', '--cert',
            help="Optional path to the SSL client .pem certificate"
            " for client authentication")

    parser.add_argument('-b', '--baseline-path',
            help="Path to the baseline.json file for the header analysis",
            default="baseline.json")

    parser.add_argument('-a', '--user-agent',
            help="User Agent to use."
            " Defaults to a recent Google Chrome user agent",
            default="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1"
            " (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1")

    parser.add_argument('-s', '--short', action="store_true",
            help="Shorten the output. Do not print the request parameters,"
            " do not print the response details,"
            " do not print headers' descriptions, do not print references.")

    parser.add_argument('--baseline-demo', action="store_true",
            help="Activates baseline demo mode. No request will be sent."
            "instead, the currently selected baseline will be applied"
            "to a set of examples.")

    parser.add_argument('-w', '--max-width', type=int,
            help="The maximum width of the output. Defaults to the screen"
            f" width ({get_terminal_size().columns} columns)",
            default=get_terminal_size().columns)

    parser.add_argument('url', help="The url to test")

    return parser.parse_args()

def main():
    """
    Main function of the module, only called when the module is called
    directly and not imported
    """
    args = parse_args()

    baseline = load_baseline(args.baseline_path)

    if not args.short:
        print(BANNER)

    if args.baseline_demo:
        baseline_demo(baseline, args.max_width, args.short)

    request_arguments = {
            "method"         : args.method,
            "url"            : args.url,
            "params"         : None,
            "data"           : None,
            "headers"        : {},
            "cookies"        : None,
            "auth"           : None,
            "timeout"        : args.timeout,
            "allow_redirects": not args.disallow_redirects,
            "proxies"        : {"http": args.proxy, "https": args.proxy},
            "verify"         : args.verify,
            "cert"           : args.cert
        }

    if args.params is not None:
        request_arguments["params"] = parse_request_parameters(args.params)

    if args.data is not None:
        request_arguments['data'] = args.data.encode()

    elif args.file is not None:
        with open(args.file, 'rb') as data_file:
            request_arguments['data'] = data_file.read()

    if args.headers is not None:
        request_arguments["headers"] = parse_request_headers(args.headers)

    if args.user_agent is not None:
        request_arguments["headers"]["User-Agent"] = args.user_agent

    if args.cookies is not None:
        request_arguments["cookies"] = parse_request_cookies(args.cookies)

    if args.username is not None and args.password is not None:
        request_arguments["auth"] = (args.username, args.password)

    if not args.short:
        print_special("[blue]Request parameters:[normal]")
        print(tabulate_dict(request_arguments, args.max_width))

    if not args.verify:
        urllib3_disable_warnings(InsecureRequestWarning)

    response = request(**request_arguments)

    if not args.short:
        print_special("\n[blue]Response:[normal]")
        print(tabulate_dict({
            "Length": len(response.content),
            "Status Code": response.status_code,
            "Reason": response.reason
            }, args.max_width))

    if not args.short:
        print_special("\n[blue]Response headers:[normal]")
        print(tabulate_dict(response.headers, args.max_width))

    findings = analyse_headers(response.headers, baseline, args.short)

    print_special("\n[blue]Headers analysis:[normal]")
    print(tabulate_findings(findings, args.max_width))


if __name__ == "__main__":
    main()
