#!/usr/bin/env python3

"""Analyse the security of your website's headers.

The headerexposer module provides functions to analyse the security
of a website's headers.

It can be loaded as a module, or directly ran from the commandline.

For commandline usage, see the output of:
python3 -m headerexposer --help

Basic module usage:

>>> import headerexposer as he
>>> import requests

>>> baseline = he.load_baseline("baseline.json")

>>> resp = requests.get("https://google.com")

>>> findings = he.analyse_headers(resp.headers, baseline, short=True)

>>> print(he.tabulate_findings(findings))
Header                     Value       Rating      Explanation
-------------------------  ----------  ----------  ------------------
Strict-Transport-Security  Absent      [ＢＡＤ]    The header is
                                                   absent.  It is
                                                   recommended to set
                                                   the header's value
                                                   to "max-
                                                   age=31536000;
                                                   includeSubDomains;
                                                   preload". This
                                                   will tell users'
                                                   browsers that...
...
"""

__all__ = [
    "special_to_ansi",
    "b_special_to_ansi",
    "print_special",
    "tabulate_dict",
    "tabulate_findings",
    "string_to_dict",
    "parse_request_cookies",
    "parse_request_headers",
    "parse_request_parameters",
    "load_baseline",
    "analyse_header",
    "analyse_headers",
]
__version__ = "2020.11.dev1"
__author__ = "Alexandre Janvrin"
__description__ = "Analyse the security of your website's headers!"
__license__ = "AGPLv3+"
__title__ = "headerexposer"
__url__ = "https://github.com/LivinParadoX/headerexposer"

import functools
import json
import re
import shutil
import textwrap
from typing import Any, List, Optional, Tuple, Union

import jsonschema  # type: ignore
import tabulate

_BANNER = "".join(
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

_SPECIALS = {
    "[red]": 91,
    "[green]": 92,
    "[yellow]": 93,
    "[blue]": 94,
    "[magenta]": 95,
    "[underline]": 4,
    "[normal]": 0,
}


def special_to_ansi(string: str, no_colors: Optional[bool] = False) -> str:
    """Replace tags to their corresponding ANSI codes in strings.

    The following tags are currently supported:
    [red], [green], [yellow], [blue], [magenta], [underline], [normal]

    Args:
        string:
          The string in which to replace the tags.
        no_colors:
          If this is True, all tags will be removed instead of being
          replaced.

    Returns:
        The string with tags replaced or stripped.
    """
    if no_colors:
        for special, code in _SPECIALS.items():
            string = string.replace(special, "")

    else:
        for special, code in _SPECIALS.items():
            string = string.replace(special, f"\033[{code}m")

    return string


def b_special_to_ansi(
    bstring: bytes, no_colors: Optional[bool] = False
) -> bytes:
    """Replace tags to their corresponding ANSI codes in bytestrings.

    The following tags are currently supported:
    [red], [green], [yellow], [blue], [magenta], [underline], [normal]

    Args:
        bstring:
          The bytestring in which to replace the tags.
        no_colors:
          If this is True, all tags will be removed instead of being
          replaced.

    Returns:
        The string with tags replaced or stripped.
    """
    if no_colors:
        for special, code in _SPECIALS.items():
            bstring = bstring.replace(special.encode(), b"")

    else:
        for special, code in _SPECIALS.items():
            bstring = bstring.replace(
                special.encode(), f"\\u001b[{code}m".encode()
            )

    return bstring


def print_special(text: str) -> None:
    """Print a string after replacing its special tags.

    The tags such as [green] will be replaced with their corresponding
    ANSI codes. The following tags are currently supported:
    [red], [green], [yellow], [blue], [magenta], [underline], [normal]

    Args:
        text:
          The text to print.
    """
    print(special_to_ansi(text))


def tabulate_dict(dictionary: dict, max_width: int = None) -> str:
    """Format a dict as a two-columns table.

    This function formats a dict as a two-columns table, where the
    first column is the dict keys and the second column is the values.
    It wraps the value column to not produce a table wider than
    max_width.

    Args:
        dictionary:
          The dict to turn into a nice table.
        max_width:
          If specified, the function will try to wrap the values in
          order to not produce a table wider than max_width characters.

    Returns:
        The nice table ready for printing.
    """
    if max_width is None:
        max_width = shutil.get_terminal_size().columns

    max_dict_key_len = len(max(dictionary.keys(), key=len))

    # The maximum value width is equal to the maximum dict key width
    # minus the two spaces between columns minus the '\' that is added
    # to each split line to make it evident to the user that the line
    # has been split.
    max_v_width = max_width - max_dict_key_len - 3

    # To understand this bit of magic one needs to understand the
    # textwrap.wrap() function and the "".join() method.
    table = [
        [str(k), "\\\n".join(textwrap.wrap(str(v), width=max_v_width))]
        for k, v in dictionary.items()
    ]

    return tabulate.tabulate(table)


def _find_optimal_column_width(
    findings: list, max_width: Optional[int] = None
) -> Tuple[int, int]:
    r"""Find the optimal Value and Explanation column widths.

    This function does a bit of wizardry to find the optimal widths of
    the Value and Explanation columns of a findings table.
    It compromises between the header names and ratings, which must not
    be broken, the header values, which must make it clear to the user
    that they are being broken by printing '\' at the end of each
    broken line, the reference links, which must preferably not be
    broken lest they become unclickable, etc. Everything taking into
    account that the tabulate() function separates columns by two
    spaces.
    The logic is the following:
     1. find the maximum length of everyone,
     2. if the values are short, we are in luck and the explanations
        have more room,
     3. if not, we try to give values and explanations about the same
        width,
     4. if this breaks the reference links, we try to shrink the header
        values a bit,
     5. if there is not enough room for the header values, we finally
        resolve to breaking the links, as there are no other choices.

    Args:
        findings:
          The table of findings as returned by analyse_headers().
        max_width:
          We will try to produce a table not wider than this.

    Returns:
        A tuple of ints representing the width of the Value column,
        and the width of the Explanations column.
    """
    if max_width is None:
        max_width = shutil.get_terminal_size().columns

    max_header_name_len = 0
    max_header_value_len = 0
    max_rating_len = 0
    max_reference_len = 0

    # In this loop we get the max width of everyone
    for finding in findings:

        # If it does not have a length it will most certainly be
        # printed as None, True or False, so 4 characters
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
    # columns_width characters of space (the 7 constant accounts for
    # the 6 spaces added by tabulate() between the columns, and the
    # extra '\' that we will append to the header values to make it
    # clear to the user that the headers' values are being broken)
    columns_width = max_width - max_header_name_len - max_rating_len - 7

    # are the values short ? Great, we have room
    if max_header_value_len <= columns_width // 2:
        e_width = columns_width - max_header_value_len
        v_width = max_header_value_len

    # else we try to give everyone the same space
    else:
        v_width = columns_width // 2
        e_width = columns_width // 2

    # Oops, it breaks the links. Can we give the values a little less
    # space ? If not, well, we have no choice but to break the links
    if max_reference_len > e_width:
        if max_reference_len < columns_width - 10:
            e_width = max_reference_len
            v_width = columns_width - e_width

    return e_width, v_width


def tabulate_findings(findings: list, max_width: Optional[int] = None) -> str:
    """Format the findings in a nice table for printing.

    Args:
        findings:
          The list of finding items to format. This should come from
          the analyse_headers() function.
        max_width:
          If specified, the function will try to produce a table at
          most max_width characters wide.

    Returns:
        The string representing the nice findings table. Usually ready
        for printing.
    """
    findings_table = []

    # for the table to fit on screen we need to know the widths of the
    # explanation and value columns.
    e_width, v_width = _find_optimal_column_width(findings, max_width)

    for finding in findings:

        if finding["value"] is None:
            value = "Absent"
        else:
            value = "\\\n".join(textwrap.wrap(finding["value"], width=v_width))

        rating = finding["rating"]

        # To understand this, one needs to know that explanations is a
        # list of strings that may or may not contain newlines. We
        # first need to join them around spaces, then split them by
        # newlines, we now have paragraphs. But these paragraphs now
        # need to be split to smaller lines that fit in the explanation
        # column width. Once this is done we again join the lines
        paragraphs = " ".join(finding["explanations"]).splitlines()

        lines = ["\n".join(textwrap.wrap(p, e_width)) for p in paragraphs]

        explanation = "\n".join(lines)

        # References are annoying because we want them in blue and
        # underlined. But if we simply apply ANSI codes at the start
        # and end of the links, the tabulate function will happily
        # produce an ugly table with long underlined empty spaces. To
        # avoid that we need to split the lines like we did for the
        # explanations, and apply the codes to the start and end of
        # each line.
        references = finding["references"]
        if references != []:

            lines = ["\n".join(textwrap.wrap(r, e_width)) for r in references]

            ref_lines = "\n".join(lines).splitlines()

            explanation += special_to_ansi("\nReferences:\n[underline][blue]")

            explanation += special_to_ansi("[normal]\n[underline][blue]").join(
                ref_lines
            )

            explanation += special_to_ansi("[normal]")

        findings_table += [[finding["header"], value, rating, explanation]]

    table_headers = ["Header", "Value", "Rating", "Explanation"]
    return tabulate.tabulate(findings_table, headers=table_headers)


def string_to_dict(string: str, delimiter_1: str, delimiter_2: str) -> dict:
    """Parse a string into a dict by splitting around delimiters.

    This function parses a string into a dict by splitting it around
    delimiters, and eliminating superfluous white spaces.

    For example, "param1: value1; param2: value2" with ':' as
    delimiter_1 and ';' as delimiter_2 will be parsed into
    {
        "param1": "value1",
        "param2": "value2"
    }

    Args:
        string:
          The string to parse.
        delimiter_1:
          The delimiter which separates the key: value pairs.
        delimiter_2:
          The delimiter which separates the keys from the values.

    Returns:
        The dict of key: value pairs.

    Raises:
        IndexError if the input string cannot be parsed.
    """
    result_dict = {}
    for couple in string.split(delimiter_2):

        key = couple.split(delimiter_1)[0].strip()
        value = couple.split(delimiter_1)[1].strip()

        result_dict[key] = value

    return result_dict


def parse_request_parameters(params: Union[str, None]) -> Union[dict, None]:
    """Parse a parameters string into a dict.

    Args:
        params:
          A string representing the parameters to parse, such as
          "param1=value1&param2=value2", or None.

    Returns:
        A dict of parameter_name: parameter_value pairs. Returns None
        if params is None.
    """
    if params is None:
        return None

    try:
        return string_to_dict(params, "=", "&")

    except IndexError:
        print(
            "Parameters must be formatted as couples of values such as"
            " param1=value1&param2=value2 etc."
        )
        print("Bad parameters: " + params)
        raise


def parse_request_headers(headers: Union[str, None]) -> dict:
    r"""Parse a headers string into a dict.

    Args:
        headers:
          A string representing the headers to parse, such as
          "header1: value1\nheader2: value2", or None.

    Returns:
        A dict of header_name: header_value pairs. Returns an empty
        dict if headers is None.
    """
    if headers is None:
        return {}

    try:
        return string_to_dict(headers, ":", "\n")

    except IndexError:
        print(
            "Headers must be formatted as couples of values such as"
            ' "header1: value1"  etc.'
        )
        print("Bad headers:")
        print(headers)
        raise


def parse_request_cookies(cookies: Union[str, None]) -> Union[dict, None]:
    """Parse a cookies string into a dict.

    Args:
        cookies:
          A string representing the cookies to parse, such as
          "cookie1=value1; cookie2=value2", or None.

    Returns:
        A dict of cookie_name: cookie_value pairs. Returns None if
        cookies is None.
    """
    if cookies is None:
        return None

    try:
        return string_to_dict(cookies, "=", ";")

    except IndexError:
        print(
            "Cookies must be formatted as couples of values such as"
            ' "cookie1=value1; cookie2=value2"  etc.'
        )
        print("Bad cookies:")
        print(cookies)
        raise


def load_baseline(
    baseline_path: str, no_colors: Optional[bool] = False
) -> dict:
    """Load and validate baseline.json.

    This function loads the baseline.json, replaces special markings
    such as [green] to their corresponding ANSI codes, and validates it
    against baseline_schema.json.

    Args:
        baseline_path:
          the absolute or relative path to the baseline file.
        no_colors:
          If True, the special tags such as [red] will be stripped from
          the baseline file, which essentially means that explanations
          will not be color-coded (but references and ratings will
          still be, as they are they are colored by headerexposer and
          not in the baseline).

    Returns:
        the baseline dict loaded from baseline.json.
    """
    with open("baseline_schema.json") as baseline_schema_file:
        baseline_schema = json.loads(baseline_schema_file.read())

    with open(baseline_path, "rb") as baseline_file:
        baseline = json.loads(
            b_special_to_ansi(baseline_file.read(), no_colors)
        )

    jsonschema.validate(baseline, baseline_schema)

    return baseline


def analyse_header(
    header_value: Any, header_baseline: dict
) -> Tuple[str, List[str]]:
    """Analyses a single valid header according to the baseline.

    Args:
        header_value:
          (string) The header's value
        header_baseline:
          The header's baseline as loaded by load_baseline()

    Returns:
        ((str) rating, List[str] explanations) The header's rating and
        the list of explanations to print.
    """
    explanations = []

    if header_baseline.get("case_sensitive_patterns", False):
        re_compile = functools.partial(re.compile)
    else:
        re_compile = functools.partial(re.compile, flags=re.IGNORECASE)

    # First we validate the header. If it does not match the validation
    # pattern, we ~~yell at the user's face~~stop the analysis and
    # apply the corresponding rating and explanation.
    # If it does, we can keep analysing it.
    v_pattern = re_compile(header_baseline["validation_pattern"])

    if not v_pattern.match(header_value):

        explanations += [
            header_baseline.get(
                "invalid_explanation",
                special_to_ansi("[red]The header is malformed.[normal]"),
            )
        ]

        if header_baseline.get("absent_or_invalid_explanation") is not None:
            explanations += [
                header_baseline.get("absent_or_invalid_" "explanation")
            ]

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


def analyse_headers(
    headers: dict, baseline: dict, short: bool = False
) -> list:
    """Analyse response headers according to baseline.

    This function compares headers' values to the baseline headers to
    produce a security analysis. Basically, it parses the baseline for
    regex patterns to identify in the headers' values, and returns the
    ratings and explanations associated in the baseline.

    Args:
        headers:
          The headers to analyse.
        baseline:
          The baseline to compare the headers' values against. It
          should be loaded from load_baseline().
        short:
          If True, the headers' descriptions and references as
          contained in the baseline will not be added to the
          explanations.

    Returns:
        The list of findings, each finding being a dict like this:
        {
            "header": (string) header_name,
            "value": (string) header_value,
            "rating": (string) rating,
            "explanations": (List[string]) explanations,
            "references": (List[string]) references
        }
    """
    nice_ratings = {
        "good": special_to_ansi("[green][ＧＯＯＤ][normal]"),
        "medium": special_to_ansi("[yellow][ＭＥＤ][normal]"),
        "bad": special_to_ansi("[red][ＢＡＤ][normal]"),
    }

    findings = []

    for b_header in baseline["headers"]:

        header_name = b_header["name"]
        header_value = headers.get(header_name)
        explanations = []

        if not short and b_header.get("description") is not None:
            explanations += [b_header["description"]]

        if header_value is None:

            explanations += [
                b_header.get(
                    "absent_explanation",
                    special_to_ansi("[red]The header is absent[normal]"),
                )
            ]

            if b_header.get("absent_or_invalid_explanation") is not None:

                explanations += [
                    b_header.get("absent_or_invalid_" "explanation")
                ]

            rating = b_header.get("absent_rating", "bad")

        else:
            rating, h_explanations = analyse_header(header_value, b_header)
            explanations += h_explanations

        if b_header.get("final_explanation") is not None:
            explanations += [b_header["final_explanation"]]

        findings += [
            {
                "header": header_name,
                "value": header_value,
                "rating": nice_ratings[rating],
                "explanations": explanations,
                "references": b_header.get("references", [])
                if not short
                else [],
            }
        ]

    return findings
