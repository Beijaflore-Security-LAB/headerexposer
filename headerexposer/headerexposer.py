#!/usr/bin/env python3


import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from argparse import ArgumentParser
from sys import exit
from pprint import pformat
from textwrap import wrap
from tabulate import tabulate
from shutil import get_terminal_size
from time import gmtime, strftime
from datetime import timedelta
from json import loads as json_loads
import re

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

RATINGS = {
        "good":   "\033[92m[ＧＯＯＤ]\033[0m",
        "medium": "\033[93m[ＭＥＤ]\033[0m",
        "bad":    "\033[91m[ＢＡＤ]\033[0m"
    }

def special_to_ansi(text):
    text = text.replace('[red]',       '\033[91m')
    text = text.replace('[green]',     '\033[92m')
    text = text.replace('[yellow]',    '\033[93m')
    text = text.replace('[blue]',      '\033[94m')
    text = text.replace('[magenta]',   '\033[95m')
    text = text.replace('[underline]', '\033[4m')
    return text.replace('[normal]',    '\033[0m')

def print_special(text):
    print(special_to_ansi(text))

def colorize(text, color):
    return special_to_ansi(f"[{color}]{text}[normal]")

def print_color(text, color):
    print(colorize(text, color))

def tabulate_dict(dict, max_width=None):

    if max_width is None:
        max_width = get_terminal_size().columns

    max_dict_key_len = 0
    max_dict_value_len = 0
    for key, value in dict.items():

        try:
            value_len = len(value)
        except TypeError:
            value_len = 4
        
        max_dict_value_len = max(max_dict_value_len, value_len)
        max_dict_key_len = max(max_dict_key_len, len(key))

    max_v_width = max_width - max_dict_key_len - 3
    
    table = [[str(k), "\\\n".join(wrap(
        str(v), width=max_v_width
        ))] for k, v in dict.items()]

    return tabulate(table)

def tabulate_findings(findings, max_width=None):

    if max_width is None:
        max_width = get_terminal_size().columns

    max_header_name_len = 0
    max_header_value_len = 0
    max_rating_len = 0
    max_reference_len = 0

    for finding in findings:
        
        try:
            value_len = len(finding["value"])
        except TypeError:
            value_len = 4

        max_header_name_len = max(max_header_name_len, len(finding["header"]))
        max_header_value_len = max(max_header_value_len, value_len)
        max_rating_len = max(max_rating_len, len(RATINGS[finding["rating"]]))
        
        for ref in finding["references"]:
            max_reference_len = max(max_reference_len, len(ref))

    columns_width = (max_width - max_header_name_len - max_rating_len - 7)

    if max_header_value_len <= columns_width // 2:
        e_width = columns_width - max_header_value_len - 1
        v_width = max_header_value_len + 1
    else:
        v_width = columns_width // 2
        e_width = columns_width // 2

    if max_reference_len > e_width and max_reference_len < columns_width - 10:
        e_width = max_reference_len
        v_width = columns_width - e_width

    findings_table = []

    for finding in findings:

        if finding["value"] is None:
            value = "Absent"
        else:
            value = "\\\n".join(wrap(finding["value"], width=v_width))
        
        rating = RATINGS.get(finding["rating"].lower())

        paragraphs = " ".join(finding["explanations"]).splitlines()
        lines = ["\n".join(wrap(p, e_width)) for p in paragraphs]
        explanation = "\n".join(lines)
        
        references = finding["references"]
        if references != []:
            lines = ["\n".join(wrap(r, e_width)) for r in references]
            ref_lines = "\n".join(lines).splitlines()
            explanation += "\nReferences:\n\033[4;94m"
            explanation += "\033[0m\n\033[4;94m".join(ref_lines)
            explanation += "\033[0m"

        findings_table += [[finding["header"], value, rating, explanation]]

    table_headers = ["Header", "Value", "Rating", "Explanation"]
    return tabulate(findings_table, headers=table_headers)

def build_request_arguments(
        url,
        method             = "GET",
        params             = None,
        timeout            = None,
        disallow_redirects = False,
        proxy              = None,
        verify             = False,
        cert               = None,
        data               = None,
        file               = None,
        headers            = None,
        user_agent         = None,
        cookies            = None,
        username           = None,
        password           = None
        ):

    if data is not None and file is not None:
        print("Error in build_request_arguments:"
                " raise and file arguments are mutually exclusive")
        exit(1)

    request_arguments = {
            "method"         : method,
            "url"            : url,
            "params"         : None,
            "data"           : None,
            "headers"        : {},
            "cookies"        : None,
            "auth"           : None,
            "timeout"        : timeout,
            "allow_redirects": not disallow_redirects,
            "proxies"        : {"http": proxy, "https": proxy},
            "verify"         : verify,
            "cert"           : cert
        }

    if params is not None:
        request_arguments["params"] = {}

        try:
            for p in params.strip().split('&'):

                p_name = p.split('=')[0].strip()
                p_value = p.split('=')[1].strip()
                
                request_arguments["params"][p_name] = p_value
        
        except IndexError:
            print("Parameters must be formatted as couples of values such as"
                    " param1=value1&param2=value2 etc.")
            print("Bad parameters: " + params)
            exit(1)

    if data is not None:
        request_arguments['data'] = data.encode()

    elif file is not None:
        with open(file, 'rb') as f:
            request_arguments['data'] = f.read()

    if headers is not None:

        try:
            for h in headers.strip().split('\n'):

                h_name = h.split(':')[0].strip()
                h_value = h.split(':')[1].strip()

                request_arguments["headers"][h_name] = h_value
        
        except IndexError:
            print('Headers must be formatted as couples of values such as'
                    ' "header1: value1"  etc.')
            print("Bad headers:")
            print(headers)
            exit(1)

    if user_agent is not None:
        request_arguments["headers"]["User-Agent"] = user_agent

    if cookies is not None:
        request_arguments["cookies"] = {}
        
        try:
            for c in cookies.strip().split(';'):

                c_name = c.split('=')[0].strip()
                c_value = c.split('=')[1].strip()

                request_arguments["cookies"][c_name] = c_value
        
        except IndexError:
            print('Cookies must be formatted as couples of values such as'
                    ' "cookie1=value1; cookie2=value2"  etc.')
            print("Bad cookies:")
            print(cookies)
            exit(1)

    if username is not None and password is not None:
        request_arguments["auth"] = (username, password)

    return request_arguments

def load_baseline(baseline_path):
    with open(baseline_path, "rb") as f:
        baseline_json = f.read()
        baseline_json = baseline_json.replace(b"[green]", b"\u001b[92m")
        baseline_json = baseline_json.replace(b"[yellow]", b"\u001b[93m")
        baseline_json = baseline_json.replace(b"[red]", b"\u001b[91m")
        baseline_json = baseline_json.replace(b"[normal]", b"\u001b[0m")
        return json_loads(baseline_json)

def analyse_headers(headers, baseline, short=False):

    findings = []

    for b_header in baseline["headers"]:

        header_name = b_header["name"]
        header_value = headers.get(header_name)
        explanations = []

        if not short and b_header.get("description") is not None:
            explanations += [b_header["description"]]

        if header_value is None:
            explanations += [b_header["absent_explanation"]]
            rating = b_header.get("absent_rating", "bad")

        else:
            case_s_patterns = b_header.get("case_sensitive_patterns", False)

            if case_s_patterns:
                v_pattern = re.compile(b_header["validation_pattern"])
            else:
                v_pattern = re.compile(b_header["validation_pattern"], re.I)

            if not v_pattern.match(header_value):
                explanations += [b_header["invalid_explanation"]]
                rating = b_header.get("invalid_rating", "bad")

            else:
                rating = b_header.get("default_rating", "bad")

                for r_pattern in b_header.get("rating_patterns", []):

                    if case_s_patterns:
                        pattern = re.compile(r_pattern["pattern"])
                    else:
                        pattern = re.compile(r_pattern["pattern"], re.I)

                    if pattern.match(header_value):
                        rating = r_pattern["rating"]

                for e_pattern in b_header.get("explanation_patterns", []):

                    if case_s_patterns:
                        pattern = re.compile(e_pattern["pattern"])
                    else:
                        pattern = re.compile(e_pattern["pattern"], re.I)

                    if pattern.match(header_value):
                        exp = pattern.sub(e_pattern["present"], header_value)
                        explanations += [exp]

                    elif e_pattern.get("absent") is not None:
                        explanations += [e_pattern["absent"]]

        if b_header.get("final_explanation") is not None:
            explanations += [b_header["final_explanation"]]

        findings += [{
            "header": header_name,
            "value": header_value,
            "rating": rating,
            "explanations": explanations,
            "references": b_header["references"] if not short else []
            }]

    return findings

def main():
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

    parser.add_argument('-w', '--max-width', type=int,
            help="The maximum width of the output. Defaults to the screen"
            f" width ({get_terminal_size().columns} columns)",
            default=get_terminal_size().columns)
    
    parser.add_argument('url', help="The url to test")
    
    args = parser.parse_args()

    request_arguments = build_request_arguments(
            url                = args.url,
            method             = args.method,
            params             = args.params,
            timeout            = args.timeout,
            disallow_redirects = args.disallow_redirects,
            proxy              = args.proxy,
            verify             = args.verify,
            cert               = args.cert,
            data               = args.data,
            file               = args.file,
            headers            = args.headers,
            user_agent         = args.user_agent,
            cookies            = args.cookies,
            username           = args.username,
            password           = args.password
        )

    if not args.short:
        print_color("\nRequest parameters:", "blue")
        print(tabulate_dict(request_arguments, args.max_width))

    response = requests.request(**request_arguments)

    if not args.short:
        print_color("\nResponse:", "blue")
        print(tabulate_dict({
            "Length": len(response.content),
            "Status Code": response.status_code,
            "Reason": response.reason
            }, args.max_width))

    if not args.short:
        print_color("\nResponse headers:", "blue")
        print(tabulate_dict(response.headers, args.max_width))

    baseline = load_baseline(args.baseline_path)

    findings = analyse_headers(response.headers, baseline, args.short)

    print_color("Header analysis", "blue")
    print(tabulate_findings(findings, args.max_width))

    exit(0)

if __name__ == "__main__":
    main()

#X-XSS-PROTECTION	
if response.headers.get('x-xss-protection') == "1" or response.headers.get('x-xss-protection') == "1; mode=block" :	
        print_color('	[GOOD]	','green')
        print('X-XSS-Protection found, value : %s ' % response.headers.get('x-xss-protection'))
elif response.headers.get('x-xss-protection') :	
        print_color('	[BAD]	','red')
        print('X-XSS-Protection found but has wrong value: %s ' % response.headers.get('x-xss-protection'))
else:
        print_color('	[BAD]	','red')
        print('X-XSS-Protection header is missing')
#Content-Security-Policy   
if response.headers.get('Content-Security-Policy'):
        print_color('	[GOOD]	','green')
        print('Content-Security-Policy found, value : %s ' % response.headers.get('Content-Security-Policy'))
else:
        print_color('	[BAD]	','red')
        print('Content-Security-Policy header is missing')
#X-Content-Type-Options   
if response.headers.get('X-Content-Type-Options'):
        print_color('	[GOOD]	','green')
        print('X-Content-Type-Options found, value : %s ' % response.headers.get('X-Content-Type-Options'))
else:
        print_color('	[BAD]	','red')
        print('X-Content-Type-Options header is missing')
#Cache-control   
if response.headers.get('Cache-control'):
        print_color('	[GOOD]	','green')
        print('Cache-control found, value : %s ' % response.headers.get('Cache-control'))
else:
        print_color('	[BAD]	','red')
        print('Cache-control header is missing')
#server   
if response.headers.get('server'):
        print_color('	[BAD]	','red')
        print('Server found, value : %s ' % response.headers.get('server'))
#x-powered-by   
if response.headers.get('x-powered-by '):
        print_color('	[BAD]	','red')
        print('x-powered-by  found, value : %s ' % response.headers.get('x-powered-by '))	
print('Test ended\n')

print(tabulate([[c.name, "\\\n".join(wrap(c.value)), c.domain, c.path, strftime("%Y-%m-%d %H:%M:%S UTC", gmtime(c.expires)), c.secure, c.has_nonstandard_attr("HttpOnly")] for c in response.cookies], headers=["Name", "Value", "Domain", "Path", "Expires", "Secure", "HttpOnly"]))

