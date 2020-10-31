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
import json
import re

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

WIDTH = get_terminal_size().columns // 80 * 80

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

def build_request_arguments(
        url,
        method="GET",
        params=None,
        timeout=None,
        disallow_redirects=False,
        proxy=None,
        verify=False,
        cert=None,
        data=None,
        file=None,
        headers=None,
        user_agent=None,
        cookies=None,
        username=None,
        password=None
        ):

    if data is not None and file is not None:
        print("Error in build_request_arguments:"
                " raise and file arguments are mutually exclusive")
        exit(1)

    request_arguments = {
            "method": method,
            "url": url,
            "params": None,
            "data": None,
            "headers": {},
            "cookies": None,
            "auth": None,
            "timeout": timeout,
            "allow_redirects": not disallow_redirects,
            "proxies": {"http": proxy, "https": proxy},
            "verify": verify,
            "cert": cert
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
    
    parser.add_argument('-a', '--user-agent',
            help="User Agent to use."
            " Defaults to a recent Google Chrome user agent",
            default="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1"
            " (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1")
    
    parser.add_argument('-s', '--short', action="store_true",
            help="Shorten the output. Do not print the request parameters,"
            " do not print the response details,"
            " do not print headers' descriptions, do not print references.")
    
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
        print(tabulate([[k, "\\\n".join((wrap(str(v), width=WIDTH)))] for k, v in request_arguments.items()]))

    response = requests.request(**request_arguments)

    if not args.short:
        print_color("\nResponse:", "blue")
        print(tabulate([["Length", len(response.content)], ["Status Code", response.status_code], ["Reason", response.reason]]))

    if not args.short:
        print_color("\nResponse headers:", "blue")
        print(tabulate([[k, "\\\n".join((wrap(str(v), width=WIDTH)))] for k, v in response.headers.items()]))

    findings = []

    with open("baseline.json", "rb") as f:
        baseline_json = f.read()
        baseline_json = baseline_json.replace(b"[green]", b"\u001b[92m")
        baseline_json = baseline_json.replace(b"[yellow]", b"\u001b[93m")
        baseline_json = baseline_json.replace(b"[red]", b"\u001b[91m")
        baseline_json = baseline_json.replace(b"[normal]", b"\u001b[0m")
        baseline = json.loads(baseline_json)

    for header_baseline in baseline["headers"]:

        header_name = header_baseline["name"]
        header_value = response.headers.get(header_name.lower())
        explanations = []

        if not args.short and header_baseline.get("description") is not None:
            explanations += [header_baseline["description"]]

        if header_value is None:
            explanations += [header_baseline["absent_explanation"]]
            rating = header_baseline.get("absent_rating", "bad")

        else:
            case_sentitive_patterns = header_baseline.get("case_sentitive_patterns", False)

            if case_sentitive_patterns:
                validation_pattern = re.compile(header_baseline["validation_pattern"])
            else:
                validation_pattern = re.compile(header_baseline["validation_pattern"], re.IGNORECASE)

            if not validation_pattern.match(header_value):
                explanations += [header_baseline["invalid_explanation"]]
                rating = header_baseline.get("invalid_rating", "bad")

            else:
                rating = header_baseline.get("default_rating", "bad")

                for rating_pattern in header_baseline.get("rating_patterns", []):

                    if case_sentitive_patterns:
                        pattern = re.compile(rating_pattern["pattern"])
                    else:
                        pattern = re.compile(rating_pattern["pattern"], re.IGNORECASE)

                    if pattern.match(header_value):
                        rating = rating_pattern["rating"]

                for explanation_pattern in header_baseline.get("explanation_patterns", []):

                    if case_sentitive_patterns:
                        pattern = re.compile(explanation_pattern["pattern"])
                    else:
                        pattern = re.compile(explanation_pattern["pattern"], re.IGNORECASE)

                    if pattern.match(header_value):
                        explanations += [pattern.sub(explanation_pattern["present"], header_value)]

                    elif explanation_pattern.get("absent") is not None:
                        explanations += [explanation_pattern["absent"]]

        if header_baseline.get("final_explanation") is not None:
            explanations += [header_baseline["final_explanation"]]

        finding_value = "\\\n".join(wrap(header_value)) if header_value is not None else "Absent"
        finding_rating = RATINGS.get(rating.lower())

        paragraphs = " ".join(explanations).splitlines()
        finding_explanation = "\n".join(["\n".join(wrap(p)) for p in paragraphs])

        if not args.short and header_baseline.get("references", []) != []:
            ref_lines = "\n".join(["\n".join(wrap(r)) for r in header_baseline["references"]]).splitlines()
            finding_explanation += "\nReferences:\n\033[4;94m" + "\033[0m\n\033[4;94m".join(ref_lines) + "\033[0m"

        findings += [[header_name, finding_value, finding_rating, finding_explanation]]

    print_color("Header analysis", "blue")

    print(tabulate(findings, headers=["Header", "Value", "Rating", "Explanation"]))

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

