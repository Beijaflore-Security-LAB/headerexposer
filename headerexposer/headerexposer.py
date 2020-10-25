#!/usr/bin/env python3


import requests
from argparse import ArgumentParser
from sys import exit
from pprint import pprint

color_map = {
        'green':'\033[92m',
        'yellow':'\033[93m',
        'red':'\033[91m',
        'blue':'\033[94m',
        'magenta':'\033[95m'
        } 
			 
def print_color(text,color):
    print(color_map[color] + text + '\033[0m', end='')

parser = ArgumentParser()
parser.add_argument('-m', '--method', help='HTTP method to use for the request. Default: "GET"', choices=["GET", "OPTIONS", "HEAD", "POST", "PUT", "PATCH", "DELETE"], default="GET")
parser.add_argument('--params', help="Add multiple, ampersand-separated parameters to the request")
group = parser.add_mutually_exclusive_group()
group.add_argument('-d', '--data', help="Data to append to the request. Mutually exclusive with --file")
group.add_argument('-f', '--file', help="Path to a file to append to the request. Mutually exclusive with --data")
parser.add_argument('-H', '--headers', help="Add multiple, newline-separated HTTP headers to the request")
parser.add_argument('-C', '--cookies', help="Add multiple, semicolon-separated cookies to the request")
parser.add_argument('-U', '--username', help="username to use in Basic/Digest/Custom HTTP Authentication")
parser.add_argument('-P', '--password', help="password to use in Basic/Digest/Custom HTTP Authentication")
parser.add_argument('-t', '--timeout', type=float, help="How many seconds to wait for the server to send data before giving up, as float")
parser.add_argument('-r', '--disallow-redirects', action="store_false", help="Disable GET/OPTIONS/POST/PUT/PATCH/DELETE/HEAD redirection. Defaults to enabled redirection")
parser.add_argument('-p', '--proxy', help="Proxy to use for the request")
parser.add_argument('-v', '--verify', action="store_true", help="Verify SSL certificates. Defaults to an insecure behavior")
parser.add_argument('-c', '--cert', help="Optional path to the SSL client .pem certificate for client authentication")
parser.add_argument('-a', '--user-agent', help="User Agent to use. Defaults to a recent Google Chrome user agent", default="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1")
parser.add_argument('URL', help="The url to test")
args = parser.parse_args()

params = {}
if args.params is not None:
    try:
        for p in args.params.strip().split('&'):
            params[p.split('=')[0].strip()] = p.split('=')[1].strip()
    except IndexError:
        print("Parameters must be formatted as couples of values such as param1=value1&param2=value2 etc.")
        print("Bad parameters: " + args.params)
        exit(1)

data = b''
if args.data is not None:
    data = args.data.encode()
elif args.file is not None:
    with open(args.file, 'rb') as f:
        data = f.read()

headers = {}
if args.headers is not None:
    try:
        for h in args.headers.strip().split('\n'):
            headers[h.split(':')[0].strip()] = h.split(':')[1].strip()
    except IndexError:
        print('Headers must be formatted as couples of values such as "header1: value1"  etc.')
        print("Bad headers:")
        print(args.headers)
        exit(1)

cookies = {}
if args.cookies is not None:
    try:
        for c in args.cookies.strip().split('\n'):
            cookies[c.split(':')[0].strip()] = c.split(':')[1].strip()
    except IndexError:
        print('Cookies must be formatted as couples of values such as "cookie1: value1"  etc.')
        print("Bad cookies:")
        print(args.cookies)
        exit(1)

print("Parameters:")
pprint(params)
print("Data:")
pprint(data)
print("Headers:")
pprint(headers)

exit(0)

burp0_url = "https://url"
burp0_cookies = {"__id": "d6", "__lb": "jqqZuM"}
burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "application/json, text/plain, */*", "Accept-Language": "en", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Referer": "https://budah-preprod.dpsin.dpdgroup.com/dashboard"}
requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)

session = requests.session()



burp0_json={"@id": "1", "pageRequest": {"page": 0, "size": 10, "sort": "createdOn,DESC"}}
session.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, json=burp0_json)

myssl = ssl.create_default_context();
myssl.check_hostname=False
myssl.verify_mode=ssl.CERT_NONE
req = urllib.request.Request(url, headers=hdr)
response = urllib.request.urlopen(req, context=myssl)
print_color('\nAnalyze headers of ' + sys.argv[1] +'\n', 'blue')
print('Test occured at : %s' % response.info().get('date'))
#X-XSS-PROTECTION	
if response.info().get('x-xss-protection') == "1" or response.info().get('x-xss-protection') == "1; mode=block" :	
        print_color('	[GOOD]	','green')
        print('X-XSS-Protection found, value : %s ' % response.info().get('x-xss-protection'))
elif response.info().get('x-xss-protection') :	
        print_color('	[BAD]	','red')
        print('X-XSS-Protection found but has wrong value: %s ' % response.info().get('x-xss-protection'))
else:
        print_color('	[BAD]	','red')
        print('X-XSS-Protection header is missing')
#Strict-transport-security 
if response.info().get('Strict-transport-security'):
        print_color('	[GOOD] ','green')
        print('Strict-transport-security found, value: %s ' % response.info().get('Strict-transport-security'))
else:
        print_color('	[BAD]	','red')
        print('Strict-transport-security header is missing')
#X-Frame-Options  
if response.info().get('X-Frame-Options') == "DENY":
        print_color('	[GOOD]	','green')
        print('X-Frame-Options found, value : %s ' % response.info().get('X-Frame-Options'))
elif response.info().get('X-Frame-Options') == "SAMEORIGIN":
        print_color('	[GOOD]	','green')
        print('X-Frame-Options found, value : %s ' % response.info().get('X-Frame-Options'))	
elif response.info().get('X-Frame-Options') :	
        print_color('	[BAD]	','red')
        print('X-Frame-Options found but has wrong value: %s ' % response.info().get('X-Frame-Options'))
else:
        print_color('	[BAD]	','red')
        print('X-Frame-Options header is missing')
#Content-Security-Policy   
if response.info().get('Content-Security-Policy'):
        print_color('	[GOOD]	','green')
        print('Content-Security-Policy found, value : %s ' % response.info().get('Content-Security-Policy'))
else:
        print_color('	[BAD]	','red')
        print('Content-Security-Policy header is missing')
#X-Content-Type-Options   
if response.info().get('X-Content-Type-Options'):
        print_color('	[GOOD]	','green')
        print('X-Content-Type-Options found, value : %s ' % response.info().get('X-Content-Type-Options'))
else:
        print_color('	[BAD]	','red')
        print('X-Content-Type-Options header is missing')
#Cache-control   
if response.info().get('Cache-control'):
        print_color('	[GOOD]	','green')
        print('Cache-control found, value : %s ' % response.info().get('Cache-control'))
else:
        print_color('	[BAD]	','red')
        print('Cache-control header is missing')
#server   
if response.info().get('server'):
        print_color('	[BAD]	','red')
        print('Server found, value : %s ' % response.info().get('server'))
#x-powered-by   
if response.info().get('x-powered-by '):
        print_color('	[BAD]	','red')
        print('x-powered-by  found, value : %s ' % response.info().get('x-powered-by '))	
print('Test ended\n')
