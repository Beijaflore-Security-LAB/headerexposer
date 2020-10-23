#!/usr/bin/env python3


import requests
import argparse
 
color_map = {
        'green':'\033[92m',
        'yellow':'\033[93m',
        'red':'\033[91m',
        'blue':'\033[94m',
        'magenta':'\033[95m'
        } 
			 
def print_color(text,color):
    print(color_map[color] + text + '\033[0m', end='')

parser = argparse.ArgumentParser()
parser.add_argument('URL', help="The url to test")
parser.add_argument('-H', '--headers', help="Add multiple, comma-separated headers to the list of headers")
parser.add_argument('-c', '--cookies', help="Add multiple, comma-separated cookies to the cookie jar")
parser.add_argument('-s', '--secure', action="store_true", help="Verify SSL certificates. Defaults to an insecure behavior")
parser.add_argument('-v', '--verb', help="HTTP verb to use for the request. Default: GET")
parser.add_argument('-d', '--data', help="Data to append to the request")
parser.add_argument('-p', '--proxy', help="Optional proxy to use")
parser.add_argument('-a', '--user-agent', help="User Agent to use. Defaults to a recent Google user agent", default="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1")
parser.parse_args()

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
