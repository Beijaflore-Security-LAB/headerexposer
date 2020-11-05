#X-XSS-PROTECTION
if response.headers.get('x-xss-protection') == "1" or response.headers.get('x-xss-protection') == "1; mode=block" :
        print_color('   [GOOD]  ','green')
        print('X-XSS-Protection found, value : %s ' % response.headers.get('x-xss-protection'))
elif response.headers.get('x-xss-protection') :
        print_color('   [BAD]   ','red')
        print('X-XSS-Protection found but has wrong value: %s ' % response.headers.get('x-xss-protection'))
else:
        print_color('   [BAD]   ','red')
        print('X-XSS-Protection header is missing')
#Content-Security-Policy
if response.headers.get('Content-Security-Policy'):
        print_color('   [GOOD]  ','green')
        print('Content-Security-Policy found, value : %s ' % response.headers.get('Content-Security-Policy'))
else:
        print_color('   [BAD]   ','red')
        print('Content-Security-Policy header is missing')
#X-Content-Type-Options
if response.headers.get('X-Content-Type-Options'):
        print_color('   [GOOD]  ','green')
        print('X-Content-Type-Options found, value : %s ' % response.headers.get('X-Content-Type-Options'))
else:
        print_color('   [BAD]   ','red')
        print('X-Content-Type-Options header is missing')
#Cache-control
if response.headers.get('Cache-control'):
        print_color('   [GOOD]  ','green')
        print('Cache-control found, value : %s ' % response.headers.get('Cache-control'))
else:
        print_color('   [BAD]   ','red')
        print('Cache-control header is missing')
#server
if response.headers.get('server'):
        print_color('   [BAD]   ','red')
        print('Server found, value : %s ' % response.headers.get('server'))
#x-powered-by
if response.headers.get('x-powered-by '):
        print_color('   [BAD]   ','red')
        print('x-powered-by  found, value : %s ' % response.headers.get('x-powered-by '))
print('Test ended\n')

print(tabulate([[c.name, "\\\n".join(wrap(c.value)), c.domain, c.path, strftime("%Y-%m-%d %H:%M:%S UTC", gmtime(c.expires)), c.secure, c.has_nonstandard_attr("HttpOnly")] for c in response.cookies], headers=["Name", "Value", "Domain", "Path", "Expires", "Secure", "HttpOnly"]))
