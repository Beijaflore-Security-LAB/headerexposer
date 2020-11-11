# HeaderExposer

Analyse the security of your website’s headers!

The headerexposer module provides functions to analyse the security
of a website’s headers.

It can be loaded as a module, or directly ran from the commandline.

# Requirements

TODO

# Installation

```
python -m pip install headerexposer
```

# CLI Usage

```
usage: headerexposer.py [-h] [-m {GET,OPTIONS,HEAD,POST,PUT,PATCH,DELETE}]
                        [--params PARAMS] [-d DATA | -f FILE] [-H HEADERS]
                        [-C COOKIES] [-U USERNAME] [-P PASSWORD] [-t TIMEOUT]
                        [-r] [-p PROXY] [-k] [-c CERT] [-b BASELINE_PATH]
                        [-a USER_AGENT] [-s] [--no-explanation-colors]
                        [-w MAX_WIDTH]
                        url

positional arguments:
  url                   The url to test

optional arguments:
  -h, --help            show this help message and exit
  -m {GET,OPTIONS,HEAD,POST,PUT,PATCH,DELETE}, --method {GET,OPTIONS,HEAD,POST,PUT,PATCH,DELETE}
                        HTTP method to use for the request. Default: "GET"
  --params PARAMS       Add multiple, ampersand-separated parameters to the
                        request
  -d DATA, --data DATA  Data to append to the request. Mutually exclusive with
                        --file
  -f FILE, --file FILE  Path to a file to append to the request. Mutually
                        exclusive with --data
  -H HEADERS, --headers HEADERS
                        Add multiple, newline-separated HTTP headers to the
                        request
  -C COOKIES, --cookies COOKIES
                        Add multiple, semicolon-separated cookies to the
                        request
  -U USERNAME, --username USERNAME
                        username to use in Basic/Digest/Custom HTTP
                        Authentication
  -P PASSWORD, --password PASSWORD
                        password to use in Basic/Digest/Custom HTTP
                        Authentication
  -t TIMEOUT, --timeout TIMEOUT
                        How many seconds to wait for the server to send data
                        before giving up, as float
  -r, --disallow-redirects
                        Disable GET/OPTIONS/POST/PUT/PATCH/DELETE/HEAD
                        redirection. Defaults to enabled redirection
  -p PROXY, --proxy PROXY
                        Proxy to use for the request
  -k, --verify          Verify SSL certificates. Defaults to an insecure
                        behavior
  -c CERT, --cert CERT  Optional path to the SSL client .pem certificate for
                        client authentication
  -b BASELINE_PATH, --baseline-path BASELINE_PATH
                        Path to the baseline.json file for the header analysis
  -a USER_AGENT, --user-agent USER_AGENT
                        User Agent to use. Defaults to a recent Google Chrome
                        user agent
  -s, --short           Shorten the output. Do not print the request
                        parameters, do not print the response details, do not
                        print headers' descriptions, do not print references.
  --no-explanation-colors
                        Suppress colors in explanations, except in reference
                        links.
  -w MAX_WIDTH, --max-width MAX_WIDTH
                        The maximum width of the output. Defaults to the
                        screen width (80 columns)
```

# Basic module usage

```
>>> import headerexposer as hdrexp
>>> import requests

>>> baseline = hdrexp.load_baseline("baseline.json")

>>> response = requests.get("https://google.com")

>>> findings = hdrexp.analyse_headers(response.headers, baseline, short=True)

>>> print(hdrexp.tabulate_findings(findings))
Header                     Value       Rating      Explanation
-------------------------  ----------  ----------  -------------------------------------------
Strict-Transport-Security  Absent      [ＢＡＤ]    The header is absent.  It is
                                                   recommended to set the header's value to
                                                   "max-age=31536000; includeSubDomains;
                                                   preload". This will tell users'
                                                   browsers that...
...
```

# Authors

Alexandre Janvrin (alexandre.janvrin@reseau.eseo.fr, ajanvrin520@beijaflore.com). I am currently a Penetration Tester and Cybersecurity Consultant at Beijaflore (https://www.beijaflore.com/en/)

# License

AGPLv3+, see LICENSE for more details.

# URLs

* https://pypi.org/project/headerexposer/
* https://github.com/LivinParadoX/headerexposer/
