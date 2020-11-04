# HeaderExposer
Analyse the security of your website’s headers!

The headerexposer module provides functions to analyse the security
of a website’s headers.

It can be loaded as a module, or directly ran from the commandline.

# Arguments and Usage
## Usage
```
usage: argdown.py [-h] [-m {GET,OPTIONS,HEAD,POST,PUT,PATCH,DELETE}]
                  [--params PARAMS] [-d DATA | -f FILE] [-H HEADERS]
                  [-C COOKIES] [-U USERNAME] [-P PASSWORD] [-t TIMEOUT] [-r]
                  [-p PROXY] [-k] [-c CERT] [-b BASELINE_PATH] [-a USER_AGENT]
                  [-s] [--no-explanation-colors] [-w MAX_WIDTH]
                  url
```
## Arguments
### Quick reference table
|Short|Long                     |Default                                                                                                     |Description                                                                                                                                             |
|-----|-------------------------|------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
|`-h` |`--help`                 |                                                                                                            |show this help message and exit                                                                                                                         |
|`-m` |`--method`               |`GET`                                                                                                       |HTTP method to use for the request. Default: "GET"                                                                                                      |
|     |`--params`               |`None`                                                                                                      |Add multiple, ampersand-separated parameters to the request                                                                                             |
|`-d` |`--data`                 |`None`                                                                                                      |Data to append to the request. Mutually exclusive with --file                                                                                           |
|`-f` |`--file`                 |`None`                                                                                                      |Path to a file to append to the request. Mutually exclusive with --data                                                                                 |
|`-H` |`--headers`              |`None`                                                                                                      |Add multiple, newline-separated HTTP headers to the request                                                                                             |
|`-C` |`--cookies`              |`None`                                                                                                      |Add multiple, semicolon-separated cookies to the request                                                                                                |
|`-U` |`--username`             |`None`                                                                                                      |username to use in Basic/Digest/Custom HTTP Authentication                                                                                              |
|`-P` |`--password`             |`None`                                                                                                      |password to use in Basic/Digest/Custom HTTP Authentication                                                                                              |
|`-t` |`--timeout`              |`None`                                                                                                      |How many seconds to wait for the server to send data before giving up, as float                                                                         |
|`-r` |`--disallow-redirects`   |                                                                                                            |Disable GET/OPTIONS/POST/PUT/PATCH/DELETE/HEAD redirection. Defaults to enabled redirection                                                             |
|`-p` |`--proxy`                |`None`                                                                                                      |Proxy to use for the request                                                                                                                            |
|`-k` |`--verify`               |                                                                                                            |Verify SSL certificates. Defaults to an insecure behavior                                                                                               |
|`-c` |`--cert`                 |`None`                                                                                                      |Optional path to the SSL client .pem certificate for client authentication                                                                              |
|`-b` |`--baseline-path`        |`baseline.json`                                                                                             |Path to the baseline.json file for the header analysis                                                                                                  |
|`-a` |`--user-agent`           |`Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1`|User Agent to use. Defaults to a recent Google Chrome user agent                                                                                        |
|`-s` |`--short`                |                                                                                                            |Shorten the output. Do not print the request parameters, do not print the response details, do not print headers' descriptions, do not print references.|
|     |`--no-explanation-colors`|                                                                                                            |Suppress colors in explanations, except in reference links.                                                                                             |
|`-w` |`--max-width`            |`80`                                                                                                        |The maximum width of the output. Defaults to the screen width (80 columns)                                                                              |

### `-h`, `--help`
show this help message and exit

### `-m`, `--method` (Default: GET)
HTTP method to use for the request. Default: "GET"

### `--params` (Default: None)
Add multiple, ampersand-separated parameters to the request

### `-d`, `--data` (Default: None)
Data to append to the request. Mutually exclusive with --file

### `-f`, `--file` (Default: None)
Path to a file to append to the request. Mutually exclusive with --data

### `-H`, `--headers` (Default: None)
Add multiple, newline-separated HTTP headers to the request

### `-C`, `--cookies` (Default: None)
Add multiple, semicolon-separated cookies to the request

### `-U`, `--username` (Default: None)
username to use in Basic/Digest/Custom HTTP Authentication

### `-P`, `--password` (Default: None)
password to use in Basic/Digest/Custom HTTP Authentication

### `-t`, `--timeout` (Default: None)
How many seconds to wait for the server to send data before giving up, as
float

### `-r`, `--disallow-redirects`
Disable GET/OPTIONS/POST/PUT/PATCH/DELETE/HEAD redirection. Defaults to
enabled redirection

### `-p`, `--proxy` (Default: None)
Proxy to use for the request

### `-k`, `--verify`
Verify SSL certificates. Defaults to an insecure behavior

### `-c`, `--cert` (Default: None)
Optional path to the SSL client .pem certificate for client authentication

### `-b`, `--baseline-path` (Default: baseline.json)
Path to the baseline.json file for the header analysis

### `-a`, `--user-agent` (Default: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1)
User Agent to use. Defaults to a recent Google Chrome user agent

### `-s`, `--short`
Shorten the output. Do not print the request parameters, do not print the
response details, do not print headers' descriptions, do not print references.

### `--no-explanation-colors`
Suppress colors in explanations, except in reference links.

### `-w`, `--max-width` (Default: 80)
The maximum width of the output. Defaults to the screen width (80 columns)


# Basic module usage:

```python
>>> import headerexposer as hdrexp
>>> import requests

>>> baseline = hdrexp.load_baseline("baseline.json")

>>> response = requests.get("https://google.com")

>>> findings = hdrexp.analyse_headers(response.headers,
...                                   baseline,
...                                   short=True)

>>> print(hdrexp.tabulate_findings(findings))
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
```


# Authors

Alexandre Janvrin. I am currently a Penetration Tester and Cybersecurity
Consultant at Beijaflore (https://www.beijaflore.com/en/)



# License

AGPLv3+, see LICENSE for more details.

# URLs

PyPI url: https://pypi.org/project/headerexposer/
GitHub url: https://github.com/LivinParadoX/headerexposer/
