# headerexposer
Python3 cmd line tool to scan Security HTTP headers

Usage : headerexposer $URL

PyPI url: https://pypi.org/project/headerexposer/
GitHub url: https://github.com/LivinParadoX/headerexposer/

# Welcome to HeaderExposer’s documentation!

Analyse the security of your website’s headers!

The headerexposer module provides functions to analyse the security
of a website’s headers.

It can be loaded as a module, or directly ran from the commandline.

For commandline usage, see the output of:
python3 -m headerexposer –help

Basic module usage:

```python
>>> import headerexposer as hdrexp
>>> import requests
```

```python
>>> baseline = hdrexp.load_baseline("baseline.json")
```

```python
>>> response = requests.get("https://google.com")
```

```python
>>> findings = hdrexp.analyse_headers(response.headers,
...                                   baseline,
...                                   short=True)
```

```python
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


* **copyright**

    
    1. 2020 Alexandre Janvrin.



* **license**

    AGPLv3+, see LICENSE for more details.



### headerexposer.analyse_header(header_value: Any, header_baseline: dict)
Analyses a single valid header according to the baseline.


* **Parameters**

    
    * **header_value** – (string) The header’s value


    * **header_baseline** – The header’s baseline as loaded by


load_baseline()
:return: ((string) rating, List[string] explanations) The header’s
rating and the list of explanations to print.


### headerexposer.analyse_headers(headers: dict, baseline: dict, short: bool = False)
Analyse response headers according to baseline.

This function compares headers’ values to the baseline headers to
produce a security analysis. Basically, it parses the baseline for
regex patterns to identify in the headers’ values, and returns the
ratings and explanations associated in the baseline.


* **Parameters**

    
    * **headers** – The headers to analyse.


    * **baseline** – The baseline to compare the headers’ values


against. It should be loaded from load_baseline.
:param short: If True, the headers’ descriptions and references as
contained in the baseline will not be added to the explanations.
:return: The list of findings, each finding being a dict like this:

> {

>     “header”: (string) header_name,
>     “value”: (string) header_value,
>     “rating”: (string) rating,
>     “explanations”: (List[string]) explanations,
>     “references”: (List[string]) references

> }


### headerexposer.b_special_to_ansi(bstring: bytes, no_colors: Optional[bool] = False)
Replace tags to their corresponding ANSI codes in bytestrings.

The following tags are currently supported:
[red], [green], [yellow], [blue], [magenta], [underline], [normal]


* **Parameters**

    
    * **bstring** – The bytestring in which to replace the tags.


    * **no_colors** – If this is True, all tags will be removed.



* **Returns**

    The string with tags replaced or stripped.



### headerexposer.load_baseline(baseline_path: str, no_colors: Optional[bool] = False)
Load and validate baseline.json.

This function loads the baseline.json, replaces special markings
such as [green] to their corresponding ANSI codes, and validates it
against baseline_schema.json.


* **Parameters**

    **baseline_path** – the absolute or relative path to the baseline


file.
:param no_colors: If True, the special tags such as [red] will be
stripped from the baseline file, which essentially means that
explanations will not be color-coded (but references and ratings
will still be, as they are they are colored by headerexposer and
not in the baseline).
:return: the baseline dict loaded from baseline.json.


### headerexposer.parse_request_cookies(cookies: Optional[str])
Parse a cookies string into a dict.


* **Parameters**

    **cookies** – A string representing the cookies to parse, such


as “cookie1=value1; cookie2=value2”, or None.
:return: A dict of cookie_name: cookie_value pairs. Returns None
if cookies is None.


### headerexposer.parse_request_headers(headers: Optional[str])
Parse a headers string into a dict.


* **Parameters**

    **cookies** – A string representing the headers to parse, such


as “header1: value1nheader2: value2”, or None.
:return: A dict of header_name: header_value pairs. Returns an
empty dict if headers is None.


### headerexposer.parse_request_parameters(params: Optional[str])
Parse a parameters string into a dict.


* **Parameters**

    **params** – A string representing the parameters to parse, such


as “param1=value1&param2=value2”, or None.
:return: A dict of parameter_name: parameter_value pairs. Returns
None if params is None.


### headerexposer.print_special(text: str)
Print a string after replacing its special tags.

The tags such as [green] will be replaced with their corresponding
ANSI codes. The following tags are currently supported:
[red], [green], [yellow], [blue], [magenta], [underline], [normal]


* **Parameters**

    **text** – The text to print.



### headerexposer.special_to_ansi(string: str, no_colors: Optional[bool] = False)
Replace tags to their corresponding ANSI codes in strings.

The following tags are currently supported:
[red], [green], [yellow], [blue], [magenta], [underline], [normal]


* **Parameters**

    
    * **string** – The string in which to replace the tags.


    * **no_colors** – If this is True, all tags will be removed.



* **Returns**

    The string with tags replaced or stripped.



### headerexposer.string_to_dict(string: str, delimiter_1: str, delimiter_2: str)
Parse a string into a dict by splitting around delimiters.

This function parses a string into a dict by splitting it around
delimiters, and eliminating superfluous white spaces.

For example, “param1: value1; param2: value2” with ‘:’ as
delimiter_1 and ‘;’ as delimiter_2 will be parsed into
{

> “param1”: “value1”,
> “param2”: “value2”

}

WARNING: This function WILL raise IndexError if the input string
cannot be parsed.


* **Parameters**

    
    * **string** – The string to parse.


    * **delimiter_1** – The delimiter which separates the key: value


pairs.
:param delimiter_2: The delimiter which separates the keys from
the values.
:return: The dict of key: value pairs.


### headerexposer.tabulate_dict(dictionary: dict, max_width: int = None)
Format a dict as a two-columns table.

This function formats a dict as a two-columns table, where the
first column is the dict keys and the second column is the values.
It wraps the value column to not produce a table wider than
max_width.


* **Parameters**

    
    * **dictionary** – The dict to turn into a nice table.


    * **max_width** – If specified, the function will try to wrap the


values in order to not produce a table wider than max_width
characters.
:return: The nice table ready for printing.


### headerexposer.tabulate_findings(findings: list, max_width: Optional[int] = None)
Format the findings in a nice table for printing.


* **Parameters**

    **findings** – The list of finding items to format. This should


come from the analyse_headers() function.
:param max_width: If specified, the function will try to produce a
table at most max_width characters wide.
:return: The string representing the nice findings table. Usually
ready for printing.

# Indices and tables


* Index


* Module Index


* Search Page
