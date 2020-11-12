# HeaderExposer

## Module contents:

### __init__.py

This is the core of the module. It contains most of the module's logic.

### __main__.py

This is the module's CLI. It contains the banner, the argument parsing logic, and the main CLI functions.

### baseline.json

This is the most important file used for header analysis. It contains the headers' descriptions, analysis patterns, ratings, etc.

### baseline_schema.json

This file is used to validate baseline.json, and also serves as its documentation.

### old.py

This soon-to-be-removed file contains a portion of the old code for reference purposes.

## Module documentation:

### headerexposer.analyse_header(header_value: Any, header_baseline: dict)
Analyses a single valid header according to the baseline.


* **Parameters**

    
    * **header_value** – (string) The header’s value


    * **header_baseline** – The header’s baseline as loaded by load_baseline()



* **Returns**

    ((str) rating, List[str] explanations) The header’s rating and
    the list of explanations to print.



### headerexposer.analyse_headers(headers: dict, baseline: dict, short: bool = False)
Analyse response headers according to baseline.

This function compares headers’ values to the baseline headers to
produce a security analysis. Basically, it parses the baseline for
regex patterns to identify in the headers’ values, and returns the
ratings and explanations associated in the baseline.


* **Parameters**

    
    * **headers** – The headers to analyse.


    * **baseline** – The baseline to compare the headers’ values against. It
    should be loaded from load_baseline().


    * **short** – If True, the headers’ descriptions and references as
    contained in the baseline will not be added to the
    explanations.



* **Returns**

    The list of findings, each finding being a dict like this:
    {

        “header”: (string) header_name,
        “value”: (string) header_value,
        “rating”: (string) rating,
        “explanations”: (List[string]) explanations,
        “references”: (List[string]) references

    }



### headerexposer.b_special_to_ansi(bstring: bytes, no_colors: Optional[bool] = False)
Replace tags to their corresponding ANSI codes in bytestrings.

The following tags are currently supported:
[red], [green], [yellow], [blue], [magenta], [underline], [normal]


* **Parameters**

    
    * **bstring** – The bytestring in which to replace the tags.


    * **no_colors** – If this is True, all tags will be removed instead of being
    replaced.



* **Returns**

    The string with tags replaced or stripped.



### headerexposer.load_baseline(baseline_path: str, no_colors: Optional[bool] = False)
Load and validate baseline.json.

This function loads the baseline.json, replaces special markings
such as [green] to their corresponding ANSI codes, and validates it
against baseline_schema.json.


* **Parameters**

    
    * **baseline_path** – the absolute or relative path to the baseline file.


    * **no_colors** – If True, the special tags such as [red] will be stripped from
    the baseline file, which essentially means that explanations
    will not be color-coded (but references and ratings will
    still be, as they are they are colored by headerexposer and
    not in the baseline).



* **Returns**

    the baseline dict loaded from baseline.json.



### headerexposer.parse_request_cookies(cookies: Optional[str])
Parse a cookies string into a dict.


* **Parameters**

    **cookies** – A string representing the cookies to parse, such as
    “cookie1=value1; cookie2=value2”, or None.



* **Returns**

    A dict of cookie_name: cookie_value pairs. Returns None if
    cookies is None.



* **Raises**

    **IndexError if the input cookies string cannot be parsed.** – 



### headerexposer.parse_request_headers(headers: Optional[str])
Parse a headers string into a dict.


* **Parameters**

    **headers** – A string representing the headers to parse, such as
    “header1: value1nheader2: value2”, or None.



* **Returns**

    A dict of header_name: header_value pairs. Returns an empty
    dict if headers is None.



* **Raises**

    **IndexError if the input headers string cannot be parsed.** – 



### headerexposer.parse_request_parameters(params: Optional[str])
Parse a parameters string into a dict.


* **Parameters**

    **params** – A string representing the parameters to parse, such as
    “param1=value1&param2=value2”, or None.



* **Returns**

    A dict of parameter_name: parameter_value pairs. Returns None
    if params is None.



* **Raises**

    **IndexError if the input params string cannot be parsed.** – 



### headerexposer.print_special(text: str)
Print a string after replacing its special tags.

The tags such as [green] will be replaced with their corresponding
ANSI codes. The following tags are currently supported:
[red], [green], [yellow], [blue], [magenta], [underline], [normal]


* **Parameters**

    **text** – The text to print.



### headerexposer.safe_wrap(text: str, width: int = 70, \*\*kwargs)
Wrap a paragraph of text, returning a list of wrapped lines.

Reformat the single paragraph in ‘text’ so it fits in lines of no
more than ‘width’ columns, and return a list of wrapped lines.  By
default, tabs in ‘text’ are expanded with string.expandtabs(), and
all other whitespace characters (including newline) are converted
to space.  See textwrap’s TextWrapper class for available keyword
args to customize wrapping behavior.

This function is actually a wrapper (no pun intended) around
ansiwrap’s wrap() function. It ensures than no dangling ANSI code
is present at the end of a line, in order to eliminate unwanted
color behavior such as color being applied to surrounding columns
in a table. When a non-zero ANSI code is found in a string without
a closing zero ANSI code, a zero ANSI code is appended to the
string and the previously found ANSI code is prepended to the next
line.


* **Parameters**

    
    * **text** – The long text to wrap.


    * **width** – The maximum width of each line.


    * **kwargs** – See help(“textwrap.TextWrapper”) for a list of keyword
    arguments to customize wrapper behavior.



### headerexposer.special_to_ansi(string: str, no_colors: Optional[bool] = False)
Replace tags to their corresponding ANSI codes in strings.

The following tags are currently supported:
[red], [green], [yellow], [blue], [magenta], [underline], [normal]


* **Parameters**

    
    * **string** – The string in which to replace the tags.


    * **no_colors** – If this is True, all tags will be removed instead of being
    replaced.



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


* **Parameters**

    
    * **string** – The string to parse.


    * **delimiter_1** – The delimiter which separates the key: value pairs.


    * **delimiter_2** – The delimiter which separates the keys from the values.



* **Returns**

    The dict of key: value pairs.


* **Raises**

    **IndexError if the input string cannot be parsed.** – 



### headerexposer.tabulate_dict(dictionary: dict, max_width: int = None)
Format a dict as a two-columns table.

This function formats a dict as a two-columns table, where the
first column is the dict keys and the second column is the values.
It wraps the value column to not produce a table wider than
max_width.


* **Parameters**

    
    * **dictionary** – The dict to turn into a nice table.


    * **max_width** – If specified, the function will try to wrap the values in
    order to not produce a table wider than max_width characters.



* **Returns**

    The nice table ready for printing.



### headerexposer.tabulate_findings(findings: list, max_width: Optional[int] = None)
Format the findings in a nice table for printing.


* **Parameters**

    
    * **findings** – The list of finding items to format. This should come from
    the analyse_headers() function.


    * **max_width** – If specified, the function will try to produce a table at
    most max_width characters wide.



* **Returns**

    The string representing the nice findings table. Usually ready
    for printing.



### headerexposer.wrap_and_join(text: str, width: int = 70, sep: str = '\\n', \*\*kwargs)
Wrap a paragraph of text around a separator.

Reformat the single paragraph in ‘text’ so it fits in lines of no
more than ‘width’ columns, and return a list of wrapped lines
joined around a separator.  By default, tabs in ‘text’ are expanded
with string.expandtabs(), and all other whitespace characters
(including newline) are converted to space.  See textwrap’s
TextWrapper class for available keyword args to customize wrapping
behavior.


* **Parameters**

    
    * **text** – The long text to wrap.


    * **width** – The maximum width of each line.


    * **sep** – The delimiter around which the lines will be joined.


    * **kwargs** – See help(“textwrap.TextWrapper”) for a list of keyword
    arguments to customize wrapper behavior.
