# HeaderExposer

Analyse the security of your website’s headers!

The headerexposer module provides functions to analyse the security
of a website’s headers.

It can be loaded as a module, or directly ran from the commandline.

It is designed to be cross-platforms, and was tested in various Linux/Windows terminals.

# Requirements

These requirements will automatically be installed upon headerexposer's installation with pip.

* ansiwrap: The standard textwrap module does not support ANSI codes, hence the use of ansiwrap as a replacement.
* colorama: This is only used for color compatibility on Microsoft platforms.
* jsonschema: This is used for json validation.
* requests: Used in the module's CLI for performing HTTP requests.
* tabulate: Used for printing nice tables.
* urllib3: (normally a dependency of requests) This is only used to intentionally suppress a specific warning.

# Installation

Let pip take care of everything:
```
python -m pip install headerexposer
```

# CLI Usage

Global usage:
```
usage: headerexposer [-h] [-b BASELINE_PATH] [-s] [--no-explanation-colors]               
                     [-w MAX_WIDTH]                                                       
                     {analyse,demo,show} ...                                              
                                                                                          
Analyse the security of your website's headers!                                           
                                                                                          
optional arguments:                                                                       
  -h, --help            show this help message and exit                                   
  -b BASELINE_PATH, --baseline-path BASELINE_PATH                                         
                        Path to the baseline.json file for the header analysis (default:  
                        /home/aja/.local/lib/python3.8/site-                              
                        packages/headerexposer/baseline.json).                            
                                                                                          
commands:                                                                                 
  Use [command] -h for additional help.                                                   
                                                                                          
  {analyse,demo,show}                                                                     
    analyse             Analyse a given url's headers.                                    
    demo                Show a demonstration of what would be printed for sample headers  
                        with the selected baseline.json.                                  
    show                Show the selected baseline without doing any analysis.            
                                                                                          
output options:                                                                           
  -s, --short           Shorten the output. Do not print the request parameters, do not   
                        print the response details, do not print headers' descriptions,   
                        do not print references.                                          
  --no-explanation-colors                                                                 
                        Suppress colors in explanations, except in reference links.       
  -w MAX_WIDTH, --max-width MAX_WIDTH                                                     
                        The maximum width of the output. Defaults to the screen width     
                        (90 columns).                                                     
                                                                                          
If you want to write a new baseline.json, consider using baseline_schema.json             
(/home/aja/.local/lib/python3.8/site-packages/headerexposer/baseline_schema.json) as docum
entation.                                                                                 
                                                                                          
Authors:                                                                                  
  * Frédéric Proux, senior pentester at Beijaflore                                        
  * Alexandre Janvrin, pentester at Beijaflore                                            
    (https://www.beijaflore.com/en/)                                                      
                                                                                          
License: AGPLv3+                                                                          
                                                                                          
This software is provided "as is", without any warranty of any kind, express or implied.  
For more information, please consult https://github.com/LivinParadoX/headerexposer.
```
analyse usage:
```
usage: headerexposer analyse [-h] [-b BASELINE_PATH]                                      
                             [-m {GET,OPTIONS,HEAD,POST,PUT,PATCH,DELETE}]                
                             [--params PARAMS] [-d DATA | -f FILE] [-H HEADERS]           
                             [-C COOKIES] [-U USERNAME] [-P PASSWORD] [-t TIMEOUT] [-r]   
                             [-p PROXY] [-k] [-c CERT] [-a USER_AGENT] [-s]               
                             [--no-explanation-colors] [-w MAX_WIDTH]                     
                             url                                                          
                                                                                          
positional arguments:                                                                     
  url                   The url to test.                                                  
                                                                                          
optional arguments:                                                                       
  -h, --help            show this help message and exit                                   
  -b BASELINE_PATH, --baseline-path BASELINE_PATH                                         
                        Path to the baseline.json file for the header analysis (default:  
                        /home/aja/.local/lib/python3.8/site-                              
                        packages/headerexposer/baseline.json).                            
                                                                                          
request options:                                                                          
  -m {GET,OPTIONS,HEAD,POST,PUT,PATCH,DELETE}, --method {GET,OPTIONS,HEAD,POST,PUT,PATCH,D
ELETE}                                                                                    
                        HTTP method to use for the request. Default: "GET".               
  --params PARAMS       Add multiple, ampersand-separated parameters to the request.      
  -d DATA, --data DATA  Data to append to the request. Mutually exclusive with --file.    
  -f FILE, --file FILE  Path to a file to append to the request. Mutually exclusive with  
                        --data.                                                           
  -H HEADERS, --headers HEADERS                                                           
                        Add multiple, newline-separated HTTP headers to the request.      
  -C COOKIES, --cookies COOKIES                                                           
                        Add multiple, semicolon-separated cookies to the request.         
  -U USERNAME, --username USERNAME                                                        
                        username to use in Basic/Digest/Custom HTTP Authentication.       
  -P PASSWORD, --password PASSWORD                                                        
                        password to use in Basic/Digest/Custom HTTP Authentication.       
  -t TIMEOUT, --timeout TIMEOUT                                                           
                        How many seconds to wait for the server to send data before       
                        giving up, as float.                                              
  -r, --disallow-redirects                                                                
                        Disable GET/OPTIONS/POST/PUT/PATCH/DELETE/HEAD redirection.       
                        Defaults to enabled redirection.                                  
  -p PROXY, --proxy PROXY                                                                 
                        Proxy to use for the request.                                     
  -k, --verify          Verify SSL certificates. Defaults to an insecure behavior.        
  -c CERT, --cert CERT  Optional path to the SSL client .pem certificate for client       
                        authentication.                                                   
  -a USER_AGENT, --user-agent USER_AGENT                                                  
                        User Agent to use. Defaults to a recent Google Chrome user        
                        agent.                                                            
                                                                                          
output options:                                                                           
  -s, --short           Shorten the output. Do not print the request parameters, do not   
                        print the response details, do not print headers' descriptions,   
                        do not print references.                                          
  --no-explanation-colors                                                                 
                        Suppress colors in explanations, except in reference links.       
  -w MAX_WIDTH, --max-width MAX_WIDTH                                                     
                        The maximum width of the output. Defaults to the screen width     
                        (90 columns).                                                     
```
demo usage:
```
usage: headerexposer demo [-h] [-b BASELINE_PATH] [-s] [--no-explanation-colors]        
                          [-w MAX_WIDTH]                                                
                                                                                        
optional arguments:                                                                     
  -h, --help            show this help message and exit                                 
  -b BASELINE_PATH, --baseline-path BASELINE_PATH                                       
                        Path to the baseline.json file for the header analysis (default:
                        /home/aja/.local/lib/python3.8/site-                            
                        packages/headerexposer/baseline.json).                          
                                                                                        
output options:                                                                         
  -s, --short           Shorten the output. Do not print the request parameters, do not 
                        print the response details, do not print headers' descriptions, 
                        do not print references.                                        
  --no-explanation-colors                                                               
                        Suppress colors in explanations, except in reference links.     
  -w MAX_WIDTH, --max-width MAX_WIDTH                                                   
                        The maximum width of the output. Defaults to the screen width   
                        (90 columns).                                                   
```
show usage:
```
usage: headerexposer show [-h] [-b BASELINE_PATH] [-s] [--no-explanation-colors]        
                          [-w MAX_WIDTH]                                                
                                                                                        
optional arguments:                                                                     
  -h, --help            show this help message and exit                                 
  -b BASELINE_PATH, --baseline-path BASELINE_PATH                                       
                        Path to the baseline.json file for the header analysis (default:
                        /home/aja/.local/lib/python3.8/site-                            
                        packages/headerexposer/baseline.json).                          
                                                                                        
output options:                                                                         
  -s, --short           Shorten the output. Do not print the request parameters, do not 
                        print the response details, do not print headers' descriptions, 
                        do not print references.                                        
  --no-explanation-colors                                                               
                        Suppress colors in explanations, except in reference links.     
  -w MAX_WIDTH, --max-width MAX_WIDTH                                                   
                        The maximum width of the output. Defaults to the screen width   
                        (90 columns).                                                   
```

# Basic module usage

```
>>> import headerexposer as he
>>> import requests

>>> baseline = he.load_baseline("baseline.json")

>>> resp = requests.get("https://google.com")

>>> findings = he.analyse_headers(resp.headers, baseline, short=True)

>>> print(he.tabulate_findings(findings))
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

* Frédéric Proux, senior penetration tester at Beijaflore. I created the original headerexposer which helped Beijaflore's auditors to test the security of our customers' websites' headers for many years!
* Alexandre Janvrin, penetration tester at Beijaflore. I improved upon Fred's design by adding the current pattern-matching system, many header explanations, the ability to send custom headers, cookies, parameters, etc. in the initial request, and nice cross-platform colored table outputs!  
https://www.beijaflore.com/en/

# License

AGPLv3+, see LICENSE for more details.

# URLs

* https://pypi.org/project/headerexposer/
* https://github.com/LivinParadoX/headerexposer/
