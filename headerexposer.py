#!/bin/env python3
# -*- coding: utf-8 -*-
import re
import sys
sys.path.insert(0, "./")
from headerexposer.__main__ import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
