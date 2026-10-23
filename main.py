#!/usr/bin/env python
"""pythondeid entry point.  All logic lives in the deid package (see deid/cli/ for the commands).

    python main.py --help
"""

import sys

from deid.cli import main

if __name__ == "__main__":  # required on Windows: worker processes re-import this module
    sys.exit(main())
