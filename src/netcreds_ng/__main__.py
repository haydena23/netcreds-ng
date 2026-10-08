"""Allow ``python -m netcreds_ng``."""

import sys

from netcreds_ng.cli import main

if __name__ == "__main__":
    sys.exit(main())
