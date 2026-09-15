"""Allow running jsxray directly with `python -m jsxray`."""

import sys
from jsxray.cli import main

if __name__ == "__main__":
    sys.exit(main())
