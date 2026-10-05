"""Allow ``python -m secscope``."""

import sys

from secscope.cli import main

sys.exit(main())
