"""Entry script of the frozen build.

* ``SecScopeApp`` (windowed) without arguments opens the desktop UI.
* ``secscope`` (console) is the CLI; it also serves the internal sub-programs
  (``worker``, ``static-server``, ``run-python-tool``) the UI starts.
"""

import sys
from pathlib import Path

from secscope.cli import main

if __name__ == "__main__":
    if Path(sys.executable).stem.lower() == "secscopeapp" and len(sys.argv) == 1:
        sys.exit(main(["gui"]))
    sys.exit(main())
