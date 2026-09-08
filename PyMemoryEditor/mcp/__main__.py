# -*- coding: utf-8 -*-

"""``python -m PyMemoryEditor.mcp`` — the same entry point as the console script.

Useful when the console script is not on PATH, which is the usual situation
when an MCP client launches the server from a virtualenv it did not activate::

    {"command": "/path/to/venv/bin/python",
     "args": ["-m", "PyMemoryEditor.mcp", "--allow-process", "game.exe"]}
"""

import sys

from .server import main

if __name__ == "__main__":
    sys.exit(main())
