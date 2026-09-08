# -*- coding: utf-8 -*-

"""
A Model Context Protocol server for PyMemoryEditor.

Exposes the library's process-memory tools over MCP so an AI assistant can run
the Cheat Engine loop itself — enumerate processes, attach, scan for a value,
narrow the matches as the value changes, then read (and optionally write) the
address it converged on.

Install and run::

    pip install "PyMemoryEditor[mcp]"
    pymemoryeditor-mcp                 # asks before attaching; writes allowed
    pymemoryeditor-mcp --read-only     # never modifies a target

Or register it with a client — Claude Code::

    claude mcp add pymemoryeditor -- pymemoryeditor-mcp

...and any client that reads ``mcpServers`` JSON::

    {
      "mcpServers": {
        "pymemoryeditor": {
          "command": "pymemoryeditor-mcp",
          "args": []
        }
      }
    }

No flags are needed, because consent is asked for where it can actually be
given: attaching to a process the operator did not pre-approve **asks the
user**, and every ``write_value`` call is confirmed by their client.
``--read-only`` drops the write tool entirely, ``--allow-process NAME``
pre-approves a target so it stops prompting, and ``--allow-any-process`` turns
prompting off for scripted runs. Read :doc:`the MCP guide </mcp>` before
pointing it at anything you care about — it runs with your privileges and it is
**not a sandbox**.

Layout: :mod:`~PyMemoryEditor.mcp.toolset` holds the tools (and imports no MCP
SDK, so it is testable on its own), :mod:`~PyMemoryEditor.mcp.session` the
process/scan handles, :mod:`~PyMemoryEditor.mcp.policy` the access rules, and
:mod:`~PyMemoryEditor.mcp.server` the protocol wiring.
"""

from .config import ServerConfig, build_parser, parse_args
from .policy import AccessDecision, ProcessPolicy
from .server import INSTRUCTIONS, build_server, main
from .session import ScanResult, Session, SessionError, SessionStore
from .toolset import MemoryToolset, ToolError

__all__ = (
    "INSTRUCTIONS",
    "AccessDecision",
    "MemoryToolset",
    "ProcessPolicy",
    "ScanResult",
    "ServerConfig",
    "Session",
    "SessionError",
    "SessionStore",
    "ToolError",
    "build_parser",
    "build_server",
    "main",
    "parse_args",
)
