# -*- coding: utf-8 -*-

"""
The MCP Registry listing (server.json) and the command it makes clients run.

A registry client starts a PyPI server as ``uvx <runtime args> <identifier>
<package args>``, with the identifier being the PyPI project. So the listing
only works while four things agree: the server name in server.json and the
``mcp-name`` marker in the README that PyPI shows (the registry's ownership
check), the versions in server.json and the package, and the console script
the identifier names, which must start the server when given ``mcp``.
"""

import json
import re
import sys
from pathlib import Path

import pytest

import PyMemoryEditor

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def server():
    return json.loads((ROOT / "server.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def package(server):
    (package,) = server["packages"]
    return package


def test_readme_carries_the_registry_name(server):
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert re.findall(r"mcp-name: (\S+) -->", readme) == [server["name"]]


def test_versions_follow_the_package(server, package):
    version = PyMemoryEditor.__version__

    assert server["version"] == package["version"] == version
    assert {"type": "named", "name": "--from"}.items() <= package["runtimeArguments"][0].items()
    assert package["runtimeArguments"][0]["value"] == "PyMemoryEditor[mcp]==" + version


def test_the_command_a_client_builds_starts_the_server(package):
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    scripts = re.search(r"\[project\.scripts\](.*?)\n\[", pyproject, re.S).group(1)

    # uvx looks the executable up by its exact name, and the console scripts
    # are lowercase: "PyMemoryEditor" would not be found on Linux.
    assert re.search(r'^{} = "PyMemoryEditor\.app\.application:main_cli"$'.format(package["identifier"]), scripts, re.M)
    assert package["runtimeHint"] == "uvx"
    assert package["packageArguments"] == [{"type": "positional", "value": "mcp"}]
    assert package["transport"] == {"type": "stdio"}


def test_description_fits_the_registry_limit(server):
    # The registry rejects a description over 100 characters at publish time.
    assert len(server["description"]) <= 100


def test_mcp_subcommand_runs_the_server_without_qt(monkeypatch):
    from PyMemoryEditor.app import application
    from PyMemoryEditor.mcp import server as mcp_server

    received = []
    monkeypatch.setattr(mcp_server, "main", lambda argv: received.append(list(argv)) or 0)
    monkeypatch.setattr(application, "main", lambda argv: pytest.fail("the Qt app started"))
    monkeypatch.setitem(sys.modules, "PySide6", None)  # any Qt import would raise

    assert application.main_cli(["pymemoryeditor", "mcp", "--read-only", "--allow-process", "game.exe"]) == 0
    assert received == [["--read-only", "--allow-process", "game.exe"]]


def test_other_arguments_still_reach_the_app(monkeypatch):
    from PyMemoryEditor.app import application

    received = []
    monkeypatch.setattr(application, "main", lambda argv: received.append(argv))

    application.main_cli(["pymemoryeditor", "--version"])
    assert received == [["pymemoryeditor", "--version"]]
