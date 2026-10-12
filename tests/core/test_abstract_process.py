# -*- coding: utf-8 -*-

"""
``AbstractProcess`` is public: a subclass written against its earlier
contract -- one that implements the listing and search methods itself, not
the private hooks the built-in backends use -- must keep instantiating and
keep its own implementations.
"""

import os

from PyMemoryEditor import AbstractProcess


class _ContractV3Process(AbstractProcess):
    """Implements exactly what ``AbstractProcess`` required up to 3.3."""

    def __init__(self):
        super().__init__(pid=os.getpid())

    def _detect_is_64bit(self):
        return True

    def close(self):
        return True

    def get_memory_regions(self):
        yield from ()

    def get_threads(self):
        yield from ()

    def get_modules(self):
        yield from ()

    def search_by_addresses(self, pytype, bufflength=None, addresses=(), **kwargs):
        yield from ((address, "own") for address in addresses)

    def search_by_value(self, pytype, bufflength=None, value=None, *args, **kwargs):
        yield 0x1000

    def search_by_pattern(self, pattern, **kwargs):
        yield 0x2000

    def search_by_value_between(self, pytype, bufflength=None, start=None, end=None, **kwargs):
        yield 0x3000

    def read_process_memory(self, address, pytype, bufflength=None):
        return 0

    def read_process_memory_into(self, address, buffer):
        return 0

    def write_process_memory(self, address, pytype, bufflength=None, value=None):
        return value

    def allocate_memory(self, size, *, permission=None):
        return 0

    def free_memory(self, address, size=0):
        return True


def test_a_subclass_of_the_earlier_contract_still_instantiates_and_runs_its_own_methods():
    process = _ContractV3Process()
    assert list(process.search_by_value(int, value=1)) == [0x1000]
    assert list(process.search_by_pattern("90")) == [0x2000]
    assert list(process.search_by_value_between(int, start=1, end=2)) == [0x3000]
    assert list(process.search_by_addresses(int, addresses=[7])) == [(7, "own")]
    assert list(process.get_memory_regions()) == []
    assert process.main_thread is None


def test_every_backend_implements_every_raw_hook():
    # The hooks are not abstract (see above), so a backend missing one would
    # only fail when that method is called -- possibly only on the CI of its
    # own OS. Read each backend's source instead of importing it, so this
    # runs on every platform.
    import ast
    import pathlib

    import PyMemoryEditor

    hooks = {
        "_require_open",
        "_iter_memory_regions",
        "_iter_threads",
        "_iter_modules",
        "_scan_addresses",
        "_scan_values",
        "_scan_pattern",
    }
    package = pathlib.Path(PyMemoryEditor.__file__).parent
    for backend, class_name in (
        ("linux", "LinuxProcess"),
        ("macos", "MacProcess"),
        ("win32", "WindowsProcess"),
    ):
        tree = ast.parse((package / backend / "process.py").read_text())
        backend_class = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == class_name
        )
        defined = {
            node.name for node in backend_class.body if isinstance(node, ast.FunctionDef)
        }
        assert hooks <= defined, (class_name, sorted(hooks - defined))
