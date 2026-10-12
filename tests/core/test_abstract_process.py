# -*- coding: utf-8 -*-

"""
``AbstractProcess`` is public: a subclass written against its earlier
contract -- one that implements the listing and search methods itself, not
the private hooks the built-in backends use -- must keep instantiating and
keep its own implementations.
"""

import os

import pytest

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
    # Built on the methods above only: no _require_open needed.
    assert list(process.scan_pointer_paths(0x1000)) == []
    with pytest.raises(ValueError, match="ptr_size"):
        process.scan_pointer_paths(0x1000, ptr_size=3)


def test_scan_pointer_paths_runs_an_earlier_contract_subclass_own_scanning_check():
    """A 3.3-contract subclass that adds its own _require_scanning (but no
    _require_open) still has it run by scan_pointer_paths."""

    class _ChecksScanning(_ContractV3Process):
        def _require_scanning(self):
            raise PermissionError("no read access")

    with pytest.raises(PermissionError, match="read access"):
        _ChecksScanning().scan_pointer_paths(0x1000)


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


class _OtherMethods:
    """Mixin: AbstractProcess's other abstract methods, implemented trivially."""

    def __init__(self):
        super().__init__(pid=os.getpid())

    def _detect_is_64bit(self):
        return True

    def close(self):
        return True

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


def test_a_subclass_with_neither_the_method_nor_its_hook_fails_when_defined():
    import pytest

    with pytest.raises(TypeError, match="_scan_values .or search_by_value"):
        type("Incomplete", (_OtherMethods, AbstractProcess), {"_require_open": lambda self: None})


def test_a_subclass_using_the_hooks_must_implement_require_open():
    import pytest

    hooks = {
        name: (lambda self, *args, **kwargs: (item for item in ()))
        for name in (
            "_iter_memory_regions", "_iter_threads", "_iter_modules",
            "_scan_addresses", "_scan_values", "_scan_pattern",
        )
    }
    with pytest.raises(TypeError, match="_require_open"):
        type("NoOpenCheck", (_OtherMethods, AbstractProcess), hooks)

    complete = type(
        "Complete", (_OtherMethods, AbstractProcess), dict(hooks, _require_open=lambda self: None)
    )
    assert list(complete().search_by_value(int, value=1)) == []


def test_an_intermediate_abstract_subclass_is_not_checked():
    # Still abstract (close and friends left open), so it is never
    # instantiated; only its concrete subclasses must be complete.
    class Intermediate(AbstractProcess):
        pass

    assert Intermediate.__name__ == "Intermediate"


def test_abstract_methods_are_counted_the_way_abcmeta_counts_them():
    import abc

    import pytest

    # A plain (non-ABC) mixin's @abstractmethod does not make a class
    # abstract for ABCMeta -- it instantiates -- so it must not exempt the
    # class from the check either.
    class PlainMixin:
        @abc.abstractmethod
        def extra(self):
            ...

    with pytest.raises(TypeError, match="must implement"):
        type("Instantiable", (PlainMixin, _OtherMethods, AbstractProcess), {})

    # A class-level descriptor is not evaluated while looking for open
    # abstract methods.
    class Loud:
        def __get__(self, obj, owner):
            raise RuntimeError("evaluated")

    class StillAbstract(AbstractProcess):
        loud = Loud()

    assert StillAbstract.__name__ == "StillAbstract"


def test_the_error_names_each_missing_hook_once():
    import pytest

    with pytest.raises(TypeError) as caught:
        type("Bare", (_OtherMethods, AbstractProcess), {})
    message = str(caught.value)
    assert message.count("_scan_values") == 1
    assert "search_by_value, search_by_value_between" in message
