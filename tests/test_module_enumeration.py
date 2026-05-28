# -*- coding: utf-8 -*-

"""
Cross-platform tests for ``AbstractProcess.get_modules`` and the ``ModuleInfo``
descriptor. Everything runs against the test process itself (``os.getpid()``),
which always has at least the interpreter plus its standard libraries loaded,
so the enumeration has something concrete to find on every platform.
"""

import os
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor import ModuleInfo, OpenProcess  # noqa: E402


@pytest.fixture
def modules():
    """Materialize the current process's module list once per test."""
    with OpenProcess(pid=os.getpid()) as process:
        return list(process.get_modules())


def test_get_modules_returns_module_infos(modules):
    """Each yielded item must be a well-formed ``ModuleInfo``."""
    assert modules, "expected at least one loaded module"
    for module in modules:
        assert isinstance(module, ModuleInfo)
        assert isinstance(module.name, str)
        assert isinstance(module.path, str)
        assert isinstance(module.base_address, int)
        assert isinstance(module.size, int)


def test_get_modules_finds_more_than_one(modules):
    """A live Python process loads its executable plus several shared libs."""
    assert len(modules) > 1, "expected the interpreter + its libraries, got %d" % len(
        modules
    )


def test_module_base_addresses_are_positive(modules):
    """The loader never maps a real module at address 0."""
    for module in modules:
        assert module.base_address > 0, "module %r has a zero base address" % (
            module.name,
        )


def test_module_sizes_are_non_negative(modules):
    """``size`` is a byte count — never negative."""
    for module in modules:
        assert module.size >= 0, "module %r has a negative size" % (module.name,)


def test_module_base_addresses_are_unique(modules):
    """Each module occupies its own load address; none should collide."""
    bases = [module.base_address for module in modules]
    assert len(bases) == len(set(bases)), "two modules share a base address"


def test_interpreter_module_is_present(modules):
    """
    Running the suite under CPython, *some* loaded module must reference
    Python — the interpreter binary itself and/or ``libpython`` (the name and
    casing differ per platform, so we match a lowercase substring on both name
    and path).
    """
    haystack = " ".join((m.name + " " + m.path) for m in modules).lower()
    assert "python" in haystack, "no python-related module found in the enumeration"


def test_module_base_matches_a_real_memory_region():
    """
    A module's ``base_address`` is the start of one of the process's memory
    regions — cross-checking the two enumerations guards against a backend
    returning bogus / unaligned bases.
    """
    with OpenProcess(pid=os.getpid()) as process:
        modules = list(process.get_modules())
        region_starts = {region.address for region in process.get_memory_regions()}

    matched = sum(1 for m in modules if m.base_address in region_starts)
    assert matched > 0, (
        "no module base_address lined up with a memory-region start "
        "(checked %d modules against %d regions)"
        % (len(modules), len(region_starts))
    )


def test_module_info_is_hashable_and_comparable():
    """``ModuleInfo`` is a frozen dataclass — usable as dict keys / set members."""
    a = ModuleInfo(name="game.exe", path="/x/game.exe", base_address=0x1000, size=4096)
    b = ModuleInfo(name="game.exe", path="/x/game.exe", base_address=0x1000, size=4096)
    c = ModuleInfo(name="other.so", path="/x/other.so", base_address=0x2000, size=8192)

    assert a == b
    assert a != c

    # ``raw`` is excluded from equality (compare=False), so two entries from
    # different snapshots that otherwise match still compare equal.
    d = ModuleInfo(name="game.exe", path="/x/game.exe", base_address=0x1000, raw="h1")
    e = ModuleInfo(name="game.exe", path="/x/game.exe", base_address=0x1000, raw="h2")
    assert d == e

    # And hashable (frozen=True):
    {a, b, c}


def test_module_info_size_defaults_to_zero():
    """``size`` is optional and defaults to 0 for backends that can't fill it."""
    module = ModuleInfo(name="x", path="/x", base_address=0x10)
    assert module.size == 0


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux-specific: modules are file-backed mappings from /proc/<pid>/maps",
)
def test_linux_modules_are_absolute_paths_with_libc(modules):
    """On Linux every module is a real file (absolute path) and libc is loaded."""
    for module in modules:
        assert module.path.startswith("/"), "module path is not absolute: %r" % (
            module.path,
        )
        assert module.name == os.path.basename(module.path)

    names = " ".join(m.name for m in modules).lower()
    assert "libc" in names, "expected libc to be among the loaded modules"


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows-specific: the main module is an .exe and kernel32 is loaded",
)
def test_windows_modules_include_exe_and_kernel32(modules):
    """On Windows the process executable and kernel32.dll are always present."""
    names = [m.name.lower() for m in modules]
    assert any(n.endswith(".exe") for n in names), "no .exe module found"
    assert any("kernel32" in n for n in names), "kernel32.dll not enumerated"


@pytest.mark.skipif(
    sys.platform != "darwin",
    reason="macOS-specific: dyld images include libsystem; size is the __TEXT span",
)
def test_macos_modules_include_libsystem_with_text_size(modules):
    """On macOS libsystem is loaded and at least one module reports a __TEXT size."""
    names = " ".join(m.name for m in modules).lower()
    assert "libsystem" in names, "expected libSystem among the dyld images"
    assert any(m.size > 0 for m in modules), "no module reported a non-zero __TEXT size"
