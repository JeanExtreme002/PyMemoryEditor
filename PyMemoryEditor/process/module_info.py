# -*- coding: utf-8 -*-

"""
Cross-platform module descriptor returned by ``AbstractProcess.get_modules()``.

A "module" is a file backing part of the target's address space — the main
executable plus every shared library loaded into it (``.dll`` on Windows,
``.so`` on Linux, ``.dylib`` on macOS). The OS places each module at a base
address that it randomizes per launch (ASLR), but the offsets *inside* a module
stay constant across runs. ``module.base_address + static_offset`` is therefore
the portable way to reach a known location regardless of where the loader put
the module — the natural feed into :meth:`AbstractProcess.resolve_pointer_chain`.

Each backend fills in what its OS exposes cheaply; ``raw`` carries the original
platform handle/key for advanced follow-up calls.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ModuleInfo:
    """A single module (executable or shared library) loaded in a process.

    :param name: file name of the module (e.g. ``"game.exe"``, ``"libc.so.6"``).
    :param path: full path of the backing file on disk when the OS exposes it;
        falls back to ``name`` when only the name is available.
    :param base_address: address where the module is loaded for this run — the
        value to add static offsets to. Defeats ASLR for ``base + offset``
        addressing.
    :param size: size of the module in memory, in bytes; ``0`` when the backend
        cannot determine it. The exact meaning is platform-specific: the full
        module image on Windows (``modBaseSize``) and Linux (mapped span), but
        the ``__TEXT`` (code) segment size on macOS, where a single
        whole-module size is ill-defined for dyld-shared-cache dylibs.
    :param raw: underlying platform handle/key used to look the module up — the
        ``MODULEENTRY32.hModule`` on Windows, the mapped path on Linux, the
        Mach-O load address on macOS. Useful for advanced callers that need to
        make follow-up OS-specific calls.
    """

    name: str
    path: str
    base_address: int
    size: int = 0
    raw: Any = field(default=None, compare=False, repr=False)


__all__ = ("ModuleInfo",)
