# -*- coding: utf-8 -*-

from typing import Iterable, List


class PyMemoryEditorError(Exception):
    """Base class for all PyMemoryEditor exceptions."""


class ClosedProcess(PyMemoryEditorError):
    def __init__(self) -> None:
        super().__init__("Operation not allowed on a closed process.")


class ProcessIDNotExistsError(PyMemoryEditorError):
    def __init__(self, pid: int):
        super().__init__('The process ID "%i" does not exist.' % pid)
        self.pid = pid


class ProcessNotFoundError(PyMemoryEditorError):
    def __init__(self, process_name: str):
        super().__init__('Could not find the process "%s".' % process_name)
        self.process_name = process_name


class AmbiguousProcessNameError(PyMemoryEditorError):
    """Raised when more than one process matches the provided name."""

    def __init__(self, process_name: str, pids: Iterable[int]):
        pid_list: List[int] = list(pids)
        super().__init__(
            'More than one process matches the name "%s": %s.'
            % (process_name, pid_list)
        )
        self.process_name = process_name
        self.pids = pid_list


class BitnessDetectionError(PyMemoryEditorError):
    """
    Raised when ``strict_bitness=True`` and the target's 32-/64-bit width could
    not be read from its own headers (the ELF class on Linux, the Mach-O magic
    on macOS, ``IsWow64Process`` on Windows).

    Without strict mode the library would instead fall back to the host word
    size — a guess that silently poisons the pointer-width default used by
    ``resolve_pointer_chain`` / ``RemotePointer`` / ``scan_pointer_paths`` on a
    cross-bitness target. Catch this to pass ``ptr_size`` explicitly instead.
    """

    def __init__(self, pid: int):
        super().__init__(
            "Could not determine the bitness of process %d from its headers. "
            "Pass ptr_size explicitly to the pointer APIs, or open the process "
            "without strict_bitness to fall back to the host word size." % pid
        )
        self.pid = pid
