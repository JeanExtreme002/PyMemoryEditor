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


class WindowNotFoundError(PyMemoryEditorError):
    def __init__(self, window_title: str):
        super().__init__('Could not find the window "%s".' % window_title)
        self.window_title = window_title


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
