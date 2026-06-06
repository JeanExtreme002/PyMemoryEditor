# -*- coding: utf-8 -*-

import sys
from typing import Iterator, List, Optional, Tuple

from .errors import AmbiguousProcessNameError


# Native, dependency-free process enumeration. Each backend exposes:
#   iter_processes() -> Iterator[(pid, name)]   (name = executable name only)
#   backend_process_exists(pid) -> bool
# Windows uses CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS); Linux walks /proc;
# macOS uses libproc's proc_listpids/proc_name. This is the same per-platform
# dispatch PyMemoryEditor already does for OpenProcess.
if sys.platform == "win32":
    from ..win32.functions import GetProcesses as _iter_processes
    from ..win32.functions import ProcessExists as _backend_process_exists

elif sys.platform.startswith("linux"):
    from ..linux.functions import get_processes as _iter_processes
    from ..linux.functions import process_exists as _backend_process_exists

elif sys.platform == "darwin":
    from ..macos.functions import get_processes as _iter_processes
    from ..macos.functions import process_exists as _backend_process_exists

else:  # pragma: no cover - importing the package already raises on these.
    def _iter_processes() -> Iterator[Tuple[int, str]]:
        return iter(())

    def _backend_process_exists(pid: int) -> bool:
        return False


def get_process_ids_by_name(
    name: str,
    *,
    case_sensitive: bool = True,
    exact_match: bool = True,
) -> List[int]:
    """
    Return a list of all process IDs matching the provided name.

    :param name: process name to search.
    :param case_sensitive: when False, comparison ignores case (useful on Windows).
    :param exact_match: when False, returns every process whose name *contains*
        ``name`` as a substring — handy when you don't know the exact
        executable name (``"chrome"`` matches ``"chrome.exe"``, ``"Google Chrome"``,
        ``"Chromium"``, ...). Often combined with ``case_sensitive=False``.
    """
    if not case_sensitive:
        process_name_cmp = name.casefold()
    else:
        process_name_cmp = name

    matches: List[int] = []

    for pid, name in _iter_processes():
        name = name or ""
        name_cmp = name if case_sensitive else name.casefold()

        if exact_match:
            hit = name_cmp == process_name_cmp
        else:
            hit = process_name_cmp in name_cmp

        if hit:
            matches.append(pid)

    return matches


def get_process_id_by_name(
    name: str,
    *,
    case_sensitive: bool = True,
    exact_match: bool = True,
) -> Optional[int]:
    """
    Return the PID of the process matching the provided name.

    Raises AmbiguousProcessNameError when more than one process matches.
    Returns None when no process matches (callers should handle this).
    """
    matches = get_process_ids_by_name(
        name,
        case_sensitive=case_sensitive,
        exact_match=exact_match,
    )

    if len(matches) > 1:
        raise AmbiguousProcessNameError(name, matches)

    return matches[0] if matches else None


def pid_exists(pid: int) -> bool:
    """
    Check if the process ID exists.
    """
    return _backend_process_exists(pid)
