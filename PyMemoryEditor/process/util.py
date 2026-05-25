# -*- coding: utf-8 -*-

from typing import List, Optional

import psutil

from .errors import AmbiguousProcessNameError


def get_process_ids_by_process_name(
    process_name: str, *, case_sensitive: bool = True
) -> List[int]:
    """
    Return a list of all process IDs matching the provided name.

    :param process_name: process name to search.
    :param case_sensitive: when False, comparison ignores case (useful on Windows).
    """
    if not case_sensitive:
        process_name_cmp = process_name.casefold()
    else:
        process_name_cmp = process_name

    matches: List[int] = []

    for process in psutil.process_iter(["name", "pid"]):
        try:
            name = process.info["name"] or ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        if (name if case_sensitive else name.casefold()) == process_name_cmp:
            matches.append(process.info["pid"])

    return matches


def get_process_id_by_process_name(
    process_name: str, *, case_sensitive: bool = True
) -> Optional[int]:
    """
    Return the PID of the process matching the provided name.

    Raises AmbiguousProcessNameError when more than one process matches.
    Returns None when no process matches (callers should handle this).
    """
    matches = get_process_ids_by_process_name(
        process_name, case_sensitive=case_sensitive
    )

    if len(matches) > 1:
        raise AmbiguousProcessNameError(process_name, matches)

    return matches[0] if matches else None


def pid_exists(pid: int) -> bool:
    """
    Check if the process ID exists.
    """
    return psutil.pid_exists(pid)
