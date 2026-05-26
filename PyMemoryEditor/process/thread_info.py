# -*- coding: utf-8 -*-

"""
Cross-platform thread descriptor returned by ``AbstractProcess.get_threads()``.

Each backend fills in what its OS exposes cheaply; fields left ``None`` mean
"this platform does not surface that attribute via the API we use." Callers
that need a platform-specific extra (e.g. the TEB on Windows, the Mach
thread port on macOS) can pull it through ``raw`` — the backend stores the
original platform handle there for round-tripping.

The meaning of ``tid`` is intentionally not unified across OSes:

- **Linux**:   POSIX TID — same namespace as PID; ``gettid()`` returns this.
- **Windows**: kernel-assigned global thread id (DWORD) from ``THREADENTRY32``.
- **macOS**:   Mach thread port name from ``task_threads``. Not the BSD pthread
              id; obtain that via ``thread_info(THREAD_IDENTIFIER_INFO)`` if needed.

Documented this way because pretending otherwise leads to subtle bugs in code
that mixes pids and tids across platforms.
"""

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class ThreadInfo:
    """A single thread inside a target process.

    :param tid: thread identifier (see module docstring — meaning is platform-dependent).
    :param start_address: entry point of the thread, when the OS exposes it
        cheaply. ``None`` when not available.
    :param state: short human-readable state — e.g. ``"R"`` / ``"S"`` on Linux.
        ``None`` when not available.
    :param priority: scheduling priority value as reported by the OS. The scale
        is platform-specific; ``None`` when not available.
    :param raw: the underlying platform handle/struct used to look up this
        thread (a ``THREADENTRY32`` on Windows, the TID string from
        ``/proc/<pid>/task/`` on Linux, a Mach port int on macOS). Useful for
        advanced callers that need to make follow-up OS-specific calls.
    """

    tid: int
    start_address: Optional[int] = None
    state: Optional[str] = None
    priority: Optional[int] = None
    raw: Any = field(default=None, compare=False, repr=False)


__all__ = ("ThreadInfo",)
