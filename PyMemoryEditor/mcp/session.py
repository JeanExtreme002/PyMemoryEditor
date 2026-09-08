# -*- coding: utf-8 -*-

"""
Server-side state: open processes and the scan result sets they produced.

This module exists because of one hard constraint that shapes the whole MCP
server: **a scan result cannot be returned to the model.** A first scan for
``int == 100`` in a real process matches tens of thousands of addresses, and
the classic Cheat Engine loop then refines that set three or four times before
it means anything. Handing those lists back through the protocol would burn the
client's whole context on hex digits the model must not reason about
individually anyway.

So results stay here, keyed by a short id, and tools trade in those ids: a scan
returns ``{"scan_id": "scan-1", "count": 41822, ...}`` plus a handful of
samples, ``refine_scan("scan-1", ...)`` narrows it server-side, and only when
the set is small does the model page through the addresses themselves. The same
handle indirection applies to processes — a ``session_id`` rather than a raw
PID — which also gives the store one place to close every handle at shutdown.

Two caps keep the store bounded without the caller thinking about it: each
session keeps its most recent :data:`MAX_SCANS_PER_SESSION` result sets
(refine loops are strictly forward-looking, so the oldest set is the one nobody
will ask for again), and each result set is capped at scan time.
"""

import sys
import threading
from dataclasses import dataclass, field
from itertools import count
from time import time
from typing import Dict, List, Optional, Sequence, Tuple

from ..process.abstract import AbstractProcess
from ..process.region import MemoryRegion, MemoryRegionSnapshot


#: Result sets retained per session before the oldest is evicted.
MAX_SCANS_PER_SESSION = 20


class SessionError(Exception):
    """An unknown or expired session/scan id.

    Raised (not returned) so the MCP layer reports it as a tool error: the
    model has referred to a handle that does not exist, and every message here
    tells it how to get a valid one instead of leaving it to guess.
    """


@dataclass
class ScanResult:
    """One materialized scan result set.

    :param scan_id: short handle the model passes back in.
    :param session_id: the process this set belongs to. Refines and reads are
        checked against it — an address from one process means nothing in
        another.
    :param value_type: the ``int`` / ``float`` / ``str`` / ``bytes`` / ``bool``
        the addresses were matched as, or ``"pattern"`` for an AOB scan.
        Carried so ``refine_scan`` re-reads each address at the same width the
        original scan used, without the model having to restate it.
    :param bufflength: the width in bytes those values were read at.
    :param addresses: the matching addresses, ascending.
    :param description: human-readable summary of the scan that produced this
        set (``"int == 100"``), used to caption the refine chain.
    :param truncated: the scan hit the result cap and stopped early, so
        ``addresses`` is a *prefix* of the real match set.
    :param timed_out: the scan hit its wall-clock budget and stopped early —
        again a partial set, but partial by region coverage rather than count.
    """

    scan_id: str
    session_id: str
    value_type: str
    bufflength: Optional[int]
    addresses: List[int]
    description: str
    truncated: bool = False
    timed_out: bool = False
    created_at: float = field(default_factory=time)

    @property
    def count(self) -> int:
        return len(self.addresses)

    @property
    def is_partial(self) -> bool:
        """Whether this set is known to be missing real matches.

        The distinction matters more here than anywhere else in the server: a
        refine chain built on a partial set can converge confidently on the
        wrong address, because the right one was never in the set to be kept.
        Every tool that returns a partial set says so, and says what to narrow.
        """
        return self.truncated or self.timed_out


@dataclass
class Session:
    """One open process, plus the state that makes refining it cheap.

    :param regions: the region snapshot taken by this session's most recent
        full scan. Reused by refines and reads to skip re-enumerating the
        address space (the point of
        :meth:`~PyMemoryEditor.AbstractProcess.snapshot_memory_regions`).
    :param lock: serializes operations on the process. MCP tool calls can
        arrive concurrently and the client is free to fire a read while a scan
        is still running; two threads driving ``read_process_memory`` on the
        same handle is a race the library does not promise to survive. Holding
        the lock for the duration of a scan also gives the queued call a
        consistent view rather than a half-refined one.
    """

    session_id: str
    process: AbstractProcess
    pid: int
    name: str
    opened_at: float = field(default_factory=time)
    regions: Optional[MemoryRegionSnapshot] = None
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _scans: "Dict[str, ScanResult]" = field(default_factory=dict, repr=False)
    _scan_order: List[str] = field(default_factory=list, repr=False)

    def snapshot_regions(self, *, refresh: bool = False) -> MemoryRegionSnapshot:
        """Return this session's region snapshot, taking a fresh one if asked.

        A full scan always refreshes (regions are allocated and freed while the
        target runs, and a stale map silently skips wherever the value moved to);
        refines and reads reuse whatever the last scan left behind, since they
        only revisit addresses that map was already built from.
        """
        if refresh or self.regions is None:
            self.regions = self.process.snapshot_memory_regions()
        return self.regions

    def add_scan(self, scan: ScanResult) -> ScanResult:
        """Store a result set, evicting the oldest beyond the per-session cap."""
        self._scans[scan.scan_id] = scan
        self._scan_order.append(scan.scan_id)

        while len(self._scan_order) > MAX_SCANS_PER_SESSION:
            self._scans.pop(self._scan_order.pop(0), None)

        return scan

    def get_scan(self, scan_id: str) -> ScanResult:
        """Look up a result set, or explain why the id is gone."""
        scan = self._scans.get(scan_id)
        if scan is None:
            known = ", ".join(self._scan_order) or "none"
            raise SessionError(
                'Unknown scan id "%s" for session "%s". Live scans: %s. Only the '
                "%d most recent scans per session are kept — run a new scan "
                "rather than refining an expired one."
                % (scan_id, self.session_id, known, MAX_SCANS_PER_SESSION)
            )
        return scan

    @property
    def scan_ids(self) -> Tuple[str, ...]:
        return tuple(self._scan_order)


class SessionStore:
    """The server's process handles and their scan results.

    Handles are short, sequential and human-readable (``proc-1``, ``scan-3``)
    rather than UUIDs. A model has to copy these strings from one tool result
    into the next call by hand, and a 32-character hex id is both a waste of
    context and something it can plausibly get wrong.
    """

    def __init__(self) -> None:
        self._sessions: Dict[str, Session] = {}
        self._session_ids = count(1)
        self._scan_ids = count(1)
        self._lock = threading.Lock()

    def open(self, process: AbstractProcess, pid: int, name: str) -> Session:
        """Register an already-opened process and return its session."""
        with self._lock:
            session_id = "proc-%d" % next(self._session_ids)
            session = Session(
                session_id=session_id, process=process, pid=pid, name=name
            )
            self._sessions[session_id] = session
            return session

    def get(self, session_id: str) -> Session:
        """Look up a session, or explain how to obtain a valid id."""
        known = "none"

        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                # Built under the lock: tool calls run on a thread pool, so a
                # concurrent open/close could otherwise resize the dict
                # mid-iteration and turn a helpful SessionError into a bare
                # "dictionary changed size during iteration". Only on the
                # failure path — `get` runs on every single tool call.
                known = ", ".join(sorted(self._sessions)) or "none"

        if session is None:
            raise SessionError(
                'Unknown session id "%s". Open sessions: %s. Call open_process '
                "to attach to a process and get one." % (session_id, known)
            )
        return session

    def new_scan(
        self,
        session: Session,
        *,
        value_type: str,
        bufflength: Optional[int],
        addresses: List[int],
        description: str,
        truncated: bool = False,
        timed_out: bool = False,
    ) -> ScanResult:
        """Build and store a result set under a freshly minted scan id."""
        with self._lock:
            scan_id = "scan-%d" % next(self._scan_ids)

        return session.add_scan(
            ScanResult(
                scan_id=scan_id,
                session_id=session.session_id,
                value_type=value_type,
                bufflength=bufflength,
                addresses=addresses,
                description=description,
                truncated=truncated,
                timed_out=timed_out,
            )
        )

    def find_scan(self, scan_id: str) -> Tuple[Session, ScanResult]:
        """Resolve a scan id to its owning session without naming the session.

        Scan ids are unique across the store, so the model only has to carry
        the one handle through a refine chain.
        """
        with self._lock:
            sessions = list(self._sessions.values())

        for session in sessions:
            if scan_id in session.scan_ids:
                return session, session.get_scan(scan_id)

        raise SessionError(
            'Unknown scan id "%s". Run a scan (scan_value / scan_pattern) to '
            "get one, or list the live sessions with server_info." % scan_id
        )

    def close(self, session_id: str) -> Session:
        """Close the target handle and forget the session."""
        with self._lock:
            session = self._sessions.pop(session_id, None)

        if session is None:
            raise SessionError('Unknown session id "%s" (already closed?).' % session_id)

        with session.lock:
            try:
                session.process.close()
            except Exception:  # noqa: BLE001 — target may already be gone
                pass

        return session

    def close_all(self) -> int:
        """Close every open handle. Called on server shutdown."""
        with self._lock:
            session_ids = list(self._sessions)

        closed = 0
        for session_id in session_ids:
            try:
                self.close(session_id)
                closed += 1
            except SessionError:
                pass
        return closed

    @property
    def sessions(self) -> Tuple[Session, ...]:
        with self._lock:
            return tuple(self._sessions.values())


def batch_regions(
    regions: Sequence[MemoryRegion],
    batch_bytes: int,
) -> List[List[MemoryRegion]]:
    """Split ``regions`` into groups each covering about ``batch_bytes``.

    A value scan is a generator that yields only on a *hit*, so scanning for a
    rare value produces no yields at all for minutes on end — there is no point
    at which the consumer regains control to check a deadline. Driving the scan
    one batch of regions at a time restores that control: each
    ``search_by_value(memory_regions=batch)`` call is bounded work, and the
    clock is checked between batches.

    A single region larger than ``batch_bytes`` still gets its own batch — it
    can't be split without splitting a value across the seam — so the budget is
    a target, not a guarantee.

    Batches come back as plain lists even when ``regions`` is a
    :class:`MemoryRegionSnapshot`, and re-tagging them would buy nothing. The
    tag has exactly one reader, ``_ensure_sorted_by_address``, reached only from
    ``iter_values_for_addresses`` — the ``search_by_addresses`` path, which
    never receives a batch from here. What batches *are* handed to,
    ``search_by_value`` / ``search_by_value_between`` / ``search_by_pattern``,
    rebuilds the regions through a filtering comprehension and then sorts
    unconditionally, in all three backends. So the sort happens either way and
    the tag is never consulted. (Tried and reverted; the constraint it imposed
    on future edits here was the only thing it added.)
    """
    batches: List[List[MemoryRegion]] = []
    current: List[MemoryRegion] = []
    current_bytes = 0

    for region in regions:
        current.append(region)
        current_bytes += region.size

        if current_bytes >= batch_bytes:
            batches.append(current)
            current = []
            current_bytes = 0

    if current:
        batches.append(current)

    return batches


def region_to_dict(region: MemoryRegion) -> Dict[str, object]:
    """Render a region as JSON for a tool result.

    Addresses go out as ``0x``-prefixed strings, never numbers — see
    ``toolset.format_address`` for why.
    """
    return {
        "address": "0x%X" % region.address,
        "size": region.size,
        "readable": region.is_readable,
        "writable": region.is_writable,
        "executable": region.is_executable,
        "shared": region.is_shared,
        "path": region.path or None,
    }


def host_platform() -> str:
    """The host platform name, as reported through ``server_info``."""
    if sys.platform == "win32":
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "macos"
    return sys.platform


__all__ = (
    "MAX_SCANS_PER_SESSION",
    "ScanResult",
    "Session",
    "SessionError",
    "SessionStore",
    "batch_regions",
    "host_platform",
    "region_to_dict",
)
