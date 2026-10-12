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

import dataclasses
import logging
import sys
import threading
from dataclasses import dataclass, field
from itertools import count
from typing import Dict, List, Optional, Sequence, Tuple

from ..process.abstract import AbstractProcess
from ..process.util import pid_exists
from ..process.region import MemoryRegion, MemoryRegionSnapshot


#: Result sets retained per session before the oldest is evicted.
MAX_SCANS_PER_SESSION = 20

#: How long ``close_process`` waits for a running operation to release the
#: session before it stops waiting. The handle is not closed early: the
#: operation that holds it closes it on its way out (see :class:`SessionLock`),
#: so a slow pointer walk delays the close but cannot hang it.
CLOSE_WAIT_SECONDS = 5.0

_logger = logging.getLogger("PyMemoryEditor")

#: Processes one server keeps open at once. Refuses rather than evicting,
#: unlike the scan cap above: a session owns an OS handle, and closing one out
#: from under the model is not something it can detect. Bounds handle
#: exhaustion, since nothing obliges a model to call ``close_process``.
MAX_OPEN_SESSIONS = 8


#: How long the dead-session reaper waits for a busy session's lock. It runs
#: inside open_process, once per dead session, so it stays well under
#: CLOSE_WAIT_SECONDS.
REAP_WAIT_SECONDS = 0.25


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
    :param steps: the comparisons the description is rendered from — the first
        scan plus the most recent refines. Kept apart from ``description`` so a
        refine can extend the chain without re-parsing the rendered text.
    :param elided_steps: refines dropped from the middle of ``steps`` to keep
        the description bounded.
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
    steps: Tuple[str, ...] = ()
    elided_steps: int = 0

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


class SessionLock:
    """The re-entrant lock serializing a session, aware of the session closing.

    Behaves as a :class:`threading.RLock` (``with``, ``acquire(timeout=...)``,
    ``release``) with two additions, both keyed off :attr:`Session.closing`:

    * the outermost ``with`` on a session that is closing raises
      :class:`SessionError` instead of running the operation, so a call queued
      behind the one that held the lock does not start on a closing handle;
    * the outermost ``release`` on a closing session closes the process handle
      *before* letting go. That is how :meth:`SessionStore.close` avoids both
      blocking forever on a long operation and closing the handle while a
      syscall is still running on it: if it cannot get the lock in
      :data:`CLOSE_WAIT_SECONDS`, it leaves the close to whoever holds it.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Only touched by the thread that holds `_lock`.
        self._depth = 0
        self._session: Optional["Session"] = None

    def bind(self, session: "Session") -> None:
        self._session = session

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        if not self._lock.acquire(blocking, timeout):
            return False
        self._depth += 1
        return True

    def release(self) -> None:
        try:
            if self._depth == 1 and self._session is not None:
                self._session._close_handle_if_closing()
        finally:
            self._depth -= 1
            self._lock.release()

    def __enter__(self) -> "SessionLock":
        self.acquire()
        session = self._session
        if self._depth == 1 and session is not None and session.closing.is_set():
            self.release()
            raise SessionError(
                'Session "%s" was closed. Call open_process to attach again.'
                % session.session_id
            )
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()


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
    :param closing: set once :meth:`SessionStore.close` has dropped the
        session. Long operations poll it to stop early, and the lock uses it to
        refuse new work and to close the handle when the last holder leaves.
    """

    session_id: str
    process: AbstractProcess
    pid: int
    name: str
    regions: Optional[MemoryRegionSnapshot] = None
    lock: SessionLock = field(default_factory=SessionLock, repr=False)
    closing: threading.Event = field(default_factory=threading.Event, repr=False)
    _scans: "Dict[str, ScanResult]" = field(default_factory=dict, repr=False)
    _scan_order: List[str] = field(default_factory=list, repr=False)
    _handle_closed: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        self.lock.bind(self)

    @property
    def handle_closed(self) -> bool:
        """Whether the process handle has actually been released."""
        return self._handle_closed

    def _close_handle_if_closing(self) -> None:
        """Close the handle once the session is closing. **Caller holds**
        :attr:`lock`, so no operation can be running on the handle; that is
        also what makes the check-and-set of ``_handle_closed`` safe."""
        if not self.closing.is_set() or self._handle_closed:
            return
        self._handle_closed = True
        try:
            self.process.close()
        except Exception:  # noqa: BLE001 — target may already be gone
            pass

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


def looks_alive(pid: int) -> bool:
    """``pid_exists``, but a pid the OS will not even accept reads as dead.

    The reaper runs inside ``open``, so anything raised here escapes as
    something other than a ``SessionError`` and the model is told only
    "Error executing tool". ``pid_exists(2**31)`` raises ``OverflowError``
    (the value does not fit the platform's pid type). A number the OS
    refuses cannot name a running process, so treating it as dead is both
    safe and correct.
    """
    try:
        return pid_exists(pid)
    except (OverflowError, ValueError, OSError):
        return False


class SessionStore:
    """The server's process handles and their scan results.

    Handles are short, sequential and human-readable (``proc-1``, ``scan-3``)
    rather than UUIDs. A model has to copy these strings from one tool result
    into the next call by hand, and a 32-character hex id is both a waste of
    context and something it can plausibly get wrong.
    """

    def __init__(self) -> None:
        self._sessions: Dict[str, Session] = {}
        # Sessions already closed whose handle a still-running operation will
        # release when it finishes (see :meth:`close`). They no longer have an
        # id, but they still hold an OS handle, so they count against the cap.
        self._draining: List[Session] = []
        self._session_ids = count(1)
        self._scan_ids = count(1)
        self._lock = threading.Lock()

    def open(self, process: AbstractProcess, pid: int, name: str) -> Session:
        """Register an already-opened process and return its session.

        :raises SessionError: if :data:`MAX_OPEN_SESSIONS` are already open.
            The caller owns the handle it passed in and must close it.
        """
        # Loop, rather than deciding to reap from a check taken earlier under
        # a different acquisition: the store can fill between the two, and then
        # a slot held by an exited process would be refused without anyone
        # having looked. At most one reap — a second pass finds nothing new,
        # and refusing has to terminate.
        reaped = False

        while True:
            with self._lock:
                refusal = self._refusal_locked(pid)

                if refusal is None:
                    session_id = "proc-%d" % next(self._session_ids)
                    session = Session(
                        session_id=session_id, process=process,
                        pid=pid, name=name,
                    )
                    self._sessions[session_id] = session
                    return session

                if reaped:
                    # Raised here, not after the block: computing the refusal
                    # under the lock and raising it outside leaves a window
                    # where another thread closes a session, and this caller
                    # is turned away with a message that is already false.
                    raise SessionError(refusal)

            # Outside the lock: reaping closes handles, which takes it again.
            self._reap_dead()
            reaped = True

    def _reap_dead(self) -> List[str]:
        """Drop sessions whose target no longer exists. Caller holds no lock.

        The cap refuses rather than evicting, because closing a live handle
        out from under the model is something it cannot detect. A *dead*
        target is the exception that proves the rule: the handle is already
        useless, so dropping it takes nothing away — and without this, eight
        exited processes hold every slot forever and `open_process` is refused
        for the rest of the server's life, with no way for the model to find
        out which sessions are the dead ones (`process_info` answers happily
        from cached state).

        A recycled pid reads as alive, which is inherent to asking the OS by
        number.
        """
        with self._lock:
            dead = [
                session_id
                for session_id, session in self._sessions.items()
                if not looks_alive(session.pid)
            ]

        for session_id in dead:
            try:
                # A short wait: this runs inside open_process, so it must not
                # sit out CLOSE_WAIT_SECONDS per session, but a quick call that
                # holds the lock for a moment should still free its slot now.
                # A longer operation releases the handle by itself when done.
                self.close(session_id, wait=REAP_WAIT_SECONDS)
            except SessionError:  # closed concurrently
                pass
        return dead

    def capacity_refusal(self, pid: int = 0) -> Optional[str]:
        """The reason :meth:`open` would refuse right now, or ``None``.

        One message, rendered once. The protocol layer asks this *before*
        prompting the user — spending an approval on an attach that cannot
        happen is worse than refusing outright — and :meth:`open` raises it as
        the authoritative guard. Rendering it in one place keeps the early
        path, which is the one a model actually hits, as informative as the
        late one.

        Reaps first, or a server full of exited processes reports as full when
        :meth:`open` would have made room.
        """
        with self._lock:
            if self._handles_held_locked() < MAX_OPEN_SESSIONS:
                return None

        self._reap_dead()

        with self._lock:
            return self._refusal_locked(pid)

    def _refusal_locked(self, pid: int) -> Optional[str]:
        """Render the refusal, or ``None``. **Caller holds** ``self._lock``.

        Separate from :meth:`capacity_refusal` so :meth:`open` can check and
        insert under one acquisition. If the check released the lock and the
        insert took it again, the cap could be exceeded: every racing thread
        would see room, then every one would insert.
        """
        # Deterministic, so a refactor that checks capacity outside the lock
        # fails here instead of in a timing test.
        assert self._lock.locked(), "capacity must be judged under the lock"

        if self._handles_held_locked() < MAX_OPEN_SESSIONS:
            return None

        # No "close the oldest": the oldest is usually the target the whole
        # session has been refining, and close_process discards its scan
        # results too. The list is given instead, so the choice is made on
        # what each session holds.
        existing = [
            sid for sid, session in self._sessions.items()
            if session.pid == pid
        ]
        already = (
            " Note that pid %d is already open as %s — reuse that id "
            "rather than attaching again." % (pid, existing[0])
            if existing
            else ""
        )
        listing = ", ".join(
            "%s (%s, pid %d, %d scan%s)"
            % (sid, session.name or "?", session.pid,
               len(session.scan_ids),
               "" if len(session.scan_ids) == 1 else "s")
            for sid, session in self._sessions.items()
        )

        draining = len(self._draining)
        if not draining:
            return (
                "This server already has %d processes open, which is the "
                "limit, and all of them are live. Close whichever you are "
                "done with (close_process also discards that session's scan "
                "results) and attach again. Open: %s.%s"
                % (MAX_OPEN_SESSIONS, listing, already)
            )

        # Closed sessions whose handle a running operation still holds: they
        # have no id to close, so the only remedy for them is to wait.
        waiting = (
            "%d closed session%s still finishing an operation; %s handle is "
            "released as soon as that operation stops, so retry shortly"
            % (draining, "" if draining == 1 else "s",
               "its" if draining == 1 else "each")
        )
        if not self._sessions:
            return (
                "This server is at its limit of %d process handles: %s."
                % (MAX_OPEN_SESSIONS, waiting)
            )
        return (
            "This server is at its limit of %d process handles: %d open "
            "session%s and %s. Or close whichever open session you are done "
            "with (close_process also discards its scan results) and attach "
            "again. Open: %s.%s"
            % (MAX_OPEN_SESSIONS, len(self._sessions),
               "" if len(self._sessions) == 1 else "s",
               waiting, listing, already)
        )

    def _handles_held_locked(self) -> int:
        """OS handles this store still holds: open sessions plus closed ones
        whose handle is waiting on a running operation. **Caller holds**
        ``self._lock``."""
        self._draining = [s for s in self._draining if not s.handle_closed]
        return len(self._sessions) + len(self._draining)

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
        steps: Sequence[str] = (),
        elided_steps: int = 0,
    ) -> ScanResult:
        """Build and store a result set under a freshly minted scan id.

        :raises SessionError: if the session was closed while the scan ran —
            its id would point at a session the model can no longer reach.
        """
        with self._lock:
            # Checked and stored under the lock `close` sets `closing` under,
            # so a close cannot land between the check and the store.
            if session.closing.is_set():
                raise SessionError(
                    'Session "%s" was closed while the scan was running, so '
                    "its results were discarded. Call open_process to attach "
                    "again." % session.session_id
                )
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
                    steps=tuple(steps) or (description,),
                    elided_steps=elided_steps,
                )
            )

    def find_scan(self, scan_id: str) -> Tuple[Session, ScanResult]:
        """Resolve a scan id to its owning session without naming the session.

        Scan ids are unique across the store, so the model only has to carry
        the one handle through a refine chain.
        """
        # Under the store lock, which `new_scan` adds (and evicts) under, so
        # an eviction cannot land between the membership test and the lookup
        # and turn a found id into "Unknown scan id".
        with self._lock:
            for session in self._sessions.values():
                if scan_id in session.scan_ids:
                    return session, session.get_scan(scan_id)

        raise SessionError(
            'Unknown scan id "%s". Run a scan (scan_value / scan_pattern) to '
            "get one, or list the live sessions with server_info." % scan_id
        )

    def close(self, session_id: str, *, wait: float = CLOSE_WAIT_SECONDS) -> Session:
        """Forget the session and close its target handle.

        The handle is closed under the session lock, so never while another
        thread is mid-syscall on it. If an operation still holds the lock after
        ``wait`` seconds, this returns without waiting further: the session is
        already marked closing, the operation stops at its next check, and its
        final release closes the handle (:class:`SessionLock`). Check
        :attr:`Session.handle_closed` to tell the two outcomes apart.
        """
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is not None:
                # Set before trying the session lock, so a holder that
                # releases at any point from here on closes the handle itself;
                # there is no window where both sides assume the other will do
                # it. Under the store lock, so `new_scan` cannot slip a result
                # in after this point.
                session.closing.set()
                # Counted against the cap until the handle is really released
                # (`_handles_held_locked` drops it then) — including while we
                # wait for the lock below.
                self._draining.append(session)

        if session is None:
            raise SessionError('Unknown session id "%s" (already closed?).' % session_id)

        if session.lock.acquire(timeout=max(wait, 0.0)):
            # Released through SessionLock.release, which closes the handle.
            session.lock.release()
        else:
            _logger.warning(
                "Session %s is busy; its handle will close when the running "
                "operation finishes.", session_id,
            )

        return session

    def close_all(self, *, wait: float = CLOSE_WAIT_SECONDS) -> int:
        """Close every open handle. Called on server shutdown.

        Never blocks on a busy session for longer than ``wait`` seconds each;
        see :meth:`close`.
        """
        with self._lock:
            session_ids = list(self._sessions)

        closed = 0
        for session_id in session_ids:
            try:
                self.close(session_id, wait=wait)
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

    A region larger than ``batch_bytes`` gets a batch to itself: it can't be
    split without splitting a value across the seam, so the budget is a target
    rather than a guarantee, and the batch that exceeds it should at least not
    be carrying anything else. Without the flush, a run of small regions
    followed by a large one would become a *single* batch — ``[10, 10, 10,
    5000]`` against a 100-byte budget would be one batch of four — so the
    deadline would be checked once for the whole thing, defeating the one job
    this function has.

    Batches are plain lists even when ``regions`` is a
    :class:`MemoryRegionSnapshot`: the snapshot tag is only consulted by
    ``search_by_addresses``, which never receives a batch from here, and the
    scan entry points re-filter and re-sort whatever they are given anyway.
    """
    batches: List[List[MemoryRegion]] = []
    current: List[MemoryRegion] = []
    current_bytes = 0

    for region in regions:
        # Flush first, so an oversized region does not drag the batch it
        # happened to land in along with it.
        if current and region.size >= batch_bytes:
            batches.append(current)
            current = []
            current_bytes = 0

        current.append(region)
        current_bytes += region.size

        if current_bytes >= batch_bytes:
            batches.append(current)
            current = []
            current_bytes = 0

    if current:
        batches.append(current)

    return batches


#: Pieces :func:`split_regions` cuts are a multiple of this, so a value at its
#: natural alignment (and a pointer-sized slot) never straddles a seam.
SPLIT_ALIGNMENT = 4096

#: Smallest piece :func:`split_regions` cuts, whatever the batch size. Splitting
#: exists to bound one *huge* region; with a tiny ``--scan-batch-bytes`` it
#: would otherwise turn a desktop target into millions of 4 KiB scans.
MIN_SPLIT_BYTES = 1024 * 1024


def split_regions(
    regions: Sequence[MemoryRegion],
    piece_bytes: int,
    *,
    overlap: int = 0,
) -> List[MemoryRegion]:
    """Cut every region larger than one piece into consecutive pieces.

    :func:`batch_regions` cannot split a region, so without this a single
    multi-gigabyte heap is one batch: the scan deadline is not checked until
    it has been read end to end, and a pointer map is built over all of it in
    one go. Pieces restore the bound.

    :param piece_bytes: target piece size; rounded down to
        :data:`SPLIT_ALIGNMENT` and floored at :data:`MIN_SPLIT_BYTES`.
    :param overlap: bytes each piece (but the last of a region) extends past
        its seam. A scan that can match at any byte offset needs
        ``width - 1``: a match straddling the seam then lies wholly inside the
        piece before it, while a match *starting* in the overlap cannot fit in
        it, so nothing is found twice. ``0`` for scans stepped at a natural
        alignment, which the aligned seams never cut.

    Pieces keep every attribute of their region but the address and size.
    """
    piece = max(MIN_SPLIT_BYTES, piece_bytes - piece_bytes % SPLIT_ALIGNMENT)
    pieces: List[MemoryRegion] = []

    for region in regions:
        if region.size <= piece:
            pieces.append(region)
            continue
        end = region.address + region.size
        start = region.address
        while start < end:
            stop = min(start + piece + overlap, end)
            pieces.append(dataclasses.replace(region, address=start, size=stop - start))
            start += piece

    return pieces


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
    "CLOSE_WAIT_SECONDS",
    "MAX_OPEN_SESSIONS",
    "SessionLock",
    "looks_alive",
    "MAX_SCANS_PER_SESSION",
    "ScanResult",
    "Session",
    "SessionError",
    "SessionStore",
    "batch_regions",
    "host_platform",
    "region_to_dict",
    "split_regions",
)
