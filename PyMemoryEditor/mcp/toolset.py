# -*- coding: utf-8 -*-

"""
The tools themselves — plain Python methods returning JSON-friendly dicts.

Nothing in this module imports the MCP SDK. ``server.py`` is the only place
that knows the protocol exists; it registers these methods and lets the SDK
derive each tool's schema from the signature. Keeping the split means the
interesting half of the server — result-set handles, value parsing, the refine
loop, every safety check — is testable by calling a method, and stays testable
if the SDK renames its decorators again.

Three conventions run through every tool, each earned the hard way:

**Addresses cross the wire as ``0x``-prefixed strings, never numbers.** An
address is an identifier the model copies from one call into the next, and JSON
numbers are IEEE doubles in most clients: a 64-bit address above 2**53 silently
loses its low bits on the way through. A write to a rounded address is exactly
the kind of failure this server must not have. Strings also let the model paste
the hex it already sees in a debugger.

**Result sets never cross the wire.** Scans return a handle and a small sample;
see :mod:`PyMemoryEditor.mcp.session`.

**Scans are bounded twice** — by result count and by wall clock — and a scan
that hit either bound says so in its result. A partial set that a model
mistakes for a complete one is the one bug in this server that produces
confident, wrong answers, so every tool that returns one repeats the warning.
"""

import sys
from contextlib import contextmanager
from time import monotonic
from typing import Any, Callable, Dict, Generator, List, Optional, Sequence, Tuple, Type

from .. import __version__
from ..enums import ScanTypesEnum
from ..process.abstract import AbstractProcess
from ..process.errors import PyMemoryEditorError
from ..process.region import MemoryRegion
from ..process.util import get_process_ids_by_name, iter_processes
from ..util import (
    decode_scan_target,
    resolve_bufflength,
    make_predicate,
    resolve_bufflength_for_value,
    value_to_bytes,
)
from .config import ServerConfig
from .session import (
    MAX_OPEN_SESSIONS,
    MAX_SCANS_PER_SESSION,
    ScanResult,
    Session,
    SessionError,
    SessionStore,
    batch_regions,
    host_platform,
    region_to_dict,
)


#: Addresses included inline in a scan result. Enough for the model to sanity
#: check what it found (are these clustered? does the value look plausible?)
#: without turning a 40 000-hit first scan into 40 000 tokens.
SAMPLE_SIZE = 10

#: Hard cap on a ``str`` / ``bytes`` width. Those two go to
#: ``create_string_buffer(length)``, which allocates exactly what it is asked
#: for — so an unbounded width was not a wrong answer but an OOM kill of the
#: server, taking every open session with it and returning no error at all.
#: 64 KiB is far past any plausible string or byte-array read.
MAX_TEXT_BYTES = 0x10000

#: The numeric widths this server offers a model. Deliberately narrower than
#: what the library now accepts, and the reasons it was *first* written down
#: no longer apply — both were fixed in this same PR, so the justification is
#: recorded honestly rather than left to rot:
#:
#: * ``int`` at 3, 5, 6 or 7 used to come back ``None`` from
#:   ``search_by_addresses`` while ``read_process_memory`` returned a value.
#:   Both paths now agree and sign-extend, so these widths work — measured,
#:   width 3 reads ``1118481``, not ``None``.
#: * ``float`` at anything but 4 or 8 used to decode garbage that read like a
#:   real measurement. ``get_c_type_of`` now refuses those widths outright.
#:
#: What remains is a product decision, not a workaround: a model is told to
#: guess widths, and an unusual one is far more often a guess gone wrong than
#: a genuine 24-bit field. Offering 1, 2, 4 and 8 keeps the guess space the
#: size of the answer space. A caller who really wants a 3-byte field has the
#: library API, which no longer half-supports it.
VALID_NUMERIC_WIDTHS = {int: (1, 2, 4, 8), float: (4, 8), bool: (1,)}

#: Modules listed inline by ``process_info``. A desktop app loads hundreds of
#: shared libraries and the model wants the main image plus a few, not the lot.
MODULE_PREVIEW = 20

#: Ceiling on ``list_scan_results(limit=...)``. Paging exists for the end of a
#: refine chain, where a handful of candidates get inspected one by one; a
#: model asking for thousands of rows has lost the thread and should refine
#: instead.
MAX_PAGE_SIZE = 100

#: One past the widest address any supported target can have. Every address
#: reaching a backend becomes a ``c_void_p``, which truncates to its low 64
#: bits *silently* rather than raising -- so an address above this does not
#: fail, it addresses somewhere else. A model that duplicates or concatenates
#: a hex string it was handed (the kind of slip that produces
#: ``"0x7FFD123456787FFD12345678"``) had that accepted and written to
#: ``0x56787FFD12345678``: not the address it meant, not the prefix it typed,
#: and possibly mapped. This is the module whose docstring says a write to a
#: rounded address is exactly the failure it must not have.
MAX_ADDRESS = (1 << 64) - 1

#: Ceiling on the magnitude of a pointer-chain offset. Offsets are struct
#: displacements: published Cheat Engine recipes use tens or hundreds of bytes,
#: occasionally thousands, and this server's own pointer scanner caps a hop at
#: ``POINTER_SCAN_LIMITS["max_offset"]`` (0x10000) -- so no chain it emits can
#: approach 4 GiB. The module-base-plus-RVA form cannot either: ``SizeOfImage``
#: in a PE header is 32 bits, so an RVA never exceeds this.
#:
#: What it does *not* do is keep the running address inside the space. An
#: earlier version of this comment claimed it kept ``base + sum(offsets)``
#: clear of the truncation boundary, and that arithmetic does not happen:
#: ``resolve_pointer_chain`` dereferences first and adds each offset to a value
#: read out of the target, which is unbounded up to 2**64-1. The address is
#: guarded where it is produced instead -- see the check at the end of
#: ``resolve_pointer_chain``.
#:
#: Negative offsets stay legal: walking backwards through a struct is ordinary
#: (see :func:`parse_offset`).
MAX_OFFSET_MAGNITUDE = 1 << 32

#: Defaults for ``find_pointer_paths``, named because they were previously
#: written twice — once in the signature and once in the clamp — and the two
#: disagreed for ``None``. ``max_offset`` fell to 0, the *narrowest* possible
#: search, while its siblings fell to their documented defaults; a client that
#: renders an unset integer as JSON null therefore got "No static path reached
#: that address" for a target the default call finds.
POINTER_SCAN_DEFAULTS = {"max_depth": 3, "max_offset": 1024, "max_results": 20}

#: Ceilings for the same three. ``max_offset`` may legitimately be 0 (keep only
#: hops pointing exactly at the address); the other two need at least 1.
POINTER_SCAN_LIMITS = {"max_depth": (1, 7), "max_offset": (0, 0x10000),
                       "max_results": (1, MAX_PAGE_SIZE)}

#: The value types a tool argument may name, mapped to the ``pytype`` the
#: library expects.
VALUE_TYPES: Dict[str, Type] = {
    "int": int,
    "float": float,
    "bool": bool,
    "str": str,
    "bytes": bytes,
}

#: Comparison names, mapped onto the library's scan enum. The names are the
#: Cheat Engine vocabulary rather than the enum's, because that is the
#: vocabulary every tutorial an agent has ever read uses.
SCAN_TYPES: Dict[str, ScanTypesEnum] = {
    "exact": ScanTypesEnum.EXACT_VALUE,
    "not_exact": ScanTypesEnum.NOT_EXACT_VALUE,
    "bigger": ScanTypesEnum.BIGGER_THAN,
    "bigger_or_exact": ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE,
    "smaller": ScanTypesEnum.SMALLER_THAN,
    "smaller_or_exact": ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE,
    "between": ScanTypesEnum.VALUE_BETWEEN,
    "not_between": ScanTypesEnum.NOT_VALUE_BETWEEN,
}

#: Comparisons that need both ``value`` and ``end_value``.
_RANGE_SCAN_TYPES = frozenset({"between", "not_between"})

#: Ordered comparisons are defined for numbers. The library does implement an
#: ordered *string* scan, but byte-wise against a fixed width — not the same
#: thing as Python's ``str`` ordering, which is what a refine would apply to
#: re-read values. Rather than quietly give two different answers depending on
#: which path ran, refine restricts text to equality.
_TEXT_SCAN_TYPES = frozenset({"exact", "not_exact"})


class ToolError(Exception):
    """A tool-level failure, phrased for the model that has to recover from it.

    Every message here answers "what do I do now?" — name the flag, the missing
    argument, or the tool to call instead. An agent handed a bare
    ``ValueError: invalid literal for int()`` will retry the same call with the
    same argument; one told "prefix hex with 0x" fixes it on the next turn.
    """


# --------------------------------------------------------------------------- #
# Parsing and formatting
# --------------------------------------------------------------------------- #

def format_address(address: int) -> str:
    """Render an address as the ``0x``-prefixed string every tool returns.

    A negative value is a bug at the call site, not something to render: it
    would come out as ``"0x-8"``, which :func:`parse_address` then rejects, so
    the server would be handing the model a string it refuses to read back
    (see :func:`format_offset`, written for that exact failure on the offset
    side). Better to fail where the wrong number was produced.
    """
    if address < 0:
        raise ValueError(
            "format_address received a negative value (%d). Addresses are "
            "unsigned; use format_offset for a signed displacement." % address
        )
    return "0x%X" % address


def format_offset(offset: int) -> str:
    """Render a pointer-chain offset so it parses back.

    ``"0x%X" % -8`` is ``"0x-8"``, which :func:`parse_offset` rejects — so the
    server was echoing a recipe it could not read back, and a model that fed
    its own output in again got told the offset was malformed.
    """
    return "-0x%X" % -offset if offset < 0 else "0x%X" % offset


def parse_offset(raw: Any, *, field: str = "offset") -> int:
    """Parse a pointer-chain offset, which may be negative.

    Split from :func:`parse_address` because the two have different domains,
    and conflating them cost real capability: an address is never negative, but
    a Cheat Engine recipe walks backwards through a struct all the time
    (``[-0x8]`` to reach a header behind the pointer) and
    ``resolve_pointer_chain`` handles those fine. Rejecting them made a whole
    class of published recipe unusable here — with a message ("must not be
    negative") that reads like a formatting complaint, so a model would "fix"
    it by mangling the offset rather than reporting the limit.

    Bounded in magnitude all the same: an offset is added to an address, and
    an absurd one pushes an intermediate dereference past the truncation
    boundary described on :data:`MAX_ADDRESS`, where the hop silently reads
    from a different place and the whole chain resolves to a plausible lie.
    """
    value = _parse_signed_int(raw, field)

    if abs(value) > MAX_OFFSET_MAGNITUDE:
        raise ToolError(
            "%s %s is too large to be a struct displacement (limit is "
            "±0x%X). An offset this size means the value was read as an "
            "address, or two arguments were swapped."
            % (field, format_offset(value), MAX_OFFSET_MAGNITUDE)
        )

    return value


def parse_address(raw: Any, *, field: str = "address") -> int:
    """Parse an address or offset from a tool argument.

    Accepts ``"0x7FFD1234"``, ``"140737488346164"``, and plain ints (a client
    that types a small number rather than a string). A bare hex string
    *without* the prefix is accepted only when it contains a hex letter, so it
    cannot be read as decimal — ``"DEADBEEF"`` is unambiguous, ``"1000"`` is
    not, and guessing at the latter is how a write lands 3096 bytes from where
    the model meant.
    """
    if isinstance(raw, bool):  # bool is an int subclass; never a valid address
        raise ToolError("%s must be a hex string like '0x1000', not a boolean." % field)

    if isinstance(raw, int):
        value = raw
    else:
        text = str(raw).strip().replace("_", "")
        if not text:
            raise ToolError(
                "%s is required — pass a hex string like '0x7FFD1234' (the form "
                "every tool here returns)." % field
            )
        if text.startswith("-"):
            raise ToolError("%s must not be negative (got %r)." % (field, raw))
        try:
            if text[:2].lower() == "0x":
                value = int(text, 16)
            elif any(char in "abcdefABCDEF" for char in text):
                # Unambiguously not decimal, so read it as the hex it must be.
                value = int(text, 16)
            else:
                value = int(text, 10)
        except ValueError:
            raise ToolError(
                "Could not parse %s from %r. Use a hex string with the 0x prefix "
                "('0x7FFD1234') or a plain decimal integer." % (field, raw)
            ) from None

    if value < 0:
        raise ToolError("%s must not be negative (got %r)." % (field, raw))

    # The floor was checked and the ceiling was not, and only one of the two
    # fails loudly. See MAX_ADDRESS: past it, ctypes truncates instead of
    # raising, so the write lands somewhere else entirely.
    if value > MAX_ADDRESS:
        raise ToolError(
            "%s 0x%X is outside any 64-bit address space (it needs %d bits). "
            "Addresses this large come from a hex string that got duplicated "
            "or concatenated — re-read the address from the tool that gave it "
            "to you rather than reconstructing it."
            % (field, value, value.bit_length())
        )

    return value


def parse_value_type(raw: str) -> Type:
    """Resolve a ``value_type`` argument to a Python type."""
    key = (raw or "").strip().lower()
    pytype = VALUE_TYPES.get(key)
    if pytype is None:
        raise ToolError(
            "Unknown value_type %r. Use one of: %s."
            % (raw, ", ".join(sorted(VALUE_TYPES)))
        )
    return pytype


def parse_scan_type(raw: str) -> Tuple[str, ScanTypesEnum]:
    """Resolve a ``scan_type`` argument to its name and enum member."""
    key = (raw or "").strip().lower()
    scan_type = SCAN_TYPES.get(key)
    if scan_type is None:
        raise ToolError(
            "Unknown scan_type %r. Use one of: %s."
            % (raw, ", ".join(sorted(SCAN_TYPES)))
        )
    return key, scan_type


def parse_value(pytype: Type, raw: Any, *, field: str = "value") -> Any:
    """Parse a scan/write value according to its declared type.

    Values arrive as strings so that one JSON schema covers all five types
    without a union. ``bytes`` is a hex string (``"DE AD BE EF"`` or
    ``"deadbeef"``, spaces and ``0x`` optional) since raw bytes have no JSON
    representation; ``int`` accepts hex too, because the value a model is
    chasing often came out of a debugger that way.
    """
    if raw is None:
        raise ToolError("%s is required for this scan." % field)

    if pytype is bool:
        if isinstance(raw, bool):
            return raw
        text = str(raw).strip().lower()
        if text in ("true", "1", "yes", "on"):
            return True
        if text in ("false", "0", "no", "off"):
            return False
        raise ToolError("Could not parse %s=%r as a bool (use true/false)." % (field, raw))

    if pytype is int:
        return _parse_signed_int(raw, field)

    if pytype is float:
        try:
            return float(str(raw).strip())
        except ValueError:
            raise ToolError("Could not parse %s=%r as a float." % (field, raw)) from None

    if pytype is str:
        text = str(raw)
        if not text:
            # A zero-width target matches at every offset: the scan would come
            # back capped, full of meaningless addresses, and every refine
            # against "" would keep all of them. Rejected for the same reason
            # empty ``bytes`` is.
            raise ToolError(
                "%s cannot be an empty string — a zero-width value matches "
                "every byte in the process. Pass the text you are looking for."
                % field
            )
        return text

    if pytype is bytes:
        text = str(raw).strip().replace(" ", "").replace("_", "")
        if text[:2].lower() == "0x":
            text = text[2:]
        if not text:
            raise ToolError("%s is required — pass hex bytes like 'DEADBEEF'." % field)
        try:
            return bytes.fromhex(text)
        except ValueError:
            raise ToolError(
                "Could not parse %s=%r as hex bytes. Use an even number of hex "
                "digits, e.g. 'DEADBEEF' or 'DE AD BE EF'." % (field, raw)
            ) from None

    raise ToolError("Unsupported value type %r." % pytype)


def _parse_signed_int(raw: Any, field: str) -> int:
    """Parse a possibly-negative integer (scan values, unlike addresses)."""
    if isinstance(raw, bool):
        raise ToolError("%s must be a number, not a boolean." % field)
    if isinstance(raw, int):
        return raw
    text = str(raw).strip().replace("_", "")
    negative = text.startswith("-")
    body = text[1:] if negative else text
    try:
        value = int(body, 16) if body[:2].lower() == "0x" else int(body, 10)
    except (ValueError, IndexError):
        raise ToolError(
            "Could not parse %s=%r as an integer (decimal, or hex with a 0x "
            "prefix)." % (field, raw)
        ) from None
    return -value if negative else value


def format_value(value: Any) -> Any:
    """Render a value read from memory for a JSON result."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex().upper()
    return value


def parse_int_arg(raw: Any, field: str, *, default: Optional[int] = None) -> int:
    """Coerce a numeric tool argument, as a ``ToolError`` rather than a crash.

    A bare ``int(raw)`` on a model-supplied value is a hole in this module's
    error contract: only ``ToolError`` text reaches the model, and everything
    else becomes an ``UnexpectedToolError`` whose message is withheld. So
    ``max_depth="deep"`` or ``limit="dez"`` raised
    ``ValueError: invalid literal for int() with base 10`` and the model was
    told nothing it could act on — for an argument it can fix by itself, which
    is the worst case to be silent about.

    ``bool`` is refused for the same reason :func:`parse_address` refuses it:
    it is an ``int`` subclass, so ``True`` would silently mean 1.
    """
    if raw is None:
        if default is None:
            raise ToolError("%s is required." % field)
        return default

    if isinstance(raw, bool):
        raise ToolError(
            "%s must be a number, not a boolean (got %r)." % (field, raw)
        )

    if isinstance(raw, int):
        return raw

    text = str(raw).strip().replace("_", "")
    try:
        return int(text, 16) if text[:2].lower() == "0x" else int(text, 10)
    except ValueError:
        raise ToolError(
            "%s must be a whole number (got %r)." % (field, raw)
        ) from None


def parse_bufflength(raw: int, pytype: Type, *, required: bool) -> Optional[int]:
    """Turn the ``bufflength=0`` sentinel into the library's ``None``.

    ``0`` rather than ``None`` keeps the JSON schema a plain integer — an
    optional-integer argument is something clients render inconsistently and
    models fill in with the string ``"null"``. Zero is never a legal width, so
    it is free to mean "use the default".
    """
    if isinstance(raw, bool):
        # An int subclass, so `bufflength=true` silently meant a width of 1 --
        # the same trap parse_address and _parse_signed_int already refuse.
        raise ToolError(
            "bufflength must be a number, not a boolean (got %r)." % raw
        )

    if raw and parse_int_arg(raw, "bufflength") < 0:
        raise ToolError("bufflength must be positive (got %r)." % raw)

    if raw:
        width = parse_int_arg(raw, "bufflength")

        # This is the one argument every tool funnels a size through, so it is
        # where both width failures get stopped: a numeric width the read, scan
        # and write paths do not all agree on, and a text width large enough to
        # OOM the server.
        allowed = VALID_NUMERIC_WIDTHS.get(pytype)
        if allowed is not None and width not in allowed:
            raise ToolError(
                "bufflength=%d is not a usable width for value_type=%r. Use "
                "%s. (This server offers only the widths a target actually "
                "stores values in; an unusual width is nearly always a "
                "mis-guess, and guessing at a width is how a write lands on "
                "the wrong bytes.)"
                % (width, pytype.__name__,
                   " or ".join(str(size) for size in allowed))
            )

        if allowed is None and width > MAX_TEXT_BYTES:
            raise ToolError(
                "bufflength=%d is too large: %s reads are capped at %d bytes "
                "(%d KiB). A width larger than that allocates a buffer of that "
                "size in this server and would kill it, losing every open "
                "session. Read the range in pieces if you really need it."
                % (width, pytype.__name__, MAX_TEXT_BYTES, MAX_TEXT_BYTES // 1024)
            )

        return width

    if required and pytype in (str, bytes):
        raise ToolError(
            "bufflength is required when value_type is 'str' or 'bytes' — there "
            "is no value to infer the width from, only an address. Pass the "
            "number of bytes to read."
        )
    return None


# --------------------------------------------------------------------------- #
# The toolset
# --------------------------------------------------------------------------- #

class MemoryToolset:
    """Every MCP tool, as a method.

    :param config: the operator's flags — consulted on every gated operation
        rather than baked into the tool set at construction, so
        :meth:`server_info` can always report the live policy.
    :param store: session/scan state; a fresh one per server by default.
    :param open_process: injection point for the ``OpenProcess`` callable,
        used by the tests to drive the whole toolset against a fake target.
    """

    def __init__(
        self,
        config: ServerConfig,
        store: Optional[SessionStore] = None,
        *,
        open_process: Optional[Callable[..., AbstractProcess]] = None,
    ) -> None:
        self.config = config
        self.store = store if store is not None else SessionStore()
        self.policy = config.policy()

        if open_process is None:
            from .. import OpenProcess

            open_process = OpenProcess

        self._open_process = open_process

    # ---------------------------------------------------------------- #
    # Server and process discovery
    # ---------------------------------------------------------------- #

    def server_info(self) -> Dict[str, Any]:
        """Report the server's capabilities, limits and open sessions.

        Call this first. It answers the questions whose wrong answer wastes the
        most turns: whether writing is enabled at all, which processes are
        reachable, how long a scan may run, and which sessions are already
        open from earlier in the conversation.
        """
        sessions = [
            {
                "session_id": session.session_id,
                "pid": session.pid,
                "name": session.name,
                "scan_ids": list(session.scan_ids),
            }
            for session in self.store.sessions
        ]

        return {
            "library_version": __version__,
            "platform": host_platform(),
            "write_enabled": self.config.allow_write,
            "write_note": (
                "Memory writes are available. Each one is confirmed by the "
                "user's client before it runs, so state plainly what you are "
                "about to change and why — and never write to an address that "
                "did not come out of a scan or a pointer chain."
                if self.config.allow_write
                else "This server was started with --read-only: the "
                "write_value tool is not registered. Tell the user to restart "
                "it without that flag if they want values changed; do not look "
                "for another way in."
            ),
            "process_policy": self.policy.describe(),
            "limits": {
                "max_scan_results": self.config.max_scan_results,
                "max_scan_seconds": self.config.max_scan_seconds,
                "max_page_size": MAX_PAGE_SIZE,
                "scan_batch_bytes": self.config.scan_batch_bytes,
                # Advertised so a width never has to be discovered by tripping
                # the error — this is the argument the hints tell you to guess.
                "max_text_bytes": MAX_TEXT_BYTES,
                "valid_numeric_widths": {
                    pytype.__name__: list(widths)
                    for pytype, widths in VALID_NUMERIC_WIDTHS.items()
                },
                # Same principle applied to the two bounds a pointer recipe
                # runs into. MAX_ADDRESS is a property of the hardware and a
                # model can be expected to know it; the offset ceiling is a
                # number this project picked, so leaving it to be discovered by
                # hitting the error is exactly the case the line above objects
                # to.
                "max_address": format_address(MAX_ADDRESS),
                "max_offset_magnitude": format_address(MAX_OFFSET_MAGNITUDE),
                "max_open_sessions": MAX_OPEN_SESSIONS,
                "max_scans_per_session": MAX_SCANS_PER_SESSION,
            },
            "open_sessions": sessions,
        }

    def list_processes(
        self, name_filter: str = "", limit: int = 50, offset: int = 0
    ) -> Dict[str, Any]:
        """List running processes this server is allowed to open.

        :param name_filter: keep only processes whose name contains this
            substring, case-insensitively. Use it — an unfiltered list on a
            desktop is several hundred entries of pure noise.
        :param limit: maximum entries to return, capped at
            ``server_info().limits.max_page_size``.
        :param offset: entries to skip, for paging. It exists because the cap
            used to be a different number from the one ``server_info``
            advertised, with no way past it — so everything after the first
            page was simply unreachable.

        Processes blocked by the server's policy are omitted, and the result
        says how many were hidden so the absence of an expected target is
        distinguishable from it not running.
        """
        needle = (name_filter or "").strip().casefold()
        limit = max(1, min(parse_int_arg(limit or 50, "limit"), MAX_PAGE_SIZE))
        offset = max(0, parse_int_arg(offset or 0, "offset"))

        # Guarded: iter_processes() is a generator that raises on first
        # iteration when the OS refuses to enumerate (Windows
        # CreateToolhelp32Snapshot returns a transient ERROR_BAD_LENGTH often
        # enough to matter), and an untranslated OSError reaches the model as a
        # bare "Error executing tool list_processes".
        try:
            candidates = [
                (pid, name or "")
                for pid, name in iter_processes()
                if not needle or needle in (name or "").casefold()
            ]
        except OSError as error:
            raise ToolError(
                "Could not enumerate processes: %s. This is usually transient "
                "— try again once before reporting it." % error
            ) from None

        # `filter` keeps everything that is not forbidden outright — including
        # targets that will prompt for approval. Checking `decision.allowed`
        # here instead would hide every process in the default "ask" mode,
        # leaving the model with nothing to name when it asks permission.
        matched = self.policy.filter(candidates)
        hidden = len(candidates) - len(matched)

        matched.sort(key=lambda entry: (entry[1].casefold(), entry[0]))
        total = len(matched)
        page = matched[offset : offset + limit]

        return {
            "processes": [
                {
                    "pid": pid,
                    "name": name,
                    # So the model can warn the user that picking this one will
                    # put a prompt in front of them.
                    "needs_approval": self.policy.check(pid, name).needs_approval,
                }
                for pid, name in page
            ],
            "returned": len(page),
            "total_matching": total,
            "hidden_by_policy": hidden,
            "name_filter": name_filter or None,
            "offset": offset,
            "has_more": offset + len(page) < total,
        }

    def resolve_target(self, pid: int = 0, name: str = "") -> Dict[str, Any]:
        """Turn the ``pid`` / ``name`` arguments into one concrete target.

        Separated from :meth:`attach` because the answer to "may we open this?"
        has three outcomes, and the middle one — *ask the user* — can only be
        acted on by the protocol layer, which has a channel to the human. This
        method resolves the arguments and reports the policy verdict; it opens
        nothing.

        :returns: ``{"status": "ok", "pid": ..., "name": ..., "decision": ...}``,
            or ``{"status": "ambiguous", "candidates": [...]}`` when a name
            matches several processes.
        """
        if pid and name:
            raise ToolError(
                "Pass either pid or name, not both — they can disagree, and a "
                "silently preferred one is how you end up attached to the "
                "wrong process."
            )

        if not pid and not name:
            raise ToolError(
                "Pass pid or name. Use list_processes to find a target first."
            )

        if name:
            try:
                candidates = get_process_ids_by_name(
                    name, case_sensitive=False, exact_match=False
                )
            except OSError as error:
                raise ToolError(
                    "Could not enumerate processes to resolve the name %r: %s. "
                    "This is usually transient — try again once." % (name, error)
                ) from None
            if not candidates:
                raise ToolError(
                    'No running process matches the name "%s". Call '
                    "list_processes to see what is actually running." % name
                )
            if len(candidates) > 1:
                try:
                    names = dict(
                        (found_pid, found_name)
                        for found_pid, found_name in iter_processes()
                        if found_pid in candidates
                    )
                except OSError:
                    # Names are a nicety here; the pids are what the caller
                    # needs to disambiguate with.
                    names = {}
                return {
                    "status": "ambiguous",
                    "candidates": [
                        {"pid": found_pid, "name": names.get(found_pid, "")}
                        for found_pid in sorted(candidates)
                    ],
                }
            pid = candidates[0]

        pid = parse_int_arg(pid, "pid")
        resolved = self._name_for_pid(pid)
        return {
            "status": "ok",
            "pid": pid,
            "name": resolved,
            "decision": self.policy.check(pid, resolved),
        }

    def attach(self, pid: int, name: str) -> Dict[str, Any]:
        """Open ``pid`` and register a session. Assumes access is already settled.

        The policy check lives in :meth:`resolve_target`, so every caller must
        have consulted it first. Keeping the two apart is what lets the
        protocol layer insert a human between the verdict and the handle.
        """
        try:
            process = self._open_process(**self._open_kwargs(pid))
        except PyMemoryEditorError as error:
            raise ToolError("Could not open pid %d: %s" % (pid, error)) from None
        except ValueError as error:
            # The tool schema types `pid` as a plain integer, so nothing stops a
            # model sending 0 or -1; the library rejects it with a clear message
            # that the SDK would otherwise withhold.
            raise ToolError(
                "Cannot open pid %d: %s Use list_processes to get a real pid."
                % (pid, error)
            ) from None
        except PermissionError as error:
            raise ToolError(
                "Permission denied opening pid %d: %s. %s"
                % (pid, error, _permission_hint())
            ) from None
        except OSError as error:
            raise ToolError(
                "Could not open pid %d: %s. %s" % (pid, error, _permission_hint())
            ) from None

        try:
            session = self.store.open(process, pid, name)
        except SessionError:
            # The handle already exists and the store's cap is checked after
            # it does, so refusing without closing leaks the resource the cap
            # protects.
            try:
                process.close()
            except Exception:  # noqa: BLE001 — target may already be gone
                pass
            raise

        result: Dict[str, Any] = {
            "opened": True,
            "session_id": session.session_id,
            "pid": pid,
            "name": name,
            "write_enabled": self.config.allow_write,
        }
        result.update(self._bitness(process))
        return result

    def open_process(self, pid: int = 0, name: str = "") -> Dict[str, Any]:
        """Attach to a process and return a ``session_id`` for the other tools.

        :param pid: the process id to open. Preferred — it is unambiguous.
        :param name: a process name (or fragment) to resolve instead, matched
            case-insensitively as a substring. When several processes match,
            no process is opened and the candidates are returned for you to
            pick a ``pid`` from.

        Pass exactly one of the two. The returned session stays open until
        ``close_process`` or server shutdown; reuse its id rather than
        reopening the same target, since each open costs a handle and resets
        the cached region map.

        At most ``max_open_sessions`` (see ``server_info``) can be open at
        once; reaching it is refused, not rotated, so ``close_process`` a
        target you are done with.

        Attaching to a process the operator has not pre-approved requires the
        **user's** approval, asked for at the moment you call this. Say which
        process you want and why; if the request is refused, report that rather
        than trying a different target.
        """
        target = self.resolve_target(pid=pid, name=name)

        if target["status"] == "ambiguous":
            return {
                "opened": False,
                "reason": "ambiguous_name",
                "message": (
                    '%d processes match "%s". Re-call open_process with one of '
                    "these pids." % (len(target["candidates"]), name)
                ),
                "candidates": target["candidates"],
            }

        decision = target["decision"]
        if not decision.allowed:
            # Includes the needs-approval case: this entry point has no channel
            # to the user, so it fails closed and the message says which flag
            # (or which prompt) unblocks it. The protocol layer overrides this
            # by asking first — see PyMemoryEditor.mcp.server.
            raise ToolError(decision.reason)

        return self.attach(target["pid"], target["name"])

    def close_process(self, session_id: str) -> Dict[str, Any]:
        """Detach from a process and drop its scan result sets."""
        session = self.store.close(session_id)
        return {
            "closed": True,
            "session_id": session.session_id,
            "pid": session.pid,
            "name": session.name,
        }

    def process_info(self, session_id: str) -> Dict[str, Any]:
        """Summarize an open target: bitness, address space, modules, threads.

        The module list is the useful half for reverse engineering: a module's
        ``base_address`` moves every launch (ASLR) but offsets *inside* it do
        not, so ``base + offset`` is how a found address becomes a recipe that
        survives a restart. See ``find_pointer_paths`` for discovering those
        offsets and ``resolve_pointer_chain`` for replaying them.
        """
        session = self.store.get(session_id)

        with session.lock, self._target_errors(session, "process_info"):
            regions = list(session.process.get_memory_regions())
            modules = list(session.process.get_modules())
            threads = list(session.process.get_threads())
            bitness = self._bitness(session.process)

        readable = [region for region in regions if region.is_readable]
        writable = [region for region in regions if region.is_writable]

        return {
            "session_id": session.session_id,
            "pid": session.pid,
            "name": session.name,
            **bitness,
            "address_space": {
                "region_count": len(regions),
                "readable_regions": len(readable),
                "writable_regions": len(writable),
                "readable_bytes": sum(region.size for region in readable),
                "writable_bytes": sum(region.size for region in writable),
            },
            "module_count": len(modules),
            "modules": [
                {
                    "name": module.name,
                    "path": module.path or None,
                    "base_address": format_address(module.base_address),
                    "size": module.size,
                }
                for module in modules[:MODULE_PREVIEW]
            ],
            "modules_truncated": len(modules) > MODULE_PREVIEW,
            "thread_count": len(threads),
            # Named for what it is. The library's `main_thread` convention is
            # "smallest tid", which holds on Linux (POSIX tids are assigned in
            # order) but not on macOS, where tid is a Mach port *name*, nor
            # reliably on Windows. Calling it main_thread_id presented a guess
            # to the model as a fact.
            "lowest_thread_id": (
                min(thread.tid for thread in threads) if threads else None
            ),
            "lowest_thread_id_note": (
                "The convention for 'the main thread' is the smallest thread "
                "id. That is only meaningful on Linux — on macOS a tid is a "
                "Mach port name and on Windows the ordering is not guaranteed."
            ),
        }

    def list_memory_regions(
        self,
        session_id: str,
        writable_only: bool = False,
        executable_only: bool = False,
        path_filter: str = "",
        limit: int = 40,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Page through the target's memory map.

        :param writable_only: keep only writable regions — where a program's
            mutable state (the values worth scanning for) lives.
        :param executable_only: keep only executable regions — code.
        :param path_filter: keep only regions backed by a file whose path
            contains this substring.
        :param limit: rows per page. The server caps it — see
            ``server_info().limits.max_page_size``.
        :param offset: rows to skip, for paging.
        """
        session = self.store.get(session_id)
        limit = max(1, min(parse_int_arg(limit or 40, "limit"), MAX_PAGE_SIZE))
        offset = max(0, parse_int_arg(offset or 0, "offset"))
        needle = (path_filter or "").strip().casefold()

        with session.lock, self._target_errors(session, "list_memory_regions"):
            regions = list(session.process.get_memory_regions())

        selected = [
            region
            for region in regions
            if (region.is_writable or not writable_only)
            and (region.is_executable or not executable_only)
            and (not needle or needle in (region.path or "").casefold())
        ]
        selected.sort(key=lambda region: region.address)
        page = selected[offset : offset + limit]

        return {
            "session_id": session.session_id,
            "regions": [region_to_dict(region) for region in page],
            "returned": len(page),
            "total_matching": len(selected),
            "total_bytes": sum(region.size for region in selected),
            "offset": offset,
            "has_more": offset + len(page) < len(selected),
        }

    # ---------------------------------------------------------------- #
    # Scanning
    # ---------------------------------------------------------------- #

    def scan_value(
        self,
        session_id: str,
        value_type: str,
        value: str,
        scan_type: str = "exact",
        end_value: str = "",
        bufflength: int = 0,
        writable_only: bool = True,
    ) -> Dict[str, Any]:
        """Scan the target's memory for a value. The first step of the loop.

        This is Cheat Engine's "First Scan". It returns a ``scan_id``, a match
        count and a few sample addresses — not the addresses themselves, which
        routinely number in the tens of thousands. Narrow the set with
        ``refine_scan`` after the value changes in the target, and repeat until
        a handful remain; then read them with ``list_scan_results``.

        :param value_type: ``int``, ``float``, ``bool``, ``str`` or ``bytes``.
        :param value: the value to match. Hex is accepted for ``int``
            (``"0x64"``) and required for ``bytes`` (``"DEADBEEF"``).
        :param scan_type: ``exact`` (default), ``not_exact``, ``bigger``,
            ``bigger_or_exact``, ``smaller``, ``smaller_or_exact``, ``between``
            or ``not_between``.
        :param end_value: the upper bound, required by ``between`` /
            ``not_between`` and rejected otherwise.
        :param bufflength: width in bytes — ``4`` for a typical ``int``, ``8``
            for a ``double``. Leave at ``0`` for the default (int→4, float→8,
            bool→1) or, for ``str`` / ``bytes``, to infer it from ``value``.

            Numeric widths are restricted to 1, 2, 4 or 8 for ``int``, 4 or 8
            for ``float``, and 1 for ``bool``; anything else is refused rather
            than half-supported. Text is capped, inferred or not — see
            ``server_info().limits``.
        :param writable_only: restrict the scan to writable memory (the
            default). A value the program changes lives in writable memory, so
            this usually cuts the work and the false positives by an order of
            magnitude. Turn it off only when hunting constants.

        A scan stops early at the server's result cap or time budget; when it
        does, the result sets ``partial`` and explains what to narrow. Refining
        a partial set can converge on the wrong address, because the right one
        may never have been in it.
        """
        session = self.store.get(session_id)
        pytype = parse_value_type(value_type)
        scan_name, scan_enum = parse_scan_type(scan_type)

        parsed = parse_value(pytype, value)

        if scan_name in _RANGE_SCAN_TYPES:
            if end_value == "" or end_value is None:
                raise ToolError(
                    "scan_type=%r needs end_value as well as value (the range "
                    "bounds)." % scan_name
                )
            parsed_end = parse_value(pytype, end_value, field="end_value")
            width = parse_bufflength(bufflength, pytype, required=False)
            width = self._resolved_width(pytype, width, parsed, parsed_end)
            description = "%s in [%s, %s]%s" % (
                value_type,
                value,
                end_value,
                " (excluded)" if scan_name == "not_between" else "",
            )

            def make_scan(batch: Sequence[MemoryRegion]) -> Generator:
                return session.process.search_by_value_between(
                    pytype,
                    width,
                    start=parsed,
                    end=parsed_end,
                    not_between=(scan_name == "not_between"),
                    writeable_only=writable_only,
                    memory_regions=batch,
                )

        else:
            if end_value:
                raise ToolError(
                    "end_value only applies to scan_type 'between' / "
                    "'not_between' (got scan_type=%r)." % scan_name
                )
            width = parse_bufflength(bufflength, pytype, required=False)
            width = self._resolved_width(pytype, width, parsed)
            description = "%s %s %s" % (value_type, _SCAN_SYMBOLS[scan_name], value)

            def make_scan(batch: Sequence[MemoryRegion]) -> Generator:
                return session.process.search_by_value(
                    pytype,
                    width,
                    value=parsed,
                    scan_type=scan_enum,
                    writeable_only=writable_only,
                    memory_regions=batch,
                )

        with session.lock, self._target_errors(session, "scan_value"):
            regions = session.snapshot_regions(refresh=True)
            addresses, truncated, timed_out, elapsed = self._run_batched_scan(
                make_scan, regions
            )
            scan = self.store.new_scan(
                session,
                value_type=value_type.strip().lower(),
                bufflength=width,
                addresses=addresses,
                description=description,
                truncated=truncated,
                timed_out=timed_out,
            )
            samples = self._sample(session, scan)

        return self._scan_payload(scan, samples, elapsed, hint_next="refine_scan")

    def scan_pattern(self, session_id: str, pattern: str) -> Dict[str, Any]:
        """Scan for a byte pattern (an AOB scan) with ``?`` wildcards.

        The IDA / Cheat Engine technique for finding a structure or a piece of
        code whose address moves between builds but whose surrounding bytes do
        not: ``"48 8B ? ? 00 00 89"``. Returns a ``scan_id`` like
        ``scan_value``.

        :param pattern: space-separated hex bytes, where ``?`` or ``??`` is a
            single-byte wildcard.

        Note that this covers the target's readable, **non-shared** regions —
        heap, stack and anonymous mappings. File-backed code (a ``.dll`` /
        ``.so`` / ``.dylib`` image) is a shared mapping and is deliberately
        excluded, so patterns matching instructions inside a loaded module will
        not be found here. Reach module code through ``process_info``'s module
        bases plus a static offset instead.
        """
        session = self.store.get(session_id)
        text = (pattern or "").strip()
        if not text:
            raise ToolError(
                "pattern is required — space-separated hex bytes with '?' "
                "wildcards, e.g. '48 8B ? ? 00'."
            )

        def make_scan(batch: Sequence[MemoryRegion]) -> Generator:
            return session.process.search_by_pattern(text, memory_regions=batch)

        with session.lock, self._target_errors(session, "scan_pattern"):
            regions = session.snapshot_regions(refresh=True)
            try:
                addresses, truncated, timed_out, elapsed = self._run_batched_scan(
                    make_scan, regions
                )
            except ValueError as error:
                raise ToolError(
                    "Invalid pattern %r: %s. Use space-separated hex bytes with "
                    "'?' wildcards, e.g. '48 8B ? ? 00'." % (text, error)
                ) from None

            scan = self.store.new_scan(
                session,
                value_type="pattern",
                bufflength=None,
                addresses=addresses,
                description="pattern %s" % text,
                truncated=truncated,
                timed_out=timed_out,
            )
            samples = self._sample(session, scan)

        return self._scan_payload(scan, samples, elapsed, hint_next="read_value")

    def refine_scan(
        self,
        scan_id: str,
        scan_type: str = "exact",
        value: str = "",
        end_value: str = "",
    ) -> Dict[str, Any]:
        """Narrow an existing result set. The second step, repeated.

        This is Cheat Engine's "Next Scan", and it is what makes the whole
        workflow work: change the value in the target (take damage, spend a
        coin), then keep only the addresses that changed to match. Two or three
        rounds usually collapse tens of thousands of candidates to one.

        It re-reads the addresses already in the set rather than walking memory
        again, so it is orders of magnitude faster than a fresh scan and cannot
        find addresses the original scan missed. Each refine returns a *new*
        ``scan_id``; the previous set stays live, so a refine that narrows too
        far (down to zero) can be retried from the one before it.

        :param scan_id: the set to narrow.
        :param scan_type: comparison to apply — the same names ``scan_value``
            takes. For ``str`` / ``bytes`` sets only ``exact`` / ``not_exact``
            are available.
        :param value: the value to compare against.
        :param end_value: upper bound for ``between`` / ``not_between``.
        """
        session, previous = self.store.find_scan(scan_id)

        if previous.value_type == "pattern":
            raise ToolError(
                "Scan %s is a byte-pattern result set, which has no value to "
                "compare — run scan_pattern again instead of refining it."
                % scan_id
            )

        pytype = parse_value_type(previous.value_type)
        scan_name, scan_enum = parse_scan_type(scan_type)

        if pytype in (str, bytes) and scan_name not in _TEXT_SCAN_TYPES:
            raise ToolError(
                "scan_type=%r is not available for a %s result set — ordered "
                "comparison of text is ambiguous. Use 'exact' or 'not_exact'."
                % (scan_name, previous.value_type)
            )

        parsed = parse_value(pytype, value)
        parsed_end: Any = parsed

        if scan_name in _RANGE_SCAN_TYPES:
            if end_value == "" or end_value is None:
                raise ToolError(
                    "scan_type=%r needs end_value as well as value." % scan_name
                )
            parsed_end = parse_value(pytype, end_value, field="end_value")
            description = "%s in [%s, %s]%s" % (
                previous.value_type,
                value,
                end_value,
                " (excluded)" if scan_name == "not_between" else "",
            )
        else:
            # Same refusal `scan_value` makes. Ignoring it silently dropped
            # half of what the caller asked for: refine_scan(scan_type="exact",
            # value="90", end_value="100") became a plain exact-90, and when
            # that came back with no matches the hint said to try another
            # value, pointing away from the actual mistake.
            if end_value:
                raise ToolError(
                    "end_value only applies to scan_type 'between' / "
                    "'not_between'; scan_type=%r takes value alone." % scan_name
                )
            description = "%s %s %s" % (
                previous.value_type, _SCAN_SYMBOLS[scan_name], value
            )

        # A refine must keep exactly the addresses a fresh scan would, so it has
        # to compare the way a scan does — and a scan does NOT compare against
        # the caller's Python value. The target is encoded to bytes at the scan
        # width and decoded back (`decode_scan_target`), which is the identity
        # for `int` and 8-byte `float` and emphatically not for the rest:
        #
        #   * `float` at 4 bytes — Cheat Engine's default "Float" — turns 0.1
        #     into 0.10000000149011612, so comparing against the double 0.1
        #     rejected every address the scan had just matched;
        #   * `str` / `bytes` are compared as the integer view of their
        #     NUL-padded buffer, so any value shorter than `bufflength` missed.
        #
        # Both failed silently and only for those types, which is why the whole
        # loop looked fine on ints. Values are therefore re-read as raw bytes
        # and decoded through the same helper, so the comparison a refine
        # applies is the one a fresh scan applies.
        #
        # One deliberate difference, since "equivalent to a fresh scan" was
        # written here unqualified and is not true in general: for
        # ``not_exact`` on ``str`` / ``bytes`` a fresh scan also drops any
        # offset whose window *overlaps* an exact match (the bisect_left
        # window in ``scan_memory_for_exact_value``), so that byte-by-byte
        # stepping does not report the bytes beside a match as independent
        # hits. A refine cannot reproduce that and should not: it was handed
        # specific addresses and reads only those, with no view of the
        # neighbours the window is computed from. So a refine can keep an
        # address a fresh scan would have suppressed as adjacent. That is the
        # right answer for "does this address still not hold X", which is what
        # the caller asked.
        # Always concrete: scan_value resolves the width before storing it, and
        # the only result sets without one are byte-pattern scans, rejected
        # above. Re-deriving it from the *refine* value would be actively wrong
        # for str/bytes, where the width came from the original value.
        width = previous.bufflength
        if not width:
            raise ToolError(
                "Scan %s has no value width recorded, so it cannot be refined. "
                "Run a fresh scan_value instead." % scan_id
            )
        with session.lock, self._target_errors(session, "refine_scan"):
            started = monotonic()

            # Encoded inside the guard: value_to_bytes rejects a value that
            # does not fit `width` ("value 70000 does not fit in a 2-byte
            # integer"), which is a likely refine mistake and exactly the kind
            # of message the SDK would otherwise withhold.
            # The same byte order `scan_memory` picks: `str` compares
            # big-endian, everything else in host order (util/scan.py, where
            # `is_string = pytype is str`). Using `sys.byteorder` for `str`
            # too was harmless only because `_TEXT_SCAN_TYPES` limits text
            # refines to exact/not_exact, where both sides cancel -- so the
            # comment above claiming bit-for-bit equivalence with a fresh scan
            # held only as long as that guard stayed. Widening
            # `_TEXT_SCAN_TYPES` would have silently inverted bigger/smaller.
            byte_order = "big" if pytype is str else sys.byteorder

            target = decode_scan_target(
                value_to_bytes(pytype, width, parsed), byte_order, pytype
            )
            end_target = (
                decode_scan_target(
                    value_to_bytes(pytype, width, parsed_end), byte_order, pytype
                )
                if scan_name in _RANGE_SCAN_TYPES
                else target
            )
            predicate = make_predicate(scan_enum, target, target, end_target)

            kept: List[int] = []
            unreadable = 0

            for address, raw in self._read_addresses(
                session, previous.addresses, bytes, width
            ):
                if raw is None or len(raw) != width:
                    unreadable += 1
                    continue
                if predicate(decode_scan_target(raw, byte_order, pytype)):
                    kept.append(address)

            scan = self.store.new_scan(
                session,
                value_type=previous.value_type,
                bufflength=previous.bufflength,
                addresses=kept,
                description="%s -> %s" % (previous.description, description),
                # Narrowing a partial set keeps it partial: the addresses the
                # original scan never reached are still missing, and saying
                # otherwise is how a refine chain lies with confidence.
                truncated=previous.truncated,
                timed_out=previous.timed_out,
            )
            samples = self._sample(session, scan)

        payload = self._scan_payload(
            scan, samples, monotonic() - started, hint_next="refine_scan"
        )
        payload["refined_from"] = {
            "scan_id": previous.scan_id,
            "count": previous.count,
            "dropped": previous.count - scan.count,
            "unreadable": unreadable,
        }
        if scan.count == 0 and previous.count:
            payload["hint"] = (
                "Nothing matched. The value may not have changed the way you "
                "expected, or it is not this type/width. Refine %s again with a "
                "different value rather than starting over — the previous set is "
                "still live." % previous.scan_id
            )
        return payload

    def list_scan_results(
        self, scan_id: str, limit: int = 20, offset: int = 0
    ) -> Dict[str, Any]:
        """Page through a result set, reading each address's *current* value.

        Values are read live, so calling this twice on a set that is still
        changing is itself a useful signal: the address whose value tracks what
        you see in the target is the one you want.

        :param limit: rows per page. The server caps it — see
            ``server_info().limits.max_page_size``.
        :param offset: rows to skip.
        """
        session, scan = self.store.find_scan(scan_id)
        limit = max(1, min(parse_int_arg(limit or 20, "limit"), MAX_PAGE_SIZE))
        offset = max(0, parse_int_arg(offset or 0, "offset"))

        page = scan.addresses[offset : offset + limit]

        with session.lock, self._target_errors(session, "list_scan_results"):
            rows = self._rows_for(session, scan, page)

        return {
            "scan_id": scan.scan_id,
            "session_id": session.session_id,
            "description": scan.description,
            "results": rows,
            "returned": len(rows),
            "count": scan.count,
            "offset": offset,
            "has_more": offset + len(page) < scan.count,
            "partial": scan.is_partial,
        }

    # ---------------------------------------------------------------- #
    # Reading and writing
    # ---------------------------------------------------------------- #

    def read_value(
        self,
        session_id: str,
        address: str,
        value_type: str = "int",
        bufflength: int = 0,
    ) -> Dict[str, Any]:
        """Read one value from an address.

        :param address: hex string, e.g. ``"0x7FFD1234"``.
        :param value_type: ``int``, ``float``, ``bool``, ``str`` or ``bytes``.
        :param bufflength: width in bytes. Required for ``str`` / ``bytes``
            (nothing else says how far to read); defaults to int→4, float→8,
            bool→1 for the numeric types.

            Numeric widths are restricted to the ones every path agrees on:
            1, 2, 4 or 8 for ``int``, 4 or 8 for ``float``, 1 for ``bool``.
            Anything else is refused rather than half-supported. Text widths
            are capped — see ``server_info().limits``.
        """
        session = self.store.get(session_id)
        target = parse_address(address)
        pytype = parse_value_type(value_type)
        width = parse_bufflength(bufflength, pytype, required=True)

        with session.lock:
            try:
                value = session.process.read_process_memory(target, pytype, width)
            except OSError as error:
                raise ToolError(
                    "Could not read %s as %s: %s. The page may have been freed, "
                    "or the range crosses into unmapped memory."
                    % (format_address(target), value_type, error)
                ) from None
            except MemoryError as error:
                raise ToolError(
                    "Ran out of memory reading %s: %s. Ask for a smaller "
                    "bufflength." % (format_address(target), error)
                ) from None
            except (ValueError, PyMemoryEditorError) as error:
                raise ToolError("Read failed at %s: %s" % (format_address(target), error)) from None

        return {
            "session_id": session.session_id,
            "address": format_address(target),
            "value_type": value_type,
            "bufflength": width,
            "value": format_value(value),
        }

    def write_value(
        self,
        session_id: str,
        address: str,
        value_type: str,
        value: str,
        bufflength: int = 0,
    ) -> Dict[str, Any]:
        """Write a value to an address. Absent when the server is ``--read-only``.

        The previous value is read first and returned as ``previous_value``, so
        the change is reversible: to undo, call this again with that value.
        Nothing else in this server can put it back.

        :param address: hex string, e.g. ``"0x7FFD1234"``.
        :param value_type: ``int``, ``float``, ``bool``, ``str`` or ``bytes``.
        :param value: the value to write. Hex for ``bytes``.
        :param bufflength: for numbers, the exact write width — 1, 2, 4 or 8
            for ``int``, 4 or 8 for ``float``, 1 for ``bool``.

            For ``bytes`` it is a maximum number of bytes, which truncates and
            never pads. For ``str`` it caps **characters**, not bytes, so
            non-ASCII text can overwrite more bytes than the number you pass:
            ``bufflength=2`` with ``"日本語"`` writes ``"日本"`` — six bytes.
            The result's ``previous_value_bufflength`` always reports the span
            that was actually replaced, so check it rather than assuming.
        """
        if not self.config.allow_write:
            # Defence in depth: the tool is not registered without the flag, so
            # reaching here means something bypassed registration.
            raise ToolError(
                "Memory writes are disabled: this server was started with "
                "--read-only. Ask the user to restart it without that flag."
            )

        session = self.store.get(session_id)
        target = parse_address(address)
        pytype = parse_value_type(value_type)
        parsed = parse_value(pytype, value)
        width = parse_bufflength(bufflength, pytype, required=False)

        with session.lock:
            # Read back exactly the bytes the write is about to replace, so the
            # undo is lossless.
            #
            # Text is read as ``bytes``, not as ``str``, even when writing a
            # ``str``. ``read_process_memory(.., str, ..)`` decodes with
            # ``errors="replace"``, so any byte in the replaced range that is
            # not valid UTF-8 comes back as U+FFFD — and following the undo hint
            # would then write U+FFFD's own encoding over the original bytes,
            # corrupting the very memory the hint promises to restore. (For
            # multibyte text the widths disagree too: the read counts bytes
            # while a ``str`` write caps characters.)
            # Through the same ceiling the scan paths use. `_write_span` on an
            # omitted bufflength returns len(value), which drove both the undo
            # read's allocation *in this server* and the write into the target:
            # a 200 KB `bytes` value wrote 200 KB, 3x the cap the very same
            # call enforces when the width is explicit and past what
            # server_info advertises. The str case escaped even with an
            # explicit width, since that cap counts characters — 65000 of them
            # in CJK is 195 KB.
            replaced_width = self._capped_span(pytype, width, parsed)
            undo_type = "bytes" if pytype in (str, bytes) else value_type

            previous: Any = None
            try:
                previous = session.process.read_process_memory(
                    target,
                    bytes if pytype in (str, bytes) else pytype,
                    replaced_width,
                )
            except (MemoryError, OSError, ValueError, PyMemoryEditorError):
                # Not fatal: a write to a valid but unreadable-as-this-type
                # address is still legitimate. The caller just loses the undo.
                previous = None

            try:
                session.process.write_process_memory(target, pytype, width, parsed)
            except OSError as error:
                raise ToolError(
                    "Write to %s failed: %s. The region may be read-only or "
                    "freed — check list_memory_regions for a writable region "
                    "covering that address."
                    % (format_address(target), error)
                ) from None
            except MemoryError as error:
                raise ToolError(
                    "Ran out of memory writing to %s: %s. Ask for a smaller "
                    "value or bufflength." % (format_address(target), error)
                ) from None
            except (ValueError, PyMemoryEditorError) as error:
                raise ToolError(
                    "Write to %s rejected: %s" % (format_address(target), error)
                ) from None

        return {
            "session_id": session.session_id,
            "address": format_address(target),
            "value_type": value_type,
            # What actually landed, not what was asked for: a str/bytes
            # bufflength is a cap, so write_value(..., "DEADBEEF", 2) writes
            # DE AD. Echoing the request made the model report a change that
            # did not happen.
            "written": format_value(_truncate_to_span(pytype, parsed, replaced_width)),
            "requested": format_value(parsed),
            "previous_value": format_value(previous),
            # Text comes back as hex, so say which type to undo it with rather
            # than leaving the model to infer it from the shape of the value.
            "previous_value_type": None if previous is None else undo_type,
            # And the width, because replaying without it defaults to the
            # type's natural size: undoing a 4-byte float write as an 8-byte
            # double put zeros in the replaced span and clobbered four bytes
            # past it. The hint is documented as the only way back, so it has
            # to carry every argument needed to actually get back.
            "previous_value_bufflength": (
                None if previous is None else replaced_width
            ),
            "undo_hint": (
                None
                if previous is None
                else "Call write_value again with value_type=%r, value=%r, "
                "bufflength=%d to restore it."
                % (undo_type, format_value(previous), replaced_width)
            ),
        }

    # ---------------------------------------------------------------- #
    # Pointers
    # ---------------------------------------------------------------- #

    def resolve_pointer_chain(
        self,
        session_id: str,
        base_address: str,
        offsets: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Walk a known multi-level pointer chain to its final address.

        Replays the recipe a Cheat Engine table records —
        ``"game.exe"+0x10F4F4 -> [+0x0] -> [+0x158]`` — which is the form that
        survives a restart. Combine with ``process_info``'s module
        ``base_address`` to build ``base_address`` for the current run.

        :param base_address: where the chain starts, hex. Usually
            ``module_base + static_offset``.
        :param offsets: the chain's offsets in order, as hex strings
            (``["0x0", "0x158"]``). **Negative offsets are allowed**
            (``"-0x8"``) — walking backwards through a struct is ordinary in a
            published recipe. The last one is added *without* a final
            dereference, so the result is the address the value lives at — read
            it with ``read_value``. Pass an empty list to dereference
            ``base_address`` once.
        """
        session = self.store.get(session_id)
        base = parse_address(base_address, field="base_address")

        if isinstance(offsets, str):
            # Same hazard as ProcessPolicy.allowed_names, same fix: a str is a
            # valid sequence of str, so a scalar was consumed character by
            # character — "108" became a three-hop chain [1, 0, 8] instead of
            # one hop of 0x108. Whether that errors or silently resolves to a
            # plausible-looking wrong address depends on what happens to be
            # mapped in the target, which nobody controls; and the address goes
            # straight into read_value or write_value.
            offsets = [offsets]

        parsed_offsets = [
            parse_offset(offset, field="offset") for offset in (offsets or [])
        ]

        with session.lock:
            try:
                final = session.process.resolve_pointer_chain(base, parsed_offsets)
            except OSError as error:
                raise ToolError(
                    "Pointer chain from %s broke: %s. One of the hops pointed "
                    "into unmapped memory — the chain is stale (the object moved "
                    "or was freed), or an offset is wrong."
                    % (format_address(base), error)
                ) from None
            except (MemoryError, ValueError, PyMemoryEditorError) as error:
                raise ToolError("Could not resolve the chain: %s" % error) from None

        # The one address here the argument parsers never saw: it comes out of
        # the target's own memory plus the offsets. Handing back something that
        # would truncate the moment the model passed it to write_value is the
        # same bug as accepting it, one call later.
        #
        # The two directions are different failures and get different messages.
        # Below zero is the common one and it has a specific cause: the last
        # offset is added *without* a dereference, so a hop that read NULL (a
        # freed object, a chain built for another build) plus a negative offset
        # lands under zero. Calling that "outside any 64-bit address space" is
        # true but useless — it points at the offset instead of at the dead
        # pointer. It also has to be rendered with `format_offset`: `"0x%X" %
        # -8` is `"0x-8"`, the malformed form that function exists to prevent,
        # and this message was emitting it.
        if final < 0:
            raise ToolError(
                "The chain resolved to %s, below zero. The last offset is "
                "applied without a dereference, so a hop that read NULL plus a "
                "negative offset lands here — the chain is stale (the object "
                "was freed or never existed in this build), not merely "
                "misaligned."
                % format_offset(final)
            )

        if final > MAX_ADDRESS:
            raise ToolError(
                "The chain resolved to 0x%X, which is outside any 64-bit "
                "address space. One of the hops read a value that is not a "
                "pointer, so the chain is stale or an offset is wrong."
                % final
            )

        return {
            "session_id": session.session_id,
            "base_address": format_address(base),
            "offsets": [format_offset(offset) for offset in parsed_offsets],
            "address": format_address(final),
            "next_step": "Read it with read_value(address=%s)." % format_address(final),
        }

    def find_pointer_paths(
        self,
        session_id: str,
        target_address: str,
        max_depth: int = POINTER_SCAN_DEFAULTS["max_depth"],
        max_offset: int = POINTER_SCAN_DEFAULTS["max_offset"],
        max_results: int = POINTER_SCAN_DEFAULTS["max_results"],
    ) -> Dict[str, Any]:
        """Reverse-scan for static pointer paths that reach an address.

        The inverse of ``resolve_pointer_chain``, and the step that turns a
        throwaway find into something reusable: an address from ``scan_value``
        is different every run, but a path rooted in a module's image is the
        same recipe every time. Run this on the address you confirmed, then
        replay the best path in the next run with ``resolve_pointer_chain``.

        :param target_address: the dynamic address to find paths to.
        :param max_depth: pointer levels to follow. Cost grows sharply with
            depth; 1–4 is the useful range and 3 is a good default. A chain
            needs at least one level, so ``0`` clamps to 1 rather than to the
            default — and ``null`` means "use the default", as it does for
            every argument here.
        :param max_offset: largest offset a single hop may add — effectively
            the assumed struct size. Larger finds more and noisier paths.
            An explicit ``0`` is meaningful rather than "unset": it keeps only
            hops that point exactly at the address. ``null`` means "use the
            default" (1024) — it used to mean 0, i.e. the narrowest search
            possible, which is the opposite of what a client sending null for
            an unset field intends.
        :param max_results: stop after this many paths.

        This is the most expensive tool here, and it runs in two phases: it
        maps every pointer in the target's writable memory, then walks that map
        backwards. Only the first phase reports progress, so the server's time
        budget bounds it precisely and the second phase only between paths —
        a deep walk that finds nothing can still run long. Expect seconds to
        minutes on a large process, and start shallow.

        """
        session = self.store.get(session_id)
        target = parse_address(target_address, field="target_address")
        # `is None` rather than a falsy test, and one rule for all three: a
        # client is free to send JSON null for an unset integer, and each of
        # these then means "use the documented default" — including
        # max_offset, whose 0 stays meaningful when it is passed explicitly.
        max_depth = _clamp_pointer_arg("max_depth", max_depth)
        max_offset = _clamp_pointer_arg("max_offset", max_offset)
        max_results = _clamp_pointer_arg("max_results", max_results)

        # Both clocks start once the target is ours. Computed before the lock
        # they would count time spent *queued* behind another tool call, and a
        # call that waited out the whole budget would report a timeout having
        # done no work at all.
        deadline = 0.0
        timed_out_phase: Optional[str] = None

        def progress(_fraction: float) -> None:
            # `scan_pointer_paths` runs in two phases and only the first one
            # reports progress: `build_pointer_map` reads the target's writable
            # memory and finishes *entirely* before the first path is yielded.
            # So this callback bounds the map, and the reverse walk below needs
            # its own check — which is also why a timeout here always means
            # zero paths, and why max_depth / max_offset (consumed only by the
            # walk) cannot be the remedy for it.
            nonlocal timed_out_phase
            if monotonic() >= deadline:
                timed_out_phase = "pointer_map"
                raise _ScanDeadline()

        paths: List[Dict[str, Any]] = []

        with session.lock, self._target_errors(session, "find_pointer_paths"):
            started = monotonic()
            deadline = started + self.config.max_scan_seconds
            # Inside the guard: this walks the target's region map, and on a
            # process that has exited it raises the same OSError every other
            # region-walking tool translates.
            regions = session.snapshot_regions(refresh=True)
            try:
                for path in session.process.scan_pointer_paths(
                    target,
                    max_depth=max_depth,
                    max_offset=max_offset,
                    max_results=max_results,
                    memory_regions=regions,
                    progress_callback=progress,
                ):
                    paths.append(
                        {
                            **path.to_dict(),
                            "recipe": str(path),
                            "static": path.module is not None,
                        }
                    )
                    # The reverse walk has no progress callback, so this is the
                    # only place its runtime can be bounded. It is not a
                    # guarantee — a deep walk can go a long time between yields
                    # — but it stops a productive-but-endless scan from holding
                    # the session lock forever.
                    if monotonic() >= deadline:
                        timed_out_phase = "path_search"
                        break
            except _ScanDeadline:
                pass
            except (OSError, ValueError, PyMemoryEditorError) as error:
                raise ToolError("Pointer scan failed: %s" % error) from None

        result = {
            "session_id": session.session_id,
            "target_address": format_address(target),
            "paths": paths,
            "count": len(paths),
            "max_depth": max_depth,
            "max_offset": max_offset,
            "elapsed_seconds": round(monotonic() - started, 3),
            "timed_out": timed_out_phase is not None,
            "timed_out_phase": timed_out_phase,
        }
        if timed_out_phase == "pointer_map":
            # Advice has to name the phase that actually ran out of time. The
            # map is built before any path is searched for, so no paths exist
            # yet and depth/offset — which only the search uses — cannot help.
            result["hint"] = (
                "The %.0fs budget ran out while mapping the target's pointers, "
                "before any path was searched for, so no paths were found. That "
                "phase is driven by how much writable memory the target has, "
                "not by max_depth or max_offset: ask the operator to raise "
                "--max-scan-seconds, or try a smaller target."
                % self.config.max_scan_seconds
            )
        elif timed_out_phase == "path_search":
            result["hint"] = (
                "The %.0fs budget ran out while walking the pointer graph, so "
                "these are the paths found first rather than the best ones. "
                "Retry with a smaller max_depth or max_offset for a faster, "
                "narrower search."
                % self.config.max_scan_seconds
            )
        elif not paths:
            result["hint"] = (
                "No static path reached that address. It may live in memory no "
                "module points to (a fresh allocation), or the chain is deeper "
                "than max_depth — try max_depth=4 and a larger max_offset."
            )
        return result

    # ---------------------------------------------------------------- #
    # Internals
    # ---------------------------------------------------------------- #

    def _resolved_width(self, pytype: Type, width: Optional[int], *values: Any) -> int:
        """Resolve a width from the value, then apply the same text cap.

        ``parse_bufflength`` capped an *explicit* ``bufflength``, but leaving it
        at 0 — which the tools' own docstrings recommend — inferred the width
        from the value with no ceiling at all, handing
        ``create_string_buffer`` whatever length the model happened to send.
        That reopened the allocation path the cap exists to close, and the
        inferred width is then stored on the scan and reused by every refine.
        """
        resolved = resolve_bufflength_for_value(pytype, width, *values)
        if pytype in (str, bytes) and resolved > MAX_TEXT_BYTES:
            raise ToolError(
                "The value is %d bytes, over the %d-byte limit for a %s scan. "
                "Sizing a buffer that large in this server would risk killing "
                "it. Search for a shorter, distinctive fragment instead."
                % (resolved, MAX_TEXT_BYTES, pytype.__name__)
            )
        return resolved

    @contextmanager
    def _target_errors(self, session: Session, action: str):
        """Translate a backend failure into a message the model can act on.

        ``_surface_errors`` in the protocol layer only forwards our own
        ``ToolError``; anything else the SDK wraps in ``UnexpectedToolError``,
        whose message deliberately withholds the original text. So an
        untranslated ``OSError`` reaches the model as a bare "Error executing
        tool <name>" — with no hint that the answer is "the target exited".

        That is the realistic failure here, not an exotic one: the user closes
        the game mid-session and the next region walk fails (on Linux,
        ``FileNotFoundError`` off ``/proc/<pid>/maps``).
        """
        try:
            yield
        except ToolError:
            raise
        except ValueError as error:
            # The encoders reject a value that cannot fit the requested width
            # ("value 70000 does not fit in a 2-byte integer", "byte string too
            # long"). Those messages are already the right advice — they just
            # never reached the model, because the SDK withholds the text of
            # anything that is not our ToolError.
            raise ToolError(
                "%s rejected an argument: %s. Check value_type, value and "
                "bufflength against each other — a value has to fit the width "
                "you asked for." % (action, error)
            ) from None
        except MemoryError as error:
            # A width the caps let through can still fail to allocate. This is
            # neither OSError nor PyMemoryEditorError, so it used to reach the
            # model as a bare "Error executing tool".
            raise ToolError(
                "%s ran out of memory: %s. Ask for a smaller bufflength or a "
                "narrower scan." % (action, error)
            ) from None
        except (OSError, PyMemoryEditorError) as error:
            raise ToolError(
                '%s failed on "%s" (pid %d): %s. The target has most likely '
                "exited or freed that memory. Call close_process and reopen it "
                "if it is still running; otherwise tell the user it is gone."
                % (action, session.name or "unknown", session.pid, error)
            ) from None

    def _capped_span(self, pytype: Type, width: Optional[int], value: Any) -> int:
        """:meth:`_write_span`, with the text ceiling applied.

        Separate from ``_write_span`` because that one answers "how many bytes
        will this write touch?", which callers need even when the answer is too
        large; this one is the gate.
        """
        span = self._write_span(pytype, width, value)
        if pytype in (str, bytes) and span > MAX_TEXT_BYTES:
            raise ToolError(
                "That value would overwrite %d bytes, over the %d-byte limit. "
                "Writing that much into a live process is almost never what "
                "you meant — pass a smaller value, or a bufflength that keeps "
                "the span under the limit. (For a `str`, bufflength counts "
                "characters, so non-ASCII text needs a smaller number.)"
                % (span, MAX_TEXT_BYTES)
            )
        return span

    @staticmethod
    def _write_span(pytype: Type, width: Optional[int], value: Any) -> int:
        """How many bytes :meth:`write_value` is about to overwrite.

        Always a concrete count, never ``None``. It is reported to the model as
        ``previous_value_bufflength`` and interpolated into the undo hint, so an
        unresolved width there meant the most ordinary call of all —
        ``write_value(.., "int", "5")`` with the schema's default
        ``bufflength=0`` — died on ``"%d" % None``.

        For ``str`` / ``bytes`` an explicit ``width`` is a *cap* rather than an
        exact size, so the span is whichever is smaller; the value never pads.
        """
        if pytype is str:
            # A str cap counts characters, so re-encode the truncated value to
            # learn how many bytes actually land.
            text = value[:width] if width else value
            return len(text.encode("utf-8"))
        if pytype is bytes:
            return min(len(value), width) if width else len(value)
        # Numeric: the exact width the write will use, resolved the same way
        # the write path resolves it (int→4, float→8, bool→1).
        return resolve_bufflength(pytype, width)

    def _open_kwargs(self, pid: int) -> Dict[str, Any]:
        """Build the ``OpenProcess`` keywords for the current safety mode.

        On Windows a read-only server opens the target with a handle that
        carries no write rights at all, so the kernel — not this process —
        enforces the read-only promise. Linux and macOS have no equivalent
        per-handle right in this library, so there the guarantee rests on
        ``write_value`` never being registered.
        """
        kwargs: Dict[str, Any] = {"pid": pid}

        if self.config.allow_write or host_platform() != "windows":
            return kwargs

        try:
            from ..win32.enums.process_operations import ProcessOperationsEnum
        except ImportError:  # pragma: no cover - non-Windows host
            return kwargs

        kwargs["permission"] = (
            ProcessOperationsEnum.PROCESS_VM_READ
            | ProcessOperationsEnum.PROCESS_QUERY_INFORMATION
        )
        return kwargs

    @staticmethod
    def _bitness(process: AbstractProcess) -> Dict[str, Any]:
        """Report target bitness without letting a detection failure abort."""
        try:
            return {
                "is_64bit": process.is_64bit,
                "pointer_size": process.pointer_size,
                "bitness_certain": process.is_bitness_certain,
            }
        except (PyMemoryEditorError, OSError):
            # OSError too: bitness detection falls back to walking the region
            # map, which raises FileNotFoundError off /proc/<pid>/maps on Linux
            # if the target exits between OpenProcess and this read. `attach`
            # is the first tool a user hits and sits outside _target_errors,
            # so an unreported bitness beats a raw OSError there.
            return {
                "is_64bit": None,
                "pointer_size": None,
                "bitness_certain": False,
            }

    def _name_for_pid(self, pid: int) -> str:
        """Best-effort executable name for a pid, for the policy check.

        Guarded: this runs on every ``open_process(pid=...)`` — the most common
        flow there is — and an enumeration failure here used to escape as a raw
        OSError, which is exactly the stripped "Error executing tool
        open_process" the translation layer exists to prevent.
        """
        try:
            for found_pid, name in iter_processes():
                if found_pid == pid:
                    return name or ""
        except OSError as error:
            raise ToolError(
                "Could not enumerate processes to identify pid %d: %s. This is "
                "usually transient — try again once before reporting it."
                % (pid, error)
            ) from None
        # Not in the listing: either it just exited, or this user cannot read
        # its name. Let the policy see an empty name (the PID gate still
        # applies) and OpenProcess produce the real error.
        return ""

    def _run_batched_scan(
        self,
        make_scan: Callable[[Sequence[MemoryRegion]], Generator],
        regions: Sequence[MemoryRegion],
    ) -> Tuple[List[int], bool, bool, float]:
        """Drive a scan batch by batch, honouring both the count and time caps.

        See :func:`PyMemoryEditor.mcp.session.batch_regions` for why the scan is
        split at all: a value scan yields only on hits, so scanning for a rare
        value gives the consumer no chance to check a clock.
        """
        limit = self.config.max_scan_results
        started = monotonic()
        deadline = started + self.config.max_scan_seconds

        addresses: List[int] = []
        truncated = False
        timed_out = False

        for batch in batch_regions(regions, self.config.scan_batch_bytes):
            if monotonic() >= deadline:
                timed_out = True
                break

            generator = make_scan(batch)
            try:
                for address in generator:
                    addresses.append(address)
                    # Collect one *past* the cap to tell a complete set of
                    # exactly `limit` matches from a genuinely truncated one.
                    # Stopping at `limit` marked the former partial, and
                    # refine_scan propagates that flag down the whole chain —
                    # so the server would keep insisting a model rescan a set
                    # that was already exhaustive.
                    if len(addresses) > limit:
                        truncated = True
                        break
            finally:
                close = getattr(generator, "close", None)
                if close is not None:
                    close()

            if truncated:
                break

        addresses.sort()
        if truncated:
            del addresses[limit:]
        return addresses, truncated, timed_out, monotonic() - started

    def _read_addresses(
        self,
        session: Session,
        addresses: Sequence[int],
        pytype: Type,
        bufflength: Optional[int],
    ) -> Generator[Tuple[int, Any], None, None]:
        """Yield ``(address, value | None)`` for each address, in one pass.

        Uses ``search_by_addresses``, which groups the reads by region so a
        50 000-address refine is a few hundred syscalls rather than 50 000.
        """
        yield from session.process.search_by_addresses(
            pytype,
            bufflength,
            addresses=list(addresses),
            memory_regions=session.regions,
        )

    def _rows_for(
        self, session: Session, scan: ScanResult, addresses: Sequence[int]
    ) -> List[Dict[str, Any]]:
        """Render ``addresses`` with their current values, when there is a type."""
        if not addresses:
            return []

        if scan.value_type == "pattern":
            return [{"address": format_address(address)} for address in addresses]

        pytype = VALUE_TYPES[scan.value_type]

        try:
            values = dict(
                self._read_addresses(session, addresses, pytype, scan.bufflength)
            )
        except (OSError, PyMemoryEditorError):
            # The target died or the region vanished mid-page. The addresses are
            # still worth returning; the values are not.
            return [{"address": format_address(address)} for address in addresses]

        # Emitted in the order asked for — ``search_by_addresses`` sorts
        # internally, and re-deriving the order from its output would silently
        # renumber the page the caller is looking at.
        return [
            {
                "address": format_address(address),
                "value": format_value(values.get(address)),
                "readable": values.get(address) is not None,
            }
            for address in addresses
        ]

    def _sample(self, session: Session, scan: ScanResult) -> List[Dict[str, Any]]:
        """A short, evenly-spread preview of a result set.

        Spread rather than the first N: the first ten hits of a scan are all in
        the lowest region and look identical, which tells the model nothing
        about whether its value type and width were right.
        """
        total = scan.count
        if total <= SAMPLE_SIZE:
            picked = list(scan.addresses)
        else:
            step = total / float(SAMPLE_SIZE)
            picked = [scan.addresses[int(index * step)] for index in range(SAMPLE_SIZE)]

        return self._rows_for(session, scan, picked)

    def _scan_payload(
        self,
        scan: ScanResult,
        samples: List[Dict[str, Any]],
        elapsed: float,
        *,
        hint_next: str,
    ) -> Dict[str, Any]:
        """The common shape of every scan result."""
        payload: Dict[str, Any] = {
            "scan_id": scan.scan_id,
            "session_id": scan.session_id,
            "description": scan.description,
            "count": scan.count,
            "sample": samples,
            "sample_note": (
                None
                if scan.count <= SAMPLE_SIZE
                else "%d of %d addresses, spread across the result set. Page "
                "through them with list_scan_results, or narrow the set first."
                % (len(samples), scan.count)
            ),
            "elapsed_seconds": round(elapsed, 3),
            "partial": scan.is_partial,
        }

        if scan.truncated:
            payload["partial_reason"] = (
                "Stopped at the server's %d-result cap, so this set is a prefix "
                "of the real matches. Narrow the scan (a more specific value, a "
                "narrower type or width, writable_only=true) — refining a "
                "prefix can converge confidently on the wrong address."
                % self.config.max_scan_results
            )
        elif scan.timed_out:
            payload["partial_reason"] = (
                "Stopped at the server's %.0fs budget, so part of the address "
                "space was never scanned. The value may be in the part that was "
                "skipped; narrow the scan and try again."
                % self.config.max_scan_seconds
            )
        elif scan.count == 0:
            payload["hint"] = (
                "No matches. The most common causes, in order: the wrong width "
                "(try bufflength=8 or 2 for an int), the wrong type (a health "
                "bar is often a float), or writable_only=true excluding it."
            )
        elif scan.count > 1 and hint_next == "refine_scan":
            payload["hint"] = (
                "Now change the value inside the target (take damage, spend a "
                "coin) and call refine_scan(scan_id=%s) with the new value. "
                "Repeat until a few addresses remain." % scan.scan_id
            )

        return payload


def _truncate_to_span(pytype: Type, value: Any, span: Optional[int]) -> Any:
    """The part of ``value`` that a write of ``span`` bytes actually stores.

    Only ``str`` / ``bytes`` can differ: their ``bufflength`` is a cap that
    truncates. Numeric writes always store the whole value or fail.
    """
    if span is None:
        return value
    if pytype is bytes:
        return value[:span]
    if pytype is str:
        encoded = value.encode("utf-8")[:span]
        # Never split a multibyte character in the reported value.
        return encoded.decode("utf-8", errors="ignore")
    return value


def _clamp_pointer_arg(name: str, value: Any) -> int:
    """Resolve one ``find_pointer_paths`` argument: null means the default.

    Written once for all three because writing it per argument is how they
    came to disagree — ``max_offset or 0`` sent a null to the narrowest
    possible search while ``max_depth or 3`` sent it to the documented one.
    """
    low, high = POINTER_SCAN_LIMITS[name]
    resolved = parse_int_arg(value, name, default=POINTER_SCAN_DEFAULTS[name])
    return min(max(resolved, low), high)


class _ScanDeadline(Exception):
    """Internal: unwinds a pointer scan that ran past its time budget."""


#: Human-readable operator per scan type, for result descriptions.
_SCAN_SYMBOLS = {
    "exact": "==",
    "not_exact": "!=",
    "bigger": ">",
    "bigger_or_exact": ">=",
    "smaller": "<",
    "smaller_or_exact": "<=",
    "between": "in",
    "not_between": "not in",
}


def _permission_hint() -> str:
    """Platform-specific advice for a failed attach — the usual first blocker."""
    platform = host_platform()
    if platform == "linux":
        return (
            "On Linux, reading another user's process needs matching privileges "
            "and a permissive ptrace_scope (see /proc/sys/kernel/yama/"
            "ptrace_scope); the client may need to run the server with sudo."
        )
    if platform == "macos":
        return (
            "On macOS, task_for_pid requires root or the com.apple.security."
            "cs.debugger entitlement, and SIP protects Apple binaries outright. "
            "The client usually has to launch the server with sudo."
        )
    if platform == "windows":
        return (
            "On Windows, opening a process running at a higher integrity level "
            "needs an elevated client (Run as administrator)."
        )
    return ""


__all__ = (
    "MAX_PAGE_SIZE",
    "SAMPLE_SIZE",
    "SCAN_TYPES",
    "VALUE_TYPES",
    "MemoryToolset",
    "ToolError",
    "format_address",
    "format_value",
    "parse_address",
    "parse_value",
)
