# -*- coding: utf-8 -*-

"""The same expectations, run against the fake target *and* a real process.

Three separate review passes over this package each found a bug that the 300+
tests in ``test_toolset.py`` could not have caught, and all three had the same
shape: the fake in ``conftest.py`` behaved differently from the real backends,
so an assertion that passed against the fake said nothing about production.

  * the fake compared scan values without the byte round trip, so ``refine_scan``
    silently dropped every float32 and NUL-padded-text match;
  * the injected opener ignored the pid, so a negative pid looked fine;
  * the fake padded a capped ``str`` write where every real backend truncates.

Reviewing case by case does not fix that; running the assertions on both
targets does. Every test here is parametrized over the two, so a divergence
fails instead of hiding — and, unlike a fake-vs-real *diff*, an expectation
stated absolutely also catches the case where both are wrong the same way.

Scans are slow-marked (they walk a real address space); reads, writes, spans
and argument errors are not, so the fast lane still guards the fidelity that
bit us most.
"""

import ctypes
import os

import pytest

from PyMemoryEditor.mcp import MemoryToolset, ServerConfig
from PyMemoryEditor.mcp.toolset import ToolError

from .conftest import WRITABLE_BASE, FakeProcess, _toolset_for, config


class Target:
    """One attachable target, with a place to plant bytes in it."""

    def __init__(self, kind: str, toolset: MemoryToolset, session_id: str) -> None:
        self.kind = kind
        self.toolset = toolset
        self.session_id = session_id
        self._anchors: list = []

    def scratch(self, size: int = 32) -> int:
        """Return the address of a fresh, writable, zeroed scratch buffer."""
        raise NotImplementedError

    def raw(self, address: int, size: int) -> bytes:
        """Read raw bytes back, through the toolset so both paths are exercised."""
        hexed = self.toolset.read_value(
            self.session_id, hex(address), "bytes", size
        )["value"]
        return bytes.fromhex(hexed)

    def fill(self, address: int, size: int, byte: int = 0xAA) -> None:
        self.toolset.write_value(
            self.session_id, hex(address), "bytes", bytes([byte] * size).hex()
        )


class FakeTarget(Target):
    def __init__(self, process: FakeProcess, toolset: MemoryToolset, session_id: str):
        super().__init__("fake", toolset, session_id)
        self.process = process
        self._next = WRITABLE_BASE + 0x400

    def scratch(self, size: int = 32) -> int:
        address = self._next
        self._next += size + 0x40  # keep buffers clear of each other
        self.process.poke(address, bytes, b"\x00" * size, size)
        return address


class RealTarget(Target):
    def scratch(self, size: int = 32) -> int:
        buffer = (ctypes.c_char * size)(*b"\x00" * size)
        self._anchors.append(buffer)  # keep it alive for the test's duration
        return ctypes.addressof(buffer)


@pytest.fixture(params=["fake", "real"])
def target(request):
    """The same toolset API over the fake target and over this process."""
    if request.param == "fake":
        process = FakeProcess()
        toolset = _toolset_for(process, config(max_scan_seconds=120))
        session_id = toolset.open_process(pid=4242)["session_id"]
        yield FakeTarget(process, toolset, session_id)
        toolset.store.close_all()
        return

    toolset = MemoryToolset(
        ServerConfig(allow_any_process=True, max_scan_seconds=180)
    )
    session_id = toolset.open_process(pid=os.getpid())["session_id"]
    yield RealTarget("real", toolset, session_id)
    toolset.store.close_all()


# --------------------------------------------------------------------------- #
# Writes: the semantics the third review pass found diverging
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "value_type, value, bufflength, expected",
    [
        # A str/bytes bufflength caps and truncates; it never pads.
        ("str", "hello", 3, b"hel"),
        ("str", "ola", 10, b"ola"),
        ("str", "ok", None, b"ok"),
        ("bytes", "DEADBEEF", 2, b"\xde\xad"),
        ("bytes", "DEAD", 8, b"\xde\xad"),
        ("bytes", "DEAD", None, b"\xde\xad"),
    ],
)
def test_capped_text_writes_agree(target, value_type, value, bufflength, expected):
    address = target.scratch()
    target.fill(address, 16, 0xAA)

    target.toolset.write_value(
        target.session_id, hex(address), value_type, value, bufflength or 0
    )

    written = target.raw(address, 16)
    assert written[: len(expected)] == expected
    # Nothing past the value is touched: no padding, no clobber.
    assert written[len(expected) :] == b"\xaa" * (16 - len(expected))


@pytest.mark.parametrize(
    "value_type, value, bufflength, expected",
    [
        ("int", "1000", 4, (1000).to_bytes(4, "little")),
        ("int", "-1000", 4, (-1000).to_bytes(4, "little", signed=True)),
        ("int", "-42", 2, (-42).to_bytes(2, "little", signed=True)),
        ("bool", "true", 1, b"\x01"),
        ("bool", "false", 1, b"\x00"),
    ],
)
def test_numeric_writes_agree(target, value_type, value, bufflength, expected):
    address = target.scratch()
    target.fill(address, 16, 0xAA)

    target.toolset.write_value(
        target.session_id, hex(address), value_type, value, bufflength
    )
    assert target.raw(address, len(expected)) == expected


def test_float_writes_agree(target):
    address = target.scratch()
    for bufflength, ctype in ((4, ctypes.c_float), (8, ctypes.c_double)):
        target.toolset.write_value(
            target.session_id, hex(address), "float", "2.5", bufflength
        )
        assert target.raw(address, bufflength) == bytes(ctype(2.5))


# --------------------------------------------------------------------------- #
# The undo contract
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "value_type, first, second, bufflength",
    [
        ("int", "4321", "99", 4),
        ("int", "-7", "7", 2),
        ("float", "2.5", "9.5", 4),
        ("float", "2.5", "9.5", 8),
        ("str", "hello", "ab", 0),
        ("str", "hello", "ab", 3),
        ("bytes", "DEADBEEF", "0102", 0),
        ("bool", "true", "false", 1),
    ],
)
def test_undo_restores_exactly_what_was_replaced(
    target, value_type, first, second, bufflength
):
    """``previous_value`` must round-trip through ``write_value`` losslessly."""
    address = target.scratch()
    target.fill(address, 16, 0xAA)
    target.toolset.write_value(
        target.session_id, hex(address), value_type, first, bufflength
    )
    before = target.raw(address, 16)

    written = target.toolset.write_value(
        target.session_id, hex(address), value_type, second, bufflength
    )
    assert target.raw(address, 16) != before

    target.toolset.write_value(
        target.session_id, hex(address),
        written["previous_value_type"], str(written["previous_value"]),
        bufflength if written["previous_value_type"] == value_type else 0,
    )
    assert target.raw(address, 16) == before


def test_undo_survives_bytes_that_are_not_valid_utf8(target):
    address = target.scratch()
    target.toolset.write_value(
        target.session_id, hex(address), "bytes", "FFFEFDFC"
    )
    before = target.raw(address, 4)

    written = target.toolset.write_value(
        target.session_id, hex(address), "str", "ab"
    )
    target.toolset.write_value(
        target.session_id, hex(address),
        written["previous_value_type"], written["previous_value"],
    )
    assert target.raw(address, 4) == before


# --------------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "value_type, written, bufflength, expected",
    [
        ("int", "1000", 4, 1000),
        ("int", "-1000", 4, -1000),
        ("int", "-42", 2, -42),
        ("float", "2.5", 4, 2.5),
        ("float", "0.1", 8, 0.1),
        ("bool", "true", 1, True),
        ("str", "hi", 2, "hi"),
        ("bytes", "DEAD", 2, "DEAD"),
    ],
)
def test_reads_agree(target, value_type, written, bufflength, expected):
    address = target.scratch()
    target.toolset.write_value(
        target.session_id, hex(address), value_type, written, bufflength
    )
    read = target.toolset.read_value(
        target.session_id, hex(address), value_type, bufflength
    )
    assert read["value"] == expected


def test_float32_reads_back_narrowed(target):
    """0.1 through a 4-byte float is 0.10000000149011612 on both targets."""
    address = target.scratch()
    target.toolset.write_value(target.session_id, hex(address), "float", "0.1", 4)
    read = target.toolset.read_value(target.session_id, hex(address), "float", 4)
    assert read["value"] == ctypes.c_float(0.1).value
    assert read["value"] != 0.1


# --------------------------------------------------------------------------- #
# Argument errors: the class that reaches the model stripped of its message
# --------------------------------------------------------------------------- #

def _outcome(call) -> str:
    try:
        call()
    except ToolError:
        return "ToolError"
    except Exception as error:  # noqa: BLE001 — that is the finding
        return "raw:%s" % type(error).__name__
    return "ok"


@pytest.mark.parametrize(
    "label, build",
    [
        ("int too wide", lambda t: lambda: t.toolset.scan_value(
            t.session_id, "int", "70000", bufflength=2)),
        ("text too long", lambda t: lambda: t.toolset.scan_value(
            t.session_id, "str", "hello", bufflength=2)),
        ("empty str", lambda t: lambda: t.toolset.scan_value(
            t.session_id, "str", "")),
        ("empty bytes", lambda t: lambda: t.toolset.scan_value(
            t.session_id, "bytes", "")),
        ("unmapped read", lambda t: lambda: t.toolset.read_value(
            t.session_id, "0xDEAD0000", "int", 4)),
        ("text read without width", lambda t: lambda: t.toolset.read_value(
            t.session_id, "0x1000", "str")),
        ("bad address", lambda t: lambda: t.toolset.read_value(
            t.session_id, "nonsense", "int", 4)),
        ("negative pid", lambda t: lambda: t.toolset.open_process(pid=-1)),
        ("both pid and name", lambda t: lambda: t.toolset.open_process(
            pid=1, name="x")),
        ("bad pattern", lambda t: lambda: t.toolset.scan_pattern(
            t.session_id, "   ")),
        ("unknown value_type", lambda t: lambda: t.toolset.read_value(
            t.session_id, "0x1000", "uint64", 8)),
        ("unknown scan_type", lambda t: lambda: t.toolset.scan_value(
            t.session_id, "int", "1", scan_type="greater", bufflength=4)),
    ],
)
def test_argument_errors_reach_the_model(target, label, build):
    """Every foreseeable mistake must be a ToolError, on both targets.

    A raw exception is withheld by the SDK, so the model sees only
    "Error executing tool <name>" and retries the same broken call.
    """
    assert _outcome(build(target)) == "ToolError", label


# --------------------------------------------------------------------------- #
# The scan / refine property (slow: walks a real address space)
# --------------------------------------------------------------------------- #

@pytest.mark.slow
@pytest.mark.parametrize(
    "value_type, value, bufflength, scan_type",
    [
        ("int", "246813", 4, "exact"),
        ("int", "-246813", 4, "exact"),
        ("int", "-4242", 2, "exact"),
        ("float", "0.1", 4, "exact"),
        ("float", "0.1", 8, "exact"),
        ("str", "hi", 2, "exact"),
        ("str", "hi", 8, "exact"),
        ("bytes", "DEAD", 8, "exact"),
        ("bool", "true", 1, "exact"),
    ],
)
def test_a_scanned_address_survives_a_refine(
    target, value_type, value, bufflength, scan_type
):
    """The core loop, as a property that holds on any target.

    Stated as a property rather than as set equality on purpose: two identical
    scans of a *live* process already disagree, because its memory churns. What
    must hold regardless is that an address the scan just matched is still
    there after refining for the same value.
    """
    address = target.scratch()
    target.toolset.write_value(
        target.session_id, hex(address), value_type, value, bufflength
    )

    scan = target.toolset.scan_value(
        target.session_id, value_type, value,
        scan_type=scan_type, bufflength=bufflength, writable_only=True,
    )
    found = target.toolset.store.find_scan(scan["scan_id"])[1].addresses
    if address not in found:
        # Skip only for the one legitimate reason: the value is so common
        # (`bool` true matches every 0x01 byte) that the scan hit its result
        # cap before reaching our buffer. Anything else means the *scan* is
        # broken, and skipping would turn that into a silent green.
        assert scan["partial"], (
            "an exhaustive scan for %r missed the address we just wrote it to "
            "(%s target) — the scan itself is wrong, not the refine"
            % (value, target.kind)
        )
        pytest.skip(
            "scan hit its result cap before reaching the scratch buffer (%s)"
            % target.kind
        )

    refined = target.toolset.refine_scan(scan["scan_id"], value=value)
    kept = target.toolset.store.find_scan(refined["scan_id"])[1].addresses
    assert address in kept


# --------------------------------------------------------------------------- #
# Widths that would corrupt this process (fourth review pass)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value_type, bufflength", [
    ("bool", 2), ("bool", 4), ("bool", 8),
    ("int", 9), ("int", 16), ("int", 32),
    ("float", 9), ("float", 16),
])
@pytest.mark.parametrize("tool", ["read", "write", "scan"])
def test_a_width_wider_than_the_c_type_is_refused(
    target, value_type, bufflength, tool
):
    """A saturating width was a heap overflow in the *server*, not the target.

    ``get_c_type_of(bool, 8)`` returns a 1-byte ``c_bool``, and the macOS and
    Windows backends then read ``bufflength`` bytes into it — seven bytes past
    the allocation. The scan path had the mirror-image out-of-bounds *read*
    through ``value_to_bytes``' ``c_byte * bufflength`` cast. Reachable
    straight from a tool argument, on a server that actively tells the model to
    guess widths ("try bufflength=8 or 2 for an int").
    """
    address = target.scratch()
    calls = {
        "read": lambda: target.toolset.read_value(
            target.session_id, hex(address), value_type, bufflength),
        "write": lambda: target.toolset.write_value(
            target.session_id, hex(address), value_type, "1", bufflength),
        "scan": lambda: target.toolset.scan_value(
            target.session_id, value_type, "1", bufflength=bufflength),
    }
    assert _outcome(calls[tool]) == "ToolError"


@pytest.mark.parametrize("value_type, bufflength", [
    ("bool", 1), ("int", 1), ("int", 2), ("int", 4), ("int", 8),
    ("float", 4), ("float", 8),
])
def test_valid_widths_still_work(target, value_type, bufflength):
    address = target.scratch()
    target.toolset.write_value(
        target.session_id, hex(address), value_type,
        "true" if value_type == "bool" else "1", bufflength,
    )
    assert target.toolset.read_value(
        target.session_id, hex(address), value_type, bufflength
    )["value"] is not None


@pytest.mark.parametrize("value_type, bufflength", [
    # Widths the library *reads* correctly but that come back None from
    # search_by_addresses (it rounds up to the next C type, whose buffer the
    # address reader then refuses). A scan at these widths would find
    # addresses and report every one as unreadable, so they are refused
    # instead of half-supported.
    ("int", 3), ("int", 5), ("int", 6), ("int", 7),
    # And widths that decode silently wrong: only 4 and 8 mean anything to a
    # float, but sizeof(c_double) >= 5 so a naive size check admitted them.
    ("float", 2), ("float", 3), ("float", 5), ("float", 6), ("float", 7),
])
def test_half_working_numeric_widths_are_refused(target, value_type, bufflength):
    address = target.scratch()
    assert _outcome(
        lambda: target.toolset.read_value(
            target.session_id, hex(address), value_type, bufflength
        )
    ) == "ToolError"


@pytest.mark.parametrize("value_type", ["str", "bytes"])
def test_a_text_width_large_enough_to_kill_the_server_is_refused(
    target, value_type
):
    """str/bytes go to create_string_buffer, which allocates exactly.

    So an unbounded width was not a wrong answer but an OOM kill of the
    server process, taking every open session with it and returning no error
    at all. Verified at 256 MiB before the cap: RSS went 25 MiB -> 281 MiB.
    """
    address = target.scratch()
    for bufflength in (2**28, 2**32, 2**40):
        assert _outcome(
            lambda: target.toolset.read_value(
                target.session_id, hex(address), value_type, bufflength
            )
        ) == "ToolError", bufflength


@pytest.mark.parametrize("value_type, bufflength", [("str", 64), ("bytes", 64)])
def test_text_widths_are_not_capped(target, value_type, bufflength):
    """Only numeric types saturate; a string buffer is sized exactly."""
    address = target.scratch(size=bufflength)
    assert target.toolset.read_value(
        target.session_id, hex(address), value_type, bufflength
    )["value"] is not None


@pytest.mark.parametrize("value_type, first, second", [
    ("int", "1234", "99"),
    ("float", "2.5", "9.5"),
    ("bool", "true", "false"),
    ("str", "hello", "ab"),
    ("bytes", "DEADBEEF", "0102"),
])
def test_a_write_without_an_explicit_bufflength_works_and_undoes(
    target, value_type, first, second
):
    """The most ordinary call shape there is: no bufflength at all.

    The schema defaults `bufflength` to 0, and `_write_span` used to leave the
    numeric span unresolved — which the undo hint then interpolated with %d,
    so `write_value(.., "int", "5")` died on `"%d" % None`. No test passed a
    numeric write without a width, so nothing caught it.
    """
    address = target.scratch()
    target.fill(address, 16, 0xAA)
    target.toolset.write_value(target.session_id, hex(address), value_type, first)
    before = target.raw(address, 16)

    written = target.toolset.write_value(
        target.session_id, hex(address), value_type, second
    )
    assert written["previous_value_bufflength"] >= 1

    target.toolset.write_value(
        target.session_id, hex(address),
        written["previous_value_type"], str(written["previous_value"]),
        written["previous_value_bufflength"],
    )
    assert target.raw(address, 16) == before


@pytest.mark.parametrize("value, cap, expected", [
    ("\u00f3l\u00e1", 2, "\u00f3l"),      # a str cap counts characters...
    ("\u00f3l\u00e1", 1, "\u00f3"),
    ("\u00f3\u00f3\u00f3\u00f3", 3, "\u00f3\u00f3\u00f3"),
    ("\u65e5\u672c\u8a9e", 2, "\u65e5\u672c"),  # ...including three-byte ones
    ("ok", 0, "ok"),
])
def test_a_capped_multibyte_write_reports_and_undoes_exactly(
    target, value, cap, expected
):
    """`written` must equal what is in memory, and the undo must be byte-exact.

    A str bufflength caps *characters* while the replaced span is counted in
    *bytes*, so these two numbers legitimately differ for non-ASCII text —
    which is exactly where a report or an undo goes subtly wrong.
    """
    address = target.scratch()
    target.fill(address, 32, 0xAA)
    before = target.raw(address, 32)

    written = target.toolset.write_value(
        target.session_id, hex(address), "str", value, cap
    )
    span = written["previous_value_bufflength"]

    assert written["written"] == expected
    assert target.raw(address, span) == expected.encode("utf-8")

    target.toolset.write_value(
        target.session_id, hex(address),
        written["previous_value_type"], written["previous_value"], span,
    )
    assert target.raw(address, 32) == before


@pytest.mark.parametrize("value, cap, expected", [
    ("DEADBEEF", 3, b"\xde\xad\xbe"),
    ("DE", 8, b"\xde"),
    ("DEADBEEF", 0, b"\xde\xad\xbe\xef"),
])
def test_a_capped_bytes_write_reports_what_landed(target, value, cap, expected):
    address = target.scratch()
    target.fill(address, 32, 0xAA)

    written = target.toolset.write_value(
        target.session_id, hex(address), "bytes", value, cap
    )
    assert written["written"] == expected.hex().upper()
    assert target.raw(address, len(expected)) == expected


def test_the_undo_hint_alone_is_enough_to_restore_a_narrow_write(target):
    """Following the hint verbatim must restore the bytes, with no extra help.

    It omitted ``bufflength``, so replaying a 4-byte float write defaulted to
    an 8-byte double: zeros in the replaced span and four clobbered bytes past
    it. The docstring calls this the only way back.
    """
    address = target.scratch()
    target.fill(address, 16, 0xAA)
    target.toolset.write_value(
        target.session_id, hex(address), "float", "2.5", 4
    )
    before = target.raw(address, 16)

    written = target.toolset.write_value(
        target.session_id, hex(address), "float", "9.5", 4
    )
    target.toolset.write_value(
        target.session_id, hex(address),
        written["previous_value_type"], str(written["previous_value"]),
        written["previous_value_bufflength"],
    )
    assert target.raw(address, 16) == before


@pytest.mark.parametrize("value_type, value, bufflength, expected, requested", [
    ("bytes", "DEADBEEF", 2, "DEAD", "DEADBEEF"),
    ("str", "hello", 3, "hel", "hello"),
    ("str", "ola", 10, "ola", "ola"),
    ("int", "1000", 4, 1000, 1000),
])
def test_written_reports_what_landed(
    target, value_type, value, bufflength, expected, requested
):
    """A str/bytes bufflength is a cap, so the request is not the outcome."""
    address = target.scratch()
    result = target.toolset.write_value(
        target.session_id, hex(address), value_type, value, bufflength
    )
    assert result["written"] == expected
    # `requested` echoes the parsed value, so it is normalized the same way
    # `written` is. As an inline if/else this used to parse as
    # `assert (a == b) if c else True`, making the int row assert nothing.
    assert result["requested"] == requested
