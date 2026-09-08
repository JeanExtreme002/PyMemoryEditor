# -*- coding: utf-8 -*-

"""Property test over every tool argument: no crash, no stripped error.

The two most serious bugs found in this package were both argument validation
on the same parameter. ``bufflength`` wider than a type's C representation
sized a buffer smaller than the read and corrupted this process's heap;
``bufflength`` unbounded for ``str``/``bytes`` allocated exactly what it was
asked for and got the server OOM-killed, losing every open session and
returning no error at all. Neither was a subtle logic error — both were a
missing bound on an integer that the server's own hints tell the model to
guess.

Reviewing for those one at a time worked, twice, but it is the wrong
instrument: the space is combinatorial and a human (or an agent) reading code
checks the cases it thinks of. So this states the invariant instead and lets
Hypothesis look for counterexamples.

**The invariant:** for *any* combination of arguments, a tool either returns a
result or raises ``ToolError``. Never a raw exception — the MCP SDK withholds
the message of anything that is not our ``ToolError``, so the model receives a
bare "Error executing tool <name>" and retries the same broken call. And never
a crash of the server process, which would take every session with it.

That is deliberately a weak postcondition: it says nothing about whether the
*answer* is right (``test_fake_fidelity.py`` and ``test_toolset.py`` do that).
It only says the server survives its inputs and always explains itself.

It is also, on its own, **not enough to have caught either HIGH** — mutation
testing showed that removing both width guards leaves every property below
green. Two reasons, and both are worth knowing:

* the end-to-end fuzz runs against the fake target, whose ``_locate``
  bounds-checks an address range *before* anything is allocated; the real
  backends size the buffer first, so the allocation that got the server killed
  simply does not happen here;
* a heap overflow is not an exception. Nothing raises, so "no raw exception"
  cannot see it.

So :class:`TestWidthValidationIsSound` states the invariant where it actually
lives — on the validation function, as a pure property over every type and
width. That one *does* catch both. The end-to-end fuzz keeps its own value
(it found the ``max_offset=None`` crash), but the two are complementary rather
than the same test at different scales.
"""

import ctypes

import pytest

from PyMemoryEditor.mcp.session import SessionError
from PyMemoryEditor.mcp.toolset import ToolError

from .conftest import WRITABLE_BASE, FakeProcess, _toolset_for, config

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402


#: Values large enough to have been dangerous, without being slow to reject.
#: 2**40 is the width that OOM-killed the server; keep it in the pool.
WIDTHS = st.one_of(
    st.integers(min_value=-8, max_value=72),
    st.sampled_from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 32, 64, 4096]),
    st.sampled_from([2**20, 2**28, 2**32, 2**40, 2**62]),
)

VALUE_TYPES = st.sampled_from(["int", "float", "bool", "str", "bytes", "", "uint64"])

SCAN_TYPES = st.sampled_from(
    ["exact", "not_exact", "bigger", "bigger_or_exact", "smaller",
     "smaller_or_exact", "between", "not_between", "", "greater"]
)

#: Text a model plausibly produces for a value: valid, empty, hex, huge,
#: negative, non-numeric, non-ASCII.
VALUES = st.one_of(
    st.sampled_from(["0", "1", "100", "-1", "-0x10", "0x64", "0.1", "-2.5",
                     "true", "false", "DEADBEEF", "hi", "日本語", "",
                     "99999999999999999999999999", "nonsense", "0x", "  "]),
    st.text(max_size=8),
)

#: Addresses, including the forms that must be rejected rather than guessed at.
ADDRESSES = st.one_of(
    st.sampled_from([hex(WRITABLE_BASE), hex(WRITABLE_BASE + 0x10),
                     "0x0", "0", "0xDEAD0000", "-0x10", "nonsense", "",
                     "0x" + "F" * 20, "1000", "DEADBEEF"]),
    st.text(max_size=6),
)

FUZZ = settings(
    max_examples=250,
    deadline=None,  # a scan over the fake's regions is not instantaneous
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


def _survives(call) -> None:
    """Assert the invariant: a result, or a ToolError. Nothing else."""
    try:
        call()
    except (ToolError, SessionError):
        # Both carry a message the SDK forwards to the model.
        pass
    except Exception as error:  # noqa: BLE001 — this is the property
        raise AssertionError(
            "raised %s instead of ToolError, so the model would see only "
            '"Error executing tool <name>": %s' % (type(error).__name__, error)
        ) from None


@pytest.fixture
def fuzz_target():
    """A toolset on the fake target, sized so a scan stays quick."""
    process = FakeProcess()
    toolset = _toolset_for(
        process, config(max_scan_results=200, max_scan_seconds=5)
    )
    session_id = toolset.open_process(pid=4242)["session_id"]
    yield toolset, session_id, process
    toolset.store.close_all()


class TestArgumentsNeverCrash:
    @given(value_type=VALUE_TYPES, bufflength=WIDTHS, address=ADDRESSES)
    @FUZZ
    def test_read_value(self, fuzz_target, value_type, bufflength, address):
        toolset, session_id, _process = fuzz_target
        _survives(
            lambda: toolset.read_value(session_id, address, value_type, bufflength)
        )

    @given(
        value_type=VALUE_TYPES, value=VALUES,
        bufflength=WIDTHS, address=ADDRESSES,
    )
    @FUZZ
    def test_write_value(
        self, fuzz_target, value_type, value, bufflength, address
    ):
        toolset, session_id, _process = fuzz_target
        _survives(
            lambda: toolset.write_value(
                session_id, address, value_type, value, bufflength
            )
        )

    @given(
        value_type=VALUE_TYPES, value=VALUES, scan_type=SCAN_TYPES,
        end_value=VALUES, bufflength=WIDTHS, writable_only=st.booleans(),
    )
    @FUZZ
    def test_scan_value(
        self, fuzz_target, value_type, value, scan_type, end_value,
        bufflength, writable_only,
    ):
        toolset, session_id, _process = fuzz_target
        _survives(
            lambda: toolset.scan_value(
                session_id, value_type, value, scan_type=scan_type,
                end_value=end_value, bufflength=bufflength,
                writable_only=writable_only,
            )
        )

    @given(pattern=st.one_of(
        st.sampled_from(["48 8B ? 00", "?", "??", "", "  ", "zz", "0",
                         "48 8B", "4", "48 8B ?? ?? ??", "GG HH"]),
        st.text(max_size=12),
    ))
    @FUZZ
    def test_scan_pattern(self, fuzz_target, pattern):
        toolset, session_id, _process = fuzz_target
        _survives(lambda: toolset.scan_pattern(session_id, pattern))

    @given(
        base=ADDRESSES,
        offsets=st.lists(
            st.one_of(
                st.sampled_from(["0x0", "0x8", "-0x8", "0", "-1", "nonsense",
                                 "", "0x" + "F" * 20]),
                st.text(max_size=5),
            ),
            max_size=4,
        ),
    )
    @FUZZ
    def test_resolve_pointer_chain(self, fuzz_target, base, offsets):
        toolset, session_id, _process = fuzz_target
        _survives(
            lambda: toolset.resolve_pointer_chain(session_id, base, offsets)
        )

    @given(
        target_address=ADDRESSES,
        max_depth=st.one_of(st.integers(min_value=-2, max_value=12), st.none()),
        max_offset=st.one_of(
            st.integers(min_value=-2, max_value=0x20000), st.none()
        ),
        max_results=st.one_of(st.integers(min_value=-2, max_value=200), st.none()),
    )
    @FUZZ
    def test_find_pointer_paths(
        self, fuzz_target, target_address, max_depth, max_offset, max_results
    ):
        toolset, session_id, _process = fuzz_target
        _survives(
            lambda: toolset.find_pointer_paths(
                session_id, target_address, max_depth=max_depth,
                max_offset=max_offset, max_results=max_results,
            )
        )

    @given(
        limit=st.one_of(st.integers(min_value=-5, max_value=10**7), st.none()),
        offset=st.one_of(st.integers(min_value=-5, max_value=10**7), st.none()),
        name_filter=st.one_of(st.sampled_from(["", "  ", "python", "zzz"]),
                              st.text(max_size=6)),
    )
    @FUZZ
    def test_list_processes(self, fuzz_target, limit, offset, name_filter):
        toolset, _session_id, _process = fuzz_target
        _survives(
            lambda: toolset.list_processes(
                name_filter=name_filter, limit=limit, offset=offset
            )
        )

    @given(
        writable_only=st.booleans(), executable_only=st.booleans(),
        path_filter=st.text(max_size=6),
        limit=st.one_of(st.integers(min_value=-5, max_value=10**6), st.none()),
        offset=st.one_of(st.integers(min_value=-5, max_value=10**6), st.none()),
    )
    @FUZZ
    def test_list_memory_regions(
        self, fuzz_target, writable_only, executable_only, path_filter,
        limit, offset,
    ):
        toolset, session_id, _process = fuzz_target
        _survives(
            lambda: toolset.list_memory_regions(
                session_id, writable_only=writable_only,
                executable_only=executable_only, path_filter=path_filter,
                limit=limit, offset=offset,
            )
        )

    @given(
        pid=st.one_of(st.integers(min_value=-3, max_value=2**31), st.none()),
        name=st.one_of(st.sampled_from(["", "  ", "faketarget", "zzz"]),
                       st.text(max_size=6)),
    )
    @FUZZ
    def test_open_process(self, fuzz_target, pid, name):
        toolset, _session_id, _process = fuzz_target
        _survives(lambda: toolset.open_process(pid=pid or 0, name=name))


class TestRefineArgumentsNeverCrash:
    """Refine needs a live result set, so it gets its own fixture."""

    @given(scan_type=SCAN_TYPES, value=VALUES, end_value=VALUES)
    @FUZZ
    def test_refine_scan(self, fuzz_target, scan_type, value, end_value):
        toolset, session_id, process = fuzz_target
        process.poke(WRITABLE_BASE + 0x10, int, 4242)
        scan = toolset.scan_value(session_id, "int", "4242", bufflength=4)
        _survives(
            lambda: toolset.refine_scan(
                scan["scan_id"], scan_type=scan_type,
                value=value, end_value=end_value,
            )
        )

    @given(
        limit=st.one_of(st.integers(min_value=-5, max_value=10**6), st.none()),
        offset=st.one_of(st.integers(min_value=-5, max_value=10**6), st.none()),
    )
    @FUZZ
    def test_list_scan_results(self, fuzz_target, limit, offset):
        toolset, session_id, process = fuzz_target
        process.poke(WRITABLE_BASE + 0x10, int, 4242)
        scan = toolset.scan_value(session_id, "int", "4242", bufflength=4)
        _survives(
            lambda: toolset.list_scan_results(
                scan["scan_id"], limit=limit, offset=offset
            )
        )


class TestUnknownHandlesNeverCrash:
    @given(handle=st.one_of(
        st.sampled_from(["", "proc-1", "proc-999", "scan-1", "scan-999", "  "]),
        st.text(max_size=8),
    ))
    @FUZZ
    def test_every_handle_taking_tool(self, fuzz_target, handle):
        toolset, _session_id, _process = fuzz_target
        for call in (
            lambda: toolset.process_info(handle),
            lambda: toolset.close_process(handle),
            lambda: toolset.list_memory_regions(handle),
            lambda: toolset.read_value(handle, "0x1000", "int", 4),
            lambda: toolset.list_scan_results(handle),
            lambda: toolset.refine_scan(handle, value="1"),
        ):
            _survives(call)


class TestWidthValidationIsSound:
    """The property both HIGH findings violated, stated where it lives.

    ``parse_bufflength`` is the single argument every tool funnels a size
    through. For any type and any width it must either raise ``ToolError`` or
    return a width that is *provably* safe to hand to a backend — meaning the
    buffer the backend will size from it is at least as large as the read it
    will then perform, and small enough not to exhaust memory.

    Checked as a pure property because that is the only level at which it is
    visible: end-to-end, a heap overflow raises nothing and the fake never
    allocates.
    """

    ALL_TYPES = [int, float, bool, str, bytes]

    @given(
        pytype=st.sampled_from(ALL_TYPES),
        width=WIDTHS,
        required=st.booleans(),
    )
    @settings(max_examples=600, deadline=None)
    def test_an_accepted_width_is_always_safe(self, pytype, width, required):
        from PyMemoryEditor.mcp.toolset import MAX_TEXT_BYTES, parse_bufflength
        from PyMemoryEditor.util import get_c_type_of

        try:
            accepted = parse_bufflength(width, pytype, required=required)
        except ToolError:
            return  # a refusal is always an acceptable answer

        if accepted is None:
            return  # "use the type's default", which the library resolves

        assert accepted >= 1, accepted

        # 1. The buffer the backend sizes from this must not be smaller than
        #    the read it then performs. This is the heap overflow, exactly.
        buffer = get_c_type_of(pytype, accepted)
        assert ctypes.sizeof(buffer) >= accepted, (
            "accepted width %d for %s sizes a %d-byte buffer"
            % (accepted, pytype.__name__, ctypes.sizeof(buffer))
        )

        # 2. And it must be small enough that sizing it cannot exhaust memory.
        #    str/bytes allocate exactly what they are asked for.
        assert accepted <= MAX_TEXT_BYTES, accepted

    @given(pytype=st.sampled_from([int, float, bool]), width=WIDTHS)
    @settings(max_examples=400, deadline=None)
    def test_an_accepted_numeric_width_round_trips_through_every_path(
        self, pytype, width
    ):
        """A numeric width that is accepted must work on all paths, not some.

        ``int`` at 3 bytes read fine but came back ``None`` from
        ``search_by_addresses``, so a scan found addresses and reported every
        one as unreadable. Accepting a width that only half-works is worse than
        refusing it.
        """
        from PyMemoryEditor.mcp.toolset import parse_bufflength
        from PyMemoryEditor.util import get_c_type_of

        try:
            accepted = parse_bufflength(width, pytype, required=True)
        except ToolError:
            return
        if accepted is None:
            return

        # search_by_addresses decodes via convert_from_byte_array, which builds
        # the C type from the width and fills it from a buffer of exactly that
        # many bytes — so the two sizes have to match, not merely fit.
        assert ctypes.sizeof(get_c_type_of(pytype, accepted)) == accepted, (
            "%s at width %d rounds up, so search_by_addresses returns None "
            "for it while read_process_memory succeeds"
            % (pytype.__name__, accepted)
        )

    @given(
        pytype=st.sampled_from([str, bytes]),
        length=st.one_of(
            st.integers(min_value=0, max_value=200),
            st.sampled_from([0x10000, 0x10001, 0x20000, 300_000, 2**20]),
        ),
    )
    @settings(max_examples=300, deadline=None)
    def test_an_inferred_text_width_is_bounded_too(self, pytype, length):
        """The branch the first version of this property could not see.

        ``parse_bufflength`` caps an *explicit* width, but leaving it at 0 —
        which the tools' docstrings recommend — infers the width from the
        value instead. That path went to ``create_string_buffer`` with
        whatever length arrived, so the cap was decorative for the call shape
        the server actually recommends. Mutation testing caught this: removing
        the inferred cap left the earlier property green.
        """
        from PyMemoryEditor.mcp.toolset import MAX_TEXT_BYTES, MemoryToolset

        toolset = MemoryToolset(config())
        value = ("x" * length) if pytype is str else (b"\x41" * length)

        try:
            resolved = toolset._resolved_width(pytype, None, value)
        except ToolError:
            return  # a refusal is always acceptable
        assert resolved <= MAX_TEXT_BYTES, (
            "inferred a %d-byte width for %s, past the %d-byte cap"
            % (resolved, pytype.__name__, MAX_TEXT_BYTES)
        )
