# -*- coding: utf-8 -*-

"""
Argument parsing for the MCP tools.

Every value an MCP client sends arrives as JSON, and a model composes it from
whatever it read a moment ago — a debugger's hex, a previous tool result, its
own arithmetic. These tests pin the cases where a forgiving parser would be
worse than a strict one: an address that silently comes out 4096 bytes off is a
write into unrelated state.
"""

import pytest

from PyMemoryEditor.mcp.toolset import (
    ToolError,
    format_address,
    format_value,
    parse_address,
    parse_bufflength,
    parse_scan_type,
    parse_value,
    parse_value_type,
)


class TestParseAddress:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("0x1000", 0x1000),
            ("0X1000", 0x1000),
            ("0x7FFD1234", 0x7FFD1234),
            ("4096", 4096),
            ("0x0", 0),
            ("0", 0),
            (4096, 4096),
            ("0x1_000", 0x1000),
            ("  0x1000  ", 0x1000),
        ],
    )
    def test_accepted_forms(self, raw, expected):
        assert parse_address(raw) == expected

    # The floor was checked and the ceiling was not, and only one of the two
    # fails loudly. Past 64 bits every address becomes a `c_void_p`, which
    # truncates to its low bits *silently*: the concatenated string below was
    # accepted and would have been written to 0x56787FFD12345678 -- not the
    # address the model meant, not even the prefix it typed, and possibly
    # mapped. This is the module whose docstring says a write to a rounded
    # address is exactly the failure it must not have.

    @pytest.mark.parametrize("raw", [
        # A hex string the model was handed, then duplicated or concatenated.
        "0x7FFD123456787FFD12345678",
        hex((1 << 64)),
        hex((1 << 64) + 1),
        (1 << 64),
        (1 << 128),
    ])
    def test_an_address_wider_than_64_bits_is_refused(self, raw):
        from PyMemoryEditor.mcp.toolset import ToolError, parse_address

        with pytest.raises(ToolError) as error:
            parse_address(raw)

        # Must not read as a formatting complaint: the model's repair for that
        # is to mangle the string, which is how it got here.
        assert "64-bit" in str(error.value)

    def test_the_widest_real_address_is_still_accepted(self):
        """The boundary itself, so the check cannot be off by one."""
        from PyMemoryEditor.mcp.toolset import MAX_ADDRESS, parse_address

        assert MAX_ADDRESS == (1 << 64) - 1
        assert parse_address(hex(MAX_ADDRESS)) == MAX_ADDRESS

    def test_bare_hex_is_accepted_when_it_cannot_be_decimal(self):
        # "DEADBEEF" has no decimal reading, so there is nothing to guess at.
        assert parse_address("DEADBEEF") == 0xDEADBEEF

    def test_ambiguous_bare_digits_are_read_as_decimal(self):
        # The dangerous case: "1000" is legal hex *and* legal decimal. Choosing
        # hex would move every such address by a factor of ~4. Decimal matches
        # int() and is the documented rule.
        assert parse_address("1000") == 1000

    @pytest.mark.parametrize("raw", ["", "   ", "0x", "nonsense", "12zz", None])
    def test_unparseable_raises_tool_error(self, raw):
        with pytest.raises(ToolError):
            parse_address(raw)

    @pytest.mark.parametrize("raw", ["-1", "-0x10", -5])
    def test_negative_addresses_rejected(self, raw):
        with pytest.raises(ToolError, match="negative"):
            parse_address(raw)

    def test_bool_is_not_an_address(self):
        # bool is an int subclass, so a naive isinstance check would read
        # True as address 1.
        with pytest.raises(ToolError, match="boolean"):
            parse_address(True)

    def test_error_names_the_field(self):
        with pytest.raises(ToolError, match="target_address"):
            parse_address("???", field="target_address")

    def test_round_trips_through_format(self):
        for address in (0, 0x1000, 0x7FFFFFFFFFFF, 2**63):
            assert parse_address(format_address(address)) == address

    def test_survives_addresses_above_the_double_precision_limit(self):
        # The reason addresses are strings: 2**53 + 1 is not representable as a
        # JSON number in a JS client, and a rounded address is a wrong address.
        address = 2**53 + 1
        assert parse_address(format_address(address)) == address


class TestParseOffset:
    """Signed by design, bounded all the same.

    A negative offset is ordinary — a published recipe walks backwards through
    a struct with ``[-0x8]`` — so the sign is deliberate. The magnitude was
    unbounded, and an offset is added to an address: a big enough one pushes an
    intermediate dereference past the 64-bit truncation boundary, where the hop
    reads from somewhere else and the whole chain resolves to a plausible lie.
    """

    @pytest.mark.parametrize("raw, expected", [
        ("-0x8", -8),          # the case the signed domain exists for
        ("0x108", 0x108),
        ("0", 0),
        (-16, -16),
    ])
    def test_ordinary_offsets_are_accepted(self, raw, expected):
        from PyMemoryEditor.mcp.toolset import parse_offset

        assert parse_offset(raw) == expected

    @pytest.mark.parametrize("raw", [
        hex((1 << 32) + 1),
        "-" + hex((1 << 32) + 1),
        1 << 40,
        -(1 << 64),
    ])
    def test_an_offset_too_large_to_be_a_displacement_is_refused(self, raw):
        from PyMemoryEditor.mcp.toolset import ToolError, parse_offset

        with pytest.raises(ToolError) as error:
            parse_offset(raw)

        assert "displacement" in str(error.value)

    def test_the_boundary_is_inclusive_on_both_signs(self):
        from PyMemoryEditor.mcp.toolset import MAX_OFFSET_MAGNITUDE, parse_offset

        assert parse_offset(hex(MAX_OFFSET_MAGNITUDE)) == MAX_OFFSET_MAGNITUDE
        assert parse_offset(-MAX_OFFSET_MAGNITUDE) == -MAX_OFFSET_MAGNITUDE


class TestNumericArgumentsReachTheModelAsToolError:
    """Only ``ToolError`` text reaches the model.

    Everything else becomes an ``UnexpectedToolError`` whose message the SDK
    withholds — so a bare ``int(raw)`` on a model-supplied argument was a hole
    in the contract this module is built around. ``max_depth="deep"`` raised
    ``ValueError: invalid literal for int() with base 10: 'deep'`` and the
    model was told nothing, for an argument it could have fixed itself.
    """

    @pytest.mark.parametrize("raw", ["deep", "muito", "", "0x", "1.5", [], {}])
    def test_a_non_numeric_argument_is_a_tool_error(self, raw):
        from PyMemoryEditor.mcp.toolset import ToolError, parse_int_arg

        with pytest.raises(ToolError):
            parse_int_arg(raw, "max_depth")

    def test_a_boolean_is_refused_like_every_other_parser_refuses_it(self):
        # bool is an int subclass, so True would silently mean 1.
        from PyMemoryEditor.mcp.toolset import ToolError, parse_int_arg

        for value in (True, False):
            with pytest.raises(ToolError) as error:
                parse_int_arg(value, "limit")
            assert "boolean" in str(error.value)

    @pytest.mark.parametrize("raw, expected", [
        (7, 7), ("7", 7), ("0x10", 16), ("  12  ", 12), ("1_000", 1000), (-3, -3),
    ])
    def test_numeric_forms_still_parse(self, raw, expected):
        from PyMemoryEditor.mcp.toolset import parse_int_arg

        assert parse_int_arg(raw, "limit") == expected

    def test_none_takes_the_default_when_there_is_one(self):
        from PyMemoryEditor.mcp.toolset import ToolError, parse_int_arg

        assert parse_int_arg(None, "max_depth", default=3) == 3
        with pytest.raises(ToolError):
            parse_int_arg(None, "limit")

    @pytest.mark.parametrize("value", [True, False])
    def test_a_boolean_bufflength_is_refused(self, value):
        """`bufflength=true` used to mean a width of 1.

        Both values are asserted, and `False` is the one that matters: it is
        falsy, so without an explicit check it slips past `if raw` and comes
        back as the "use the default width" sentinel instead of an error. A
        mutation removing the check passed while only `True` was tested,
        because `parse_int_arg` happens to refuse that one too.
        """
        from PyMemoryEditor.mcp.toolset import ToolError, parse_bufflength

        with pytest.raises(ToolError) as error:
            parse_bufflength(value, int, required=False)

        assert "boolean" in str(error.value)


class TestParseValue:
    @pytest.mark.parametrize(
        "raw, expected",
        [("100", 100), ("0x64", 100), ("-7", -7), ("-0x7", -7), (100, 100), ("1_000", 1000)],
    )
    def test_int_forms(self, raw, expected):
        assert parse_value(int, raw) == expected

    def test_float(self):
        assert parse_value(float, "1.5") == 1.5
        assert parse_value(float, "-0.25") == -0.25

    @pytest.mark.parametrize("raw, expected", [
        ("true", True), ("True", True), ("1", True), ("yes", True),
        ("false", False), ("0", False), ("no", False), (True, True),
    ])
    def test_bool_forms(self, raw, expected):
        assert parse_value(bool, raw) is expected

    def test_bool_rejects_junk(self):
        with pytest.raises(ToolError, match="bool"):
            parse_value(bool, "maybe")

    def test_str_passes_through(self):
        assert parse_value(str, "Player1") == "Player1"

    @pytest.mark.parametrize("raw", ["DEADBEEF", "de ad be ef", "0xDEADBEEF", "DE_AD_BE_EF"])
    def test_bytes_from_hex(self, raw):
        assert parse_value(bytes, raw) == b"\xde\xad\xbe\xef"

    @pytest.mark.parametrize("raw", ["ABC", "zz", ""])
    def test_bad_hex_rejected(self, raw):
        with pytest.raises(ToolError, match="hex"):
            parse_value(bytes, raw)

    def test_int_rejects_junk_with_actionable_message(self):
        with pytest.raises(ToolError, match="0x"):
            parse_value(int, "one hundred")

    def test_none_is_rejected(self):
        with pytest.raises(ToolError, match="required"):
            parse_value(int, None)


class TestFormatValue:
    def test_bytes_render_as_uppercase_hex(self):
        assert format_value(b"\xde\xad") == "DEAD"

    def test_other_values_pass_through(self):
        assert format_value(100) == 100
        assert format_value(1.5) == 1.5
        assert format_value("hi") == "hi"
        assert format_value(None) is None


class TestTypesAndScanTypes:
    @pytest.mark.parametrize("name", ["int", "float", "bool", "str", "bytes", "INT", " Int "])
    def test_known_value_types(self, name):
        assert parse_value_type(name) in (int, float, bool, str, bytes)

    def test_unknown_value_type_lists_the_valid_ones(self):
        with pytest.raises(ToolError, match="bytes"):
            parse_value_type("uint64")

    def test_known_scan_types(self):
        name, enum = parse_scan_type("bigger")
        assert name == "bigger" and enum.name == "BIGGER_THAN"

    def test_unknown_scan_type_lists_the_valid_ones(self):
        with pytest.raises(ToolError, match="exact"):
            parse_scan_type("greater_than")


class TestParseBufflength:
    def test_zero_means_default_for_numbers(self):
        assert parse_bufflength(0, int, required=True) is None

    def test_zero_is_rejected_for_text_on_a_read(self):
        # A str/bytes read has only an address; nothing says how far to go.
        with pytest.raises(ToolError, match="bufflength is required"):
            parse_bufflength(0, str, required=True)

    def test_zero_is_allowed_for_text_on_a_scan(self):
        # A scan has the value itself to measure.
        assert parse_bufflength(0, str, required=False) is None

    def test_explicit_width_passes_through(self):
        assert parse_bufflength(8, int, required=True) == 8

    def test_negative_width_rejected(self):
        with pytest.raises(ToolError, match="positive"):
            parse_bufflength(-4, int, required=True)


class TestAdvertisedLimitsMatchEnforcement:
    """What the server says about itself must be what it does.

    Both halves have drifted before: the flag table in ``docs/mcp.md`` missed
    ``--scan-batch-bytes`` entirely, and ``server_info`` advertised a
    ``max_page_size`` of 100 while ``list_processes`` clamped at 200 — so
    anything past the first page was unreachable with no way to find out.
    These are the checks that would have caught both.
    """

    def test_the_documented_flags_are_exactly_the_real_flags(self):
        import re
        from pathlib import Path

        from PyMemoryEditor.mcp import build_parser

        real = {
            option
            for action in build_parser()._actions
            for option in action.option_strings
            if option.startswith("--") and option != "--help"
        }
        guide = Path(__file__).resolve().parents[2] / "docs" / "mcp.md"
        # encoding is not optional: read_text() defaults to the locale's
        # encoding, which is cp1252 on Windows, and docs/mcp.md has 14 distinct
        # non-ASCII bytes (em dashes, arrows). This test was the only Windows
        # failure in the whole CI run.
        documented = set(
            re.findall(r"<code>(--[a-z-]+)", guide.read_text(encoding="utf-8"))
        )

        assert real - documented == set(), "undocumented flags"
        assert documented - real == set(), "documented flags that do not exist"

    def test_advertised_limits_are_the_configured_ones(self):
        from PyMemoryEditor.mcp import MemoryToolset, ServerConfig
        from PyMemoryEditor.mcp.toolset import (
            MAX_PAGE_SIZE,
            MAX_TEXT_BYTES,
        )

        config = ServerConfig(
            max_scan_results=123, max_scan_seconds=4.5, scan_batch_bytes=8192
        )
        limits = MemoryToolset(config).server_info()["limits"]

        assert limits["max_scan_results"] == 123
        assert limits["max_scan_seconds"] == 4.5
        assert limits["scan_batch_bytes"] == 8192
        assert limits["max_page_size"] == MAX_PAGE_SIZE
        assert limits["max_text_bytes"] == MAX_TEXT_BYTES

    def test_advertised_widths_are_exactly_the_accepted_widths(self):
        # Advertising a width the validator refuses (or refusing one it
        # advertises) is worse than not advertising at all: this is the
        # argument the server's own hints tell the model to guess.
        from PyMemoryEditor.mcp import MemoryToolset, ServerConfig
        from PyMemoryEditor.mcp.toolset import ToolError, parse_bufflength

        advertised = MemoryToolset(ServerConfig()).server_info()["limits"][
            "valid_numeric_widths"
        ]
        types = {"int": int, "float": float, "bool": bool}

        for name, widths in advertised.items():
            for width in range(1, 12):
                try:
                    parse_bufflength(width, types[name], required=True)
                    accepted = True
                except ToolError:
                    accepted = False
                assert accepted is (width in widths), (name, width)

    def test_the_page_size_cap_is_the_advertised_one(self, toolset):
        # list_processes clamped at 200 while server_info said 100.
        advertised = toolset.server_info()["limits"]["max_page_size"]
        assert toolset.list_processes(limit=10**6)["returned"] <= advertised


class TestGetCTypeOfContract:
    """`get_c_type_of` is the choke point every buffer is sized through.

    Its three refusals interact, and getting the order wrong is how a width
    complaint came back for an unsupported type, and how a `pytype` without
    `__name__` raised AttributeError -- which neither the MCP toolset nor any
    of the three backends catch, since they all guard `ValueError`.
    """

    def test_an_unsupported_type_is_rejected_by_type_not_by_width(self):
        class NotAType:
            pass

        from PyMemoryEditor.util import get_c_type_of

        for width in (0, 1, 4, 99):
            with pytest.raises(ValueError, match="must be bool, int, float"):
                get_c_type_of(NotAType, width)

    def test_a_pytype_without_a_name_still_raises_value_error(self):
        # Formatting the width message with `pytype.__name__` blew up here.
        from PyMemoryEditor.util import get_c_type_of

        with pytest.raises(ValueError):
            get_c_type_of("notatype", 0)

    @pytest.mark.parametrize("pytype", [int, float, bool])
    def test_zero_is_refused_for_numeric_types(self, pytype):
        from PyMemoryEditor.util import get_c_type_of

        with pytest.raises(ValueError, match="at least 1 byte"):
            get_c_type_of(pytype, 0)

    @pytest.mark.parametrize("pytype", [str, bytes])
    def test_zero_stays_legal_for_text(self, pytype):
        # An empty write is a documented no-op on the public API.
        import ctypes

        from PyMemoryEditor.util import get_c_type_of

        assert ctypes.sizeof(get_c_type_of(pytype, 0)) == 0

    def test_a_negative_width_is_refused_for_every_type(self):
        from PyMemoryEditor.util import get_c_type_of

        for pytype in (int, float, bool, str, bytes):
            with pytest.raises(ValueError, match="negative"):
                get_c_type_of(pytype, -1)

    def test_a_width_narrower_than_the_c_type_is_allowed(self):
        # Documented and safe: an int of 3 bytes reads 3 into a 4-byte buffer.
        import ctypes

        from PyMemoryEditor.util import get_c_type_of

        assert ctypes.sizeof(get_c_type_of(int, 3)) == 4

    def test_a_width_wider_than_the_c_type_is_refused(self):
        from PyMemoryEditor.util import get_c_type_of

        for pytype, width in ((bool, 2), (int, 9), (float, 9)):
            with pytest.raises(ValueError, match="too wide"):
                get_c_type_of(pytype, width)


class TestCoverageConfigsAreValidIni:
    """The CI coverage configs are INI, and were written as if they were TOML.

    `source = ["PyMemoryEditor"]` parsed as a directory literally named
    `["PyMemoryEditor"]`. It looked fine only because CI always passes an
    explicit `--cov=PATH`, which overrides `source`; anyone running
    `coverage --rcfile=` or a bare `pytest --cov` measured nothing.
    """

    @pytest.mark.parametrize("config_file, expected", [
        (".coveragerc-lib", "PyMemoryEditor"),
        (".coveragerc-mcp", "PyMemoryEditor/mcp"),
    ])
    def test_source_parses_to_a_real_path(self, config_file, expected):
        from pathlib import Path

        from coverage import Coverage

        root = Path(__file__).resolve().parents[2]
        config = Coverage(config_file=str(root / config_file)).config
        assert config.source == [expected]
        assert (root / expected).is_dir()

    def test_the_library_config_omits_the_mcp_package(self):
        from pathlib import Path

        from coverage import Coverage

        root = Path(__file__).resolve().parents[2]
        omit = Coverage(config_file=str(root / ".coveragerc-lib")).config.run_omit
        assert any("mcp" in pattern for pattern in omit), omit


class TestServerConfigValidatesItsBounds:
    """The three numeric bounds were checked at the CLI only.

    An embedder building a `ServerConfig` in Python got no error and a server
    that misbehaved quietly: `scan_batch_bytes=0` makes every region its own
    scan batch, `max_scan_results=0` makes every scan return nothing while
    reporting itself partial. The dataclass now mirrors `parse_args`.
    """

    @pytest.mark.parametrize("field, value", [
        ("max_scan_results", 0),
        ("max_scan_results", -1),
        ("max_scan_seconds", 0),
        ("max_scan_seconds", 0.0),
        ("max_scan_seconds", -0.5),
        ("scan_batch_bytes", 0),
        ("scan_batch_bytes", -4096),
    ])
    def test_a_non_positive_bound_is_rejected(self, field, value):
        from PyMemoryEditor.mcp import ServerConfig

        with pytest.raises(ValueError) as error:
            ServerConfig(**{field: value})

        # The message has to name the offending field -- an embedder passing
        # several bounds at once cannot act on "invalid configuration".
        assert field in str(error.value)

    def test_the_defaults_are_valid(self):
        """A guard against a default drifting below its own floor."""
        from PyMemoryEditor.mcp import ServerConfig

        config = ServerConfig()
        assert config.max_scan_results >= 1
        assert config.max_scan_seconds > 0
        assert config.scan_batch_bytes >= 1

    def test_the_smallest_accepted_values_are_accepted(self):
        from PyMemoryEditor.mcp import ServerConfig

        config = ServerConfig(
            max_scan_results=1, max_scan_seconds=1e-9, scan_batch_bytes=1
        )
        assert config.max_scan_results == 1

    def test_the_cli_still_reports_its_own_message(self):
        """`parse_args` must fail as a CLI, not with a raw traceback.

        Its checks run before the dataclass is constructed, so the operator
        keeps getting `--max-scan-results must be at least 1.` and exit code 2
        rather than a ValueError escaping through argparse.
        """
        from PyMemoryEditor.mcp.config import parse_args

        with pytest.raises(SystemExit) as exit_info:
            parse_args(["--max-scan-results", "0"])

        assert exit_info.value.code == 2
