# -*- coding: utf-8 -*-

"""
The MCP protocol layer: what a client actually sees.

These tests run against the real ``mcp`` SDK rather than a mock of it, because
the things worth checking here are precisely the things a mock would let us get
wrong: that the SDK derives the schema we expect from our signatures, that a
``ToolError`` reaches the client as a tool error rather than a crash, and that
the write tool is genuinely absent — not merely refusing — in read-only mode.

They are skipped when the SDK is not installed; ``tests/mcp/test_toolset.py``
covers the same tools without it.
"""

import asyncio
import json
from contextlib import asynccontextmanager

import pytest

from PyMemoryEditor.mcp import ServerConfig, build_server
from PyMemoryEditor.mcp.server import INSTRUCTIONS

from .conftest import WRITABLE_BASE, FakeProcess, _toolset_for, config

mcp = pytest.importorskip("mcp", reason="the MCP server needs the 'mcp' SDK")

import anyio  # noqa: E402 — only importable once the SDK is present
from mcp import ClientSession  # noqa: E402
from mcp.shared.memory import create_client_server_memory_streams  # noqa: E402
from mcp.types import ElicitResult  # noqa: E402


@asynccontextmanager
async def connected(server, elicitation_callback=None):
    """Run ``server`` against an in-memory client session.

    The approval flow can only be tested from the client side: it is the client
    that answers an elicitation, and a bare ``call_tool`` has no session to ask
    through. This wires both halves over memory streams, so the whole path —
    tool call, elicitation request, answer, attach — runs for real without a
    subprocess or a transport.

    Reaches into ``_lowlevel_server`` because the SDK's high-level wrapper only
    exposes ``run_stdio_async`` / the HTTP apps, none of which take streams.
    """
    async with create_client_server_memory_streams() as (
        (client_read, client_write),
        (server_read, server_write),
    ):
        low = server._lowlevel_server

        async with anyio.create_task_group() as task_group:

            async def serve() -> None:
                await low.run(
                    server_read, server_write, low.create_initialization_options()
                )

            task_group.start_soon(serve)
            async with ClientSession(
                client_read, client_write, elicitation_callback=elicitation_callback
            ) as session:
                await session.initialize()
                yield session
            task_group.cancel_scope.cancel()


class Answerer:
    """A scripted user, standing in for the elicitation dialog."""

    def __init__(self, action="accept", remember=False):
        self.action = action
        self.remember = remember
        self.prompts = []

    async def __call__(self, context, params):
        self.prompts.append(params.message)
        return ElicitResult(
            action=self.action,
            content={"remember": self.remember} if self.action == "accept" else None,
        )

    @property
    def asked(self) -> bool:
        return bool(self.prompts)


def _run(coroutine):
    """Drive one coroutine to completion.

    The SDK's server API is async; using ``asyncio.run`` per test keeps this
    file free of an ``asyncio`` plugin dependency for the handful of
    round-trips we need.
    """
    return asyncio.run(coroutine)


@pytest.fixture
def built(fake_process: FakeProcess):
    """A server + toolset pair wired to the fake target, with writes enabled."""

    def factory(config: ServerConfig):
        toolset = _toolset_for(fake_process, config)
        server, _toolset = build_server(config, toolset=toolset)
        return server, toolset

    return factory


def _tool_names(server) -> list:
    return [tool.name for tool in _run(server.list_tools())]


def _call(server, name, **arguments):
    result = _run(server.call_tool(name, arguments))
    return result


def _payload(result) -> dict:
    """Decode the JSON a tool returned through the protocol."""
    return json.loads(result.content[0].text)


class TestRegistration:
    def test_every_read_tool_is_registered(self, built):
        server, _toolset = built(config())
        expected = {
            "server_info",
            "list_processes",
            "open_process",
            "close_process",
            "process_info",
            "list_memory_regions",
            "scan_value",
            "scan_pattern",
            "refine_scan",
            "list_scan_results",
            "read_value",
            "resolve_pointer_chain",
            "find_pointer_paths",
        }
        assert expected.issubset(set(_tool_names(server)))

    def test_write_tool_is_absent_in_read_only_mode(self, built):
        # Not "registered but refusing": a tool the model cannot see is a tool
        # it cannot be talked into calling.
        server, _toolset = built(config(allow_write=False))
        assert "write_value" not in _tool_names(server)

    def test_write_tool_appears_with_the_flag(self, built):
        server, _toolset = built(config(allow_write=True))
        assert "write_value" in _tool_names(server)

    def test_no_tool_is_registered_twice(self, built):
        server, _toolset = built(config(allow_write=True))
        names = _tool_names(server)
        assert len(names) == len(set(names))

    def test_server_carries_the_instructions(self, built):
        server, _toolset = built(config())
        assert server.instructions == INSTRUCTIONS

    def test_instructions_teach_the_refine_loop(self, built):
        # This text is the only guidance the model gets before choosing a tool;
        # if it stops describing the loop, the server stops being usable.
        assert "refine_scan" in INSTRUCTIONS
        assert "server_info" in INSTRUCTIONS


class TestAnnotations:
    def _annotations(self, server, name):
        return {tool.name: tool.annotations for tool in _run(server.list_tools())}[name]

    def test_read_tools_are_marked_read_only(self, built):
        server, _toolset = built(config())
        annotations = self._annotations(server, "read_value")
        assert annotations.read_only_hint is True
        assert annotations.destructive_hint is False

    def test_write_tool_is_marked_destructive(self, built):
        # The hint is what makes a client prompt before the model changes a
        # running process's memory.
        server, _toolset = built(config(allow_write=True))
        annotations = self._annotations(server, "write_value")
        assert annotations.read_only_hint is False
        assert annotations.destructive_hint is True

    def test_handle_minting_tools_are_not_idempotent(self, built):
        server, _toolset = built(config())
        assert self._annotations(server, "scan_value").idempotent_hint is False
        assert self._annotations(server, "open_process").idempotent_hint is False

    def test_pure_lookups_are_idempotent(self, built):
        server, _toolset = built(config())
        assert self._annotations(server, "list_processes").idempotent_hint is True


class TestSchemas:
    def _schema(self, server, name):
        return {tool.name: tool.input_schema for tool in _run(server.list_tools())}[name]

    def test_addresses_are_typed_as_strings(self, built):
        # The whole reason: a 64-bit address does not survive a JSON number in
        # a client that parses with IEEE doubles.
        server, _toolset = built(config(allow_write=True))
        for name, field in (
            ("read_value", "address"),
            ("write_value", "address"),
            ("resolve_pointer_chain", "base_address"),
            ("find_pointer_paths", "target_address"),
        ):
            assert self._schema(server, name)["properties"][field]["type"] == "string"

    def test_required_arguments_have_no_defaults(self, built):
        server, _toolset = built(config())
        required = self._schema(server, "scan_value")["required"]
        assert set(required) == {"session_id", "value_type", "value"}

    def test_optional_arguments_carry_their_defaults(self, built):
        server, _toolset = built(config())
        properties = self._schema(server, "scan_value")["properties"]
        assert properties["writable_only"]["default"] is True
        assert properties["bufflength"]["default"] == 0

    def test_error_wrapping_preserves_the_derived_schema(self, built):
        # Tools are registered through a wrapper that translates our errors
        # into the SDK's. If that wrapper ever stopped carrying the signature
        # through, every tool would silently degrade to (*args, **kwargs).
        server, _toolset = built(config())
        schema = self._schema(server, "list_scan_results")
        assert set(schema["required"]) == {"scan_id"}
        assert schema["properties"]["limit"]["type"] == "integer"
        assert "kwargs" not in schema["properties"]

    def test_descriptions_come_from_the_docstrings(self, built):
        # The docstrings in toolset.py are the prompt the model reads; an empty
        # description means the tool is effectively undocumented to it.
        server, _toolset = built(config())
        for tool in _run(server.list_tools()):
            assert tool.description and len(tool.description) > 40, tool.name


class TestCallsThroughTheProtocol:
    def test_a_tool_result_is_json(self, built):
        server, _toolset = built(config())
        payload = _payload(_call(server, "server_info"))
        assert payload["write_enabled"] is True

    def test_the_full_loop_works_over_the_protocol(self, built, fake_process):
        server, _toolset = built(config(allow_write=True))

        opened = _payload(_call(server, "open_process", pid=4242))
        session_id = opened["session_id"]

        address = fake_process.poke(WRITABLE_BASE + 0x100, int, 4200)
        scan = _payload(
            _call(
                server, "scan_value",
                session_id=session_id, value_type="int", value="4200", bufflength=4,
            )
        )
        assert scan["count"] == 1

        fake_process.poke(address, int, 4100)
        refined = _payload(
            _call(server, "refine_scan", scan_id=scan["scan_id"], value="4100")
        )
        assert refined["count"] == 1

        written = _payload(
            _call(
                server, "write_value",
                session_id=session_id, address=refined["sample"][0]["address"],
                value_type="int", value="7", bufflength=4,
            )
        )
        assert written["previous_value"] == 4100
        assert fake_process.read_process_memory(address, int, 4) == 7

    def test_a_session_error_reaches_the_model_with_its_guidance(self, built):
        # The SDK withholds the message of any exception that is not its own
        # ToolError, so an unmapped error would reach the model as a bare
        # "Error executing tool read_value" and it would retry blindly.
        server, _toolset = built(config())
        with pytest.raises(Exception) as caught:
            _call(server, "read_value", session_id="proc-nope", address="0x1000")
        assert "open_process" in str(caught.value)

    def test_a_tool_error_reaches_the_model_with_its_guidance(self, built):
        server, _toolset = built(config())
        _call(server, "open_process", pid=4242)
        with pytest.raises(Exception) as caught:
            _call(
                server, "read_value",
                session_id="proc-1", address="not-an-address", value_type="int",
            )
        assert "0x" in str(caught.value)

    def test_a_policy_refusal_names_the_flag_that_lifts_it(self, fake_process):
        # The denylist is the hard refusal: no prompt would change it, so the
        # message has to name the flag instead.
        fake_process.pid, fake_process.name = 1, "launchd"
        toolset = _toolset_for(fake_process, ServerConfig())
        server, _toolset = build_server(toolset.config, toolset=toolset)

        with pytest.raises(Exception) as caught:
            _call(server, "open_process", pid=1)
        assert "--allow-system-processes" in str(caught.value)

    def test_an_unknown_tool_is_rejected(self, built):
        server, _toolset = built(config())
        with pytest.raises(Exception):
            _call(server, "delete_everything")


class TestBuildServer:
    def test_defaults_need_no_flags_to_be_useful(self, fake_process):
        # `claude mcp add pymemoryeditor -- pymemoryeditor-mcp` must give a
        # working memory editor, not one missing its headline tool.
        server, toolset = build_server()
        assert toolset.config.allow_write is True
        assert "write_value" in _tool_names(server)

    def test_read_only_removes_the_write_tool(self, fake_process):
        server, toolset = build_server(ServerConfig(allow_write=False))
        assert "write_value" not in _tool_names(server)

    def test_returns_the_toolset_so_handles_can_be_closed(self, built, fake_process):
        _server, toolset = built(config())
        toolset.open_process(pid=4242)
        assert toolset.store.close_all() == 1
        assert fake_process.closed


class TestAttachApproval:
    """Attaching to an unlisted process asks the user, live, and obeys them.

    This is the feature that lets one server be pointed at whatever you need
    later, instead of at a target fixed when the client was configured. The
    guard rail moves from configuration time to use time — so these tests are
    about who decides, and about the answer actually being honoured.
    """

    def _build(self, server_config, process=None):
        process = process or FakeProcess()
        toolset = _toolset_for(process, server_config)
        server, _toolset = build_server(server_config, toolset=toolset)
        return server, toolset, process

    def _open(self, server_config, answerer, arguments=None, process=None):
        server, toolset, process = self._build(server_config, process)

        async def run():
            async with connected(server, answerer) as session:
                return await session.call_tool(
                    "open_process", arguments or {"pid": 4242}
                )

        return asyncio.run(run()), toolset

    # --- the prompt itself --------------------------------------------- #

    def test_an_unlisted_target_prompts_the_user(self):
        answerer = Answerer("accept")
        self._open(ServerConfig(), answerer)
        assert answerer.asked

    def test_the_prompt_identifies_the_process(self):
        # The user is authorizing access to one specific process; a prompt that
        # does not say which one is not consent.
        answerer = Answerer("accept")
        self._open(ServerConfig(), answerer)
        assert "faketarget" in answerer.prompts[0]
        assert "4242" in answerer.prompts[0]

    def test_the_prompt_says_whether_writes_are_possible(self):
        # The consent prompt is where the user learns that approving this
        # target also means it can be modified — which is the default.
        writable = Answerer("accept")
        self._open(ServerConfig(), writable)
        assert "ENABLED" in writable.prompts[0]

        read_only = Answerer("accept")
        self._open(ServerConfig(allow_write=False), read_only)
        assert "read-only" in read_only.prompts[0]

    # --- honouring the answer ------------------------------------------ #

    def test_approval_attaches(self):
        result, _toolset = self._open(ServerConfig(), Answerer("accept"))
        assert result.is_error is False
        assert _payload(result)["opened"] is True

    def test_refusal_does_not_attach(self):
        result, toolset = self._open(ServerConfig(), Answerer("decline"))
        assert result.is_error is True
        assert toolset.store.sessions == ()

    def test_refusal_tells_the_model_not_to_go_looking_elsewhere(self):
        # The failure mode this guards against: a declined attach followed by
        # the model quietly trying a neighbouring process instead.
        result, _toolset = self._open(ServerConfig(), Answerer("decline"))
        text = result.content[0].text
        assert "did not approve" in text
        assert "Do not retry" in text

    def test_cancelling_the_dialog_is_not_approval(self):
        result, toolset = self._open(ServerConfig(), Answerer("cancel"))
        assert result.is_error is True
        assert toolset.store.sessions == ()

    # --- remembering --------------------------------------------------- #

    def test_approval_is_not_remembered_by_default(self):
        _result, toolset = self._open(ServerConfig(), Answerer("accept"))
        assert toolset.policy.granted_names == ()

    def test_remember_grants_the_name(self):
        _result, toolset = self._open(
            ServerConfig(), Answerer("accept", remember=True)
        )
        assert toolset.policy.granted_names == ("faketarget",)

    def test_a_remembered_target_stops_prompting(self):
        server_config = ServerConfig()
        process = FakeProcess()
        server, toolset, process = self._build(server_config, process)

        first = Answerer("accept", remember=True)
        second = Answerer("decline")  # would refuse if it were asked again

        async def run():
            async with connected(server, first) as session:
                await session.call_tool("open_process", {"pid": 4242})
            async with connected(server, second) as session:
                return await session.call_tool("open_process", {"pid": 4242})

        result = asyncio.run(run())
        assert second.asked is False
        assert _payload(result)["opened"] is True

    def test_a_remembered_name_does_not_cover_other_processes(self):
        server_config = ServerConfig()
        process = FakeProcess()
        server, toolset, _process = self._build(server_config, process)
        toolset.policy.grant("faketarget")

        other = Answerer("accept")
        process.name = "somethingelse"
        toolset._name_for_pid = lambda pid: "somethingelse"

        async def run():
            async with connected(server, other) as session:
                return await session.call_tool("open_process", {"pid": 4242})

        asyncio.run(run())
        assert other.asked, "a different process must still be approved"

    # --- when asking is unnecessary or impossible ----------------------- #

    def test_a_preapproved_target_never_prompts(self):
        answerer = Answerer("decline")
        result, _toolset = self._open(
            ServerConfig(allowed_processes=("faketarget",)), answerer
        )
        assert answerer.asked is False
        assert _payload(result)["opened"] is True

    def test_allow_any_process_never_prompts(self):
        answerer = Answerer("decline")
        result, _toolset = self._open(ServerConfig(allow_any_process=True), answerer)
        assert answerer.asked is False
        assert _payload(result)["opened"] is True

    def test_a_denylisted_target_is_refused_without_asking(self):
        # Consent is not the question here: these are refused outright, so
        # prompting would only teach the user to click through warnings.
        answerer = Answerer("accept")
        process = FakeProcess(pid=1, name="launchd")
        result, toolset = self._open(
            ServerConfig(), answerer, arguments={"pid": 1}, process=process
        )
        assert answerer.asked is False
        assert result.is_error is True
        assert "denylist" in result.content[0].text

    def test_a_client_that_cannot_ask_is_refused_with_guidance(self):
        # No elicitation callback: the client never advertises the capability,
        # so there is nobody to ask. Failing open here would silently void the
        # "asks before attaching" promise on such clients.
        result, toolset = self._open(ServerConfig(), None)
        assert result.is_error is True
        text = result.content[0].text
        assert "--allow-process" in text and "--allow-any-process" in text
        assert toolset.store.sessions == ()

    # --- the rest of the loop still works after approval ---------------- #

    def test_the_full_loop_runs_after_an_approved_attach(self):
        server_config = ServerConfig(allow_write=True)
        process = FakeProcess()
        server, toolset, process = self._build(server_config, process)
        address = process.poke(WRITABLE_BASE + 0x100, int, 4200)

        async def run():
            async with connected(server, Answerer("accept")) as session:
                opened = json.loads(
                    (await session.call_tool("open_process", {"pid": 4242}))
                    .content[0].text
                )
                scan = json.loads(
                    (
                        await session.call_tool(
                            "scan_value",
                            {
                                "session_id": opened["session_id"],
                                "value_type": "int",
                                "value": "4200",
                                "bufflength": 4,
                            },
                        )
                    ).content[0].text
                )
                return opened, scan

        opened, scan = asyncio.run(run())
        assert opened["opened"] is True
        assert scan["count"] == 1
        assert scan["sample"][0]["address"] == "0x%X" % address


class TestAlwaysAskMetadata:
    """The two tools whose blast radius is another process force a prompt.

    Claude Code ignores ``readOnlyHint`` / ``destructiveHint`` when deciding
    whether to ask; it honours ``_meta["anthropic/requiresUserInteraction"]``,
    which forces approval on *every* call even under its most permissive
    auto-approve mode. These assertions are the only thing standing between a
    refactor and a server that silently stops asking.
    """

    def _tools(self, server):
        return {tool.name: tool for tool in _run(server.list_tools())}

    def test_open_process_always_requires_interaction(self):
        server, _toolset = build_server(config())
        meta = self._tools(server)["open_process"].meta or {}
        assert meta.get("anthropic/requiresUserInteraction") is True

    def test_write_value_always_requires_interaction(self):
        server, _toolset = build_server(config(allow_write=True))
        meta = self._tools(server)["write_value"].meta or {}
        assert meta.get("anthropic/requiresUserInteraction") is True

    def test_open_process_is_not_advertised_as_read_only(self):
        # It acquires a debug handle on another process. Some clients treat
        # readOnlyHint as "safe to auto-approve".
        server, _toolset = build_server(config())
        assert self._tools(server)["open_process"].annotations.read_only_hint is False

    def test_plain_read_tools_do_not_force_a_prompt(self):
        # Forcing interaction on every read would make the loop unusable.
        server, _toolset = build_server(config())
        for name in ("read_value", "scan_value", "list_processes", "server_info"):
            assert not (self._tools(server)[name].meta or {}).get(
                "anthropic/requiresUserInteraction"
            ), name


class TestBuildServerConsistency:
    """The server must not advertise a capability its toolset will refuse."""

    def test_a_read_only_toolset_is_not_given_a_write_tool(self, fake_process):
        # `config` defaulted to write-enabled while every write check reads
        # `toolset.config`, so passing only a read-only toolset registered
        # write_value: the model saw the tool, called it, and hit the
        # defence-in-depth refusal every time.
        toolset = _toolset_for(fake_process, ServerConfig(allow_write=False))
        server, built = build_server(toolset=toolset)
        assert built.config.allow_write is False
        assert "write_value" not in _tool_names(server)

    def test_the_toolset_config_wins_over_the_argument(self, fake_process):
        toolset = _toolset_for(fake_process, ServerConfig(allow_write=False))
        server, built = build_server(ServerConfig(allow_write=True), toolset=toolset)
        assert built.config.allow_write is False
        assert "write_value" not in _tool_names(server)

    def test_registration_matches_the_config_either_way(self, fake_process):
        for allow_write in (True, False):
            toolset = _toolset_for(fake_process, ServerConfig(allow_write=allow_write))
            server, _built = build_server(toolset=toolset)
            assert ("write_value" in _tool_names(server)) is allow_write


class TestRememberingANamelessTarget:
    """A process whose name cannot be read has nothing to remember it by."""

    def test_remember_reports_that_it_could_not_be_honoured(self, fake_process):
        # Grants are matched by name so they survive a restart; with no name
        # there is nothing to store. Silently dropping the tick left the user
        # believing it worked and being asked again next time.
        fake_process.name = ""
        toolset = _toolset_for(fake_process, ServerConfig())
        toolset._name_for_pid = lambda pid: ""
        server, _toolset = build_server(toolset=toolset)

        answerer = Answerer("accept", remember=True)

        async def run():
            async with connected(server, answerer) as session:
                return await session.call_tool("open_process", {"pid": 4242})

        payload = _payload(asyncio.run(run()))
        assert payload["opened"] is True
        assert payload["approval_remembered"] is False
        assert "could not be read" in payload["approval_note"]
        assert toolset.policy.granted_names == ()

    def test_a_named_target_reports_the_grant(self, fake_process):
        toolset = _toolset_for(fake_process, ServerConfig())
        server, _toolset = build_server(toolset=toolset)
        answerer = Answerer("accept", remember=True)

        async def run():
            async with connected(server, answerer) as session:
                return await session.call_tool("open_process", {"pid": 4242})

        payload = _payload(asyncio.run(run()))
        assert payload["approval_remembered"] is True
        assert toolset.policy.granted_names == ("faketarget",)
