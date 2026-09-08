# -*- coding: utf-8 -*-

"""
The MCP protocol layer: registers :class:`MemoryToolset` on an SDK server.

This is deliberately the thinnest file in the package. Everything worth testing
lives in :mod:`PyMemoryEditor.mcp.toolset` and knows nothing about MCP; here we
only attach those methods to the SDK, tag them with the read-only /
destructive hints a client uses to decide what to prompt about, and pick a
transport.

The SDK derives each tool's JSON schema from the method signature and its
description from the docstring, so the docstrings in ``toolset.py`` are not
internal notes — they are the prompt the model reads before deciding which tool
to call. Changing one changes the server's behaviour.

Requires the ``mcp`` SDK (2.x), which ships in the ``mcp`` extra::

    pip install "PyMemoryEditor[mcp]"
"""

import functools
import inspect
import logging
import sys
from typing import TYPE_CHECKING, Any, Callable, List, Optional, Sequence, Tuple

from .. import __version__
from .config import ServerConfig, parse_args
from .session import MAX_OPEN_SESSIONS, SessionError, host_platform
from .toolset import MemoryToolset, ToolError

if TYPE_CHECKING:  # pragma: no cover - import cost avoided at runtime
    from mcp.server.mcpserver import MCPServer


_logger = logging.getLogger("PyMemoryEditor")


#: Server-level guidance, handed to the model before it picks a tool. It exists
#: to pre-empt the two failure modes this domain invites: treating a first
#: scan's result count as an answer (it is noise until refined), and hunting for
#: a way around a policy refusal instead of reporting it.
INSTRUCTIONS = """\
PyMemoryEditor exposes the memory of live processes on this machine: enumerate
processes, attach to one, scan its memory for a value, narrow the matches, then
read or write them. It is the Cheat Engine workflow, driven by tools.

Start with `server_info` — it reports whether writing is enabled at all, which
processes are reachable, and which sessions are already open.

The core loop, and the only reliable way to find an address:

1. `open_process` -> a `session_id`.
2. `scan_value` with the value you can see in the target now (e.g. health 100).
   Expect thousands of matches. That count is not progress; it is a starting
   set. You get a `scan_id`, not the addresses.
3. Ask the user to change the value in the target (take damage, spend a coin),
   then `refine_scan` with the new value. Repeat 2-4 times.
4. When a handful remain, `list_scan_results` reads their live values. The one
   that tracks what the user reports is the address.
5. `find_pointer_paths` on that address turns it into a recipe that survives a
   restart; `resolve_pointer_chain` replays such a recipe in a later run.

Things worth knowing before you call anything:

- Never guess an address. An address that did not come out of a scan, a pointer
  chain, or a module base plus a known offset is meaningless, and writing to
  one corrupts unrelated state in a live process.
- Writing is usually available, and the user confirms every write before it
  runs. Say what you are changing and from what to what, so they can judge it;
  `write_value` returns the previous value, which is the only way back.
- A scan result flagged `partial` is a prefix of the real matches, not the
  whole set. Refining it can converge confidently on the wrong address. Narrow
  the scan and rerun instead.
- Scans cost seconds and hold the target's lock. Keep `writable_only` on unless
  you are hunting a constant, and prefer refining a set over rescanning.
- Attaching to a process usually needs the user's approval, asked for live
  when you call `open_process`. Name the process you want and say why. If they
  refuse, report that — do not retry, and do not attach to something else
  instead on the assumption it is close enough.
- If a tool refuses on policy grounds (a denied process, writes disabled), that
  is the operator's configuration. Report it and say which flag lifts it; do
  not look for another route to the same effect.
- Addresses are hex strings ("0x7FFD1234") in both directions. Pass back what
  you were given rather than converting.
"""


def _surface_errors(method: Callable) -> Callable:
    """Re-raise our own tool errors as the SDK's, so the model can read them.

    The SDK draws a hard line between a failure the tool *anticipated* and a
    crash: raise its ``ToolError`` and the message goes back to the model with
    ``is_error=True``; raise anything else and it is wrapped in
    ``UnexpectedToolError``, whose message is only "Error executing tool
    <name>" — the original text is deliberately withheld from the client.

    That default is right for a genuine crash and wrong for everything in
    :mod:`~PyMemoryEditor.mcp.toolset`, where the entire value of a
    :class:`~PyMemoryEditor.mcp.toolset.ToolError` is the sentence telling the
    model what to do instead ("pass a pid", "the write flag is off", "refine
    the previous set"). Swallow those and an agent retries the same broken call
    until it gives up.

    So the translation happens here rather than in the toolset, which stays
    free of any SDK import. Genuinely unexpected exceptions are left alone: a
    crash should still be logged with its traceback and reported as a crash.

    ``functools.wraps`` carries over the signature, annotations and docstring
    the SDK derives each tool's schema and description from.

    Async tools get an async wrapper. A sync wrapper around a coroutine
    function returns the coroutine object *unawaited*: the SDK would receive a
    coroutine where it expected a result, the tool would never actually run,
    and — because the schema and description are derived from the signature
    rather than a call — everything about the tool would still look correct
    from the outside.
    """
    from mcp.server.mcpserver.exceptions import ToolError as SdkToolError

    if inspect.iscoroutinefunction(method):

        @functools.wraps(method)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return await method(*args, **kwargs)
            except (ToolError, SessionError) as error:
                raise SdkToolError(str(error)) from error

        return async_wrapper

    @functools.wraps(method)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return method(*args, **kwargs)
        except (ToolError, SessionError) as error:
            raise SdkToolError(str(error)) from error

    return wrapper


def _read_only(toolset: MemoryToolset) -> List[Tuple[Any, bool]]:
    """The always-registered tools that really are read-only, with an
    idempotency hint.

    "Idempotent" here means *calling it twice does the same thing* — true of
    the pure lookups, false of anything that mints a scan id. Clients use the
    hint to decide what may be retried silently.

    ``close_process`` used to be in this list and is not read-only: it drops
    the handle *and* every scan result set in the session. A client that treats
    ``read_only_hint`` as licence to auto-approve would throw away a refine
    chain the user spent minutes building, without asking. It is registered
    separately below.
    """
    return [
        (toolset.server_info, True),
        (toolset.list_processes, True),
        (toolset.process_info, True),
        (toolset.list_memory_regions, True),
        (toolset.scan_value, False),
        (toolset.scan_pattern, False),
        (toolset.refine_scan, False),
        (toolset.list_scan_results, True),
        (toolset.read_value, True),
        (toolset.resolve_pointer_chain, True),
        (toolset.find_pointer_paths, False),
    ]


#: Marks a tool so a client always asks the user before running it, even in
#: its most permissive auto-approve mode. An Anthropic extension rather than
#: standard MCP (clients that do not know the key simply ignore it), and worth
#: setting on the two tools whose blast radius is another live process:
#: acquiring a debug handle, and changing memory.
_ALWAYS_ASK = {"anthropic/requiresUserInteraction": True}


def _register_open_process(server: "MCPServer", toolset: MemoryToolset) -> None:
    """Register ``open_process`` with a human in the approval path.

    The policy has three answers, and the middle one — *ask* — is the reason
    this tool cannot just be the toolset's bound method like the rest. Attaching
    to a process is where the server stops being a passive reader and starts
    holding a debug handle on something the user cares about, so a target that
    the operator did not pre-approve is escalated to the person, live, through
    MCP elicitation. The model can request a target; only the user grants it.

    On a client without elicitation there is no one to ask, so the attach is
    refused and the message names the flags that resolve it. Failing open here
    would mean the "asks before attaching" promise silently evaporates on some
    clients, which is worse than an error the operator can act on.
    """
    from mcp.server.elicitation import AcceptedElicitation
    from mcp.server.mcpserver import Context
    from mcp.server.mcpserver.exceptions import ToolError as SdkToolError
    from mcp.types import ToolAnnotations
    from pydantic import BaseModel, Field

    class AttachApproval(BaseModel):
        """The form shown to the user when a new target needs approval."""

        remember: bool = Field(
            default=False,
            description=(
                "Stop asking for this process for the rest of this server's "
                "life (it also covers the target restarting)."
            ),
        )

    # ``ctx`` is keyword-only and has no default: the SDK injects it by
    # annotation and strips it from the input schema, so a default would only
    # invite a caller to pass None and skip the approval channel.
    async def open_process(pid: int = 0, name: str = "", *, ctx: Context) -> Any:
        target = toolset.resolve_target(pid=pid, name=name)

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

        found_pid, found_name = target["pid"], target["name"]
        decision = target["decision"]

        if decision.allowed:
            return toolset.attach(found_pid, found_name)

        if not decision.needs_approval:
            raise SdkToolError(decision.reason)

        if not _can_elicit(ctx):
            raise SdkToolError(decision.reason)

        # Before the prompt, not after. The cap lives in SessionStore.open,
        # which runs once the handle is already open -- so without this the
        # user was asked to approve an attach, approved it, and then got told
        # the server was full. An approval is the most expensive step here and
        # the one thing this server must not spend carelessly.
        if toolset.store.at_capacity():
            raise SdkToolError(
                "Not asking to attach to \"%s\" (pid %d): this server already "
                "has %d processes open, which is the limit. Close one with "
                "close_process first." % (found_name, found_pid, MAX_OPEN_SESSIONS)
            )

        try:
            answer = await ctx.elicit(
                message=(
                    'Allow PyMemoryEditor to attach to "%s" (pid %d)?\n\n'
                    "This gives the assistant read access to that process's "
                    "memory.%s"
                    % (
                        found_name or "unknown",
                        found_pid,
                        (
                            "\nWrites are ENABLED on this server, so it can "
                            "also change values in it."
                            if toolset.config.allow_write
                            else "\nThis server is read-only; it cannot change "
                            "the process."
                        ),
                    )
                ),
                schema=AttachApproval,
            )
        except Exception as error:  # noqa: BLE001 — a client that cannot answer
            _logger.warning("Attach approval could not be requested: %s", error)
            raise SdkToolError(
                'Could not ask for approval to attach to "%s" (pid %d): %s. %s'
                % (found_name, found_pid, error, _APPROVAL_FALLBACK)
            ) from None

        if not isinstance(answer, AcceptedElicitation):
            raise SdkToolError(
                'The user did not approve attaching to "%s" (pid %d). Do not '
                "retry it or try a different process on your own — report the "
                "refusal and ask what they would like instead."
                % (found_name, found_pid)
            )

        remember = bool(getattr(answer.data, "remember", False))
        remembered = False

        if remember and found_name:
            toolset.policy.grant(found_name)
            remembered = True
            _logger.info("Approved and remembered target %r", found_name)
        else:
            _logger.info("Approved target %r (this attach only)", found_name)

        result = toolset.attach(found_pid, found_name)

        if remember and not remembered:
            # A process whose name this user cannot read has nothing to
            # remember it by, and grants are name-based so the target survives
            # a restart. Say so instead of letting the user believe their tick
            # was honoured and then be asked again next time.
            result["approval_remembered"] = False
            result["approval_note"] = (
                "The user asked to remember this target, but its name could not "
                "be read, and approvals are matched by name. Attaching to it "
                "will prompt again — mention this so they are not surprised."
            )
        elif remember:
            result["approval_remembered"] = True

        return result

    # The canonical model-facing description lives on the toolset method, so
    # the two entry points cannot drift. Only __doc__ is copied: functools.wraps
    # would also set __wrapped__, and the SDK follows that when deriving the
    # signature — which would hide the `ctx` parameter it needs to inject.
    open_process.__doc__ = toolset.open_process.__doc__

    server.tool(
        annotations=ToolAnnotations(
            # Not read-only: it acquires a debug handle on another process.
            # Some clients treat readOnlyHint as "safe to auto-approve".
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=True,
        ),
        meta=dict(_ALWAYS_ASK),
    )(_surface_errors(open_process))


def _can_elicit(ctx: Any) -> bool:
    """Whether the connected client can show the user a form.

    Checked rather than assumed: elicitation is optional in MCP, and calling it
    on a client that never advertised it produces a protocol error in the
    middle of a tool call rather than a usable answer.
    """
    if ctx is None:
        return False
    try:
        capabilities = ctx.client_capabilities
    except Exception:  # noqa: BLE001 — no active session
        return False
    return bool(capabilities is not None and capabilities.elicitation is not None)


#: Appended to an approval failure: the two ways an operator can proceed.
_APPROVAL_FALLBACK = (
    "This client cannot prompt for approval. Ask the user to restart the "
    "server with --allow-process NAME to pre-approve the target, or "
    "--allow-any-process to stop asking altogether."
)


def build_server(
    config: Optional[ServerConfig] = None,
    *,
    toolset: Optional[MemoryToolset] = None,
) -> "Tuple[MCPServer, MemoryToolset]":
    """Build the MCP server for ``config``.

    :param config: the operator's flags. Defaults to :class:`ServerConfig`'s
        own defaults — writes allowed, and the user asked before each attach.
        Ignored when ``toolset`` is given: the toolset's own config wins.
    :param toolset: an existing toolset to expose, for tests that want to drive
        a fake target through the real protocol layer.
    :returns: the server and the toolset it wraps — the caller needs the latter
        to close outstanding process handles on shutdown.
    :raises RuntimeError: when the ``mcp`` SDK is missing or too old, with the
        install command in the message.

    Tool registration keys off the *toolset's* config rather than the ``config``
    argument, because every write check inside the toolset does. Letting the two
    disagree would register ``write_value`` against a read-only toolset: the
    model would see the tool, call it, and hit the defence-in-depth refusal
    every time — a capability advertised and then denied.
    """
    try:
        from mcp.server.mcpserver import MCPServer
        from mcp.types import ToolAnnotations
    except ImportError as error:
        raise RuntimeError(
            "The MCP server needs the 'mcp' SDK (2.x), which is not installed. "
            'Install it with:  pip install "PyMemoryEditor[mcp]"   '
            "(underlying error: %s)" % error
        ) from None

    if toolset is not None:
        # The toolset is the authority on its own configuration.
        config = toolset.config
    else:
        config = config if config is not None else ServerConfig()
        toolset = MemoryToolset(config)

    server = MCPServer(
        name="pymemoryeditor",
        title="PyMemoryEditor — process memory",
        version=__version__,
        instructions=INSTRUCTIONS,
        website_url="https://github.com/JeanExtreme002/PyMemoryEditor",
    )

    for method, idempotent in _read_only(toolset):
        server.tool(
            annotations=ToolAnnotations(
                read_only_hint=True,
                destructive_hint=False,
                idempotent_hint=idempotent,
                # The target's memory is state outside this server that changes
                # on its own: the same read twice legitimately differs.
                open_world_hint=True,
            )
        )(_surface_errors(method))

    # Not read-only, and the annotation has to say so. Closing discards every
    # scan set in the session -- work that took the user real time to narrow --
    # so a client auto-approving on `read_only_hint` was destroying state on
    # the model's word alone.
    #
    # No `_ALWAYS_ASK`, though: this is the ordinary way to finish, and
    # prompting on every cleanup teaches the user to click through prompts,
    # which is what makes the write confirmation worth anything. `destructive`
    # plus not-idempotent is the honest signal without that cost.
    server.tool(
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=False,
            open_world_hint=True,
        )
    )(_surface_errors(toolset.close_process))

    _register_open_process(server, toolset)

    if config.allow_write:
        # Present unless --read-only. Writing is the point of a memory editor,
        # and the two consent points that matter are elsewhere: the user
        # approves the target, and _ALWAYS_ASK makes the client confirm every
        # single write. Under --read-only the tool is not registered at all —
        # a tool the model cannot see is one it cannot be talked into calling,
        # which is worth more than the better error message a
        # registered-but-refusing tool would give.
        server.tool(
            annotations=ToolAnnotations(
                read_only_hint=False,
                destructive_hint=True,
                idempotent_hint=True,
                open_world_hint=True,
            ),
            # Changing another process's memory is never something to
            # auto-approve, whatever mode the client is running in.
            meta=dict(_ALWAYS_ASK),
        )(_surface_errors(toolset.write_value))

    return server, toolset


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point for ``pymemoryeditor-mcp`` and ``python -m PyMemoryEditor.mcp``.

    Logs go to stderr, never stdout: on the default stdio transport, stdout
    *is* the protocol channel and one stray print corrupts the session.
    """
    config, transport = parse_args(argv)

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        server, toolset = build_server(config)
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1

    _logger.info(
        "PyMemoryEditor MCP server %s on %s — writes %s, %s",
        __version__,
        host_platform(),
        "ENABLED" if config.allow_write else "disabled",
        (
            "allowlist: %s" % ", ".join(config.allowed_processes)
            if config.allowed_processes
            else "no process allowlist"
        ),
    )

    try:
        server.run(transport=transport)
    except KeyboardInterrupt:
        pass
    finally:
        # Leaving a debug handle open on someone's game after the client
        # disconnects is both a leak and, on Windows, a reason the target
        # cannot be updated or closed cleanly.
        closed = toolset.store.close_all()
        if closed:
            _logger.info("Closed %d process handle(s) on shutdown.", closed)

    return 0


__all__ = ("INSTRUCTIONS", "build_server", "main")
