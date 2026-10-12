# -*- coding: utf-8 -*-

"""
Command-line configuration for the MCP server.

The server is launched by an MCP *client* (Claude Code, Claude Desktop, an
editor plugin) from a JSON config file, not by a human at a prompt. The
operator writes these flags once, months before the model ever calls a tool,
and nobody is watching stderr when it does — so the defaults are what actually
governs the server, and they need to be the ones that make it useful *and*
keep a human in the loop.

Both halves are load-bearing here. The server is a memory **editor**: a
read-only default would make the headline workflow — find a value, change it
— require a flag nobody discovers, which is a bad trade when the protections that
matter are elsewhere. Consent is enforced at the two points where it can
actually be given:

* **which process** — attaching to a target the operator did not pre-approve
  asks the user, live, and the prompt says whether writes are possible
  (:mod:`PyMemoryEditor.mcp.policy`);
* **each write** — ``write_value`` is tagged so a client that honours the
  ``anthropic/requiresUserInteraction`` hint prompts on every call, even in its
  most permissive auto-approve mode (see ``_ALWAYS_ASK`` in
  :mod:`PyMemoryEditor.mcp.server`). The hint is an Anthropic extension, not
  standard MCP: a client that does not know it may run writes unprompted, and
  ``--read-only`` is the guarantee for that case, and ``--confirm-writes``
  the opt-in that makes the server itself ask before each write on any client
  that supports elicitation.

``--read-only`` is there for when you want the guarantee enforced below this
process rather than promised by it: the write tool is not registered at all, so
the model never sees it, and on Windows the target is opened with a handle that
carries no write rights, leaving the kernel to enforce it.
"""

import argparse
from dataclasses import dataclass, field
from typing import List, Literal, Optional, Sequence, Tuple, cast

from .policy import ProcessPolicy


#: The transports the MCP SDK can serve this server over. Spelled as a
#: ``Literal`` because the SDK's ``run()`` is overloaded per transport — a plain
#: ``str`` matches none of the overloads and fails type checking at the call
#: site.
Transport = Literal["stdio", "sse", "streamable-http"]

#: Hard ceiling on the addresses one scan keeps. A first scan for a common
#: value (``int`` ``0``, ``100``) legitimately matches millions of addresses;
#: keeping them all would blow out the server's memory for a result set no
#: refine loop can use anyway. At the cap the scan stops early and says so.
#:
#: Sizing: 100 000 addresses cost ~4.2 MB per result set. A session keeps
#: ``MAX_SCANS_PER_SESSION`` (20) of them and a server keeps
#: ``MAX_OPEN_SESSIONS`` (8) sessions, so the ceiling on retained addresses is
#: ~672 MB — reachable only by a long refine chain across several targets.
#: The time a scan spends reaching the cap depends on how dense the value is:
#: for a sparse value it walks further to collect more hits, bounded by the
#: wall-clock budget below.
DEFAULT_MAX_SCAN_RESULTS = 100_000

#: Wall-clock budget for one scan, in seconds. A full address-space scan of a
#: large process takes minutes — long past the point where an MCP client gives
#: up on the request and the model starts retrying. Scans check the budget
#: between region batches and return a partial, explicitly-flagged result
#: instead of hanging.
DEFAULT_MAX_SCAN_SECONDS = 30.0

#: Bytes of target memory one scan batch covers before the deadline is checked.
#: Value scans only yield on a *hit*, so a rare value produces no yields for
#: minutes; the only way to stay interruptible is to drive the scan region
#: batch by region batch and check the clock between them.
DEFAULT_SCAN_BATCH_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class ServerConfig:
    """Everything the server's behaviour depends on.

    :param allow_write: register the memory-mutating tools (``write_value``).
        **On by default** — editing memory is what the library is for, and
        clients that honour the ``anthropic/requiresUserInteraction`` hint ask
        before each write (others may not). Set it off with ``--read-only``
        when your client auto-approves tools, or whenever you want the
        guarantee enforced below this process: the tool then does not exist,
        and on Windows the process handle carries no write rights.
    :param confirm_writes: confirm every ``write_value`` call with the user
        through an MCP elicitation prompt the server sends itself, instead of
        relying on the client to honour the ``requiresUserInteraction`` hint.
        Off by default, because a client that honours the hint (Claude Code)
        would then ask twice. Fails closed: on a client that cannot show the
        prompt, writes are refused rather than run unconfirmed.
    :param allowed_processes: process names pre-approved so they open without
        prompting — see :class:`~PyMemoryEditor.mcp.policy.ProcessPolicy`.
        Leaving it empty does **not** mean "anything goes": unlisted targets
        prompt the user instead.
    :param allow_any_process: never prompt — open any target the denylist
        permits. For scripted use, where there is nobody to ask.
    :param allow_system_processes: lift the system-process denylist.
    :param protect_self: refuse to open this process (the server) and its
        parent (the MCP client). On by default, lifted by no flag; see
        :class:`~PyMemoryEditor.mcp.policy.ProcessPolicy`. Exists so a test
        that attaches to itself can turn it off.
    :param max_scan_results: per-scan cap on stored addresses.
    :param max_scan_seconds: per-scan wall-clock budget.
    :param scan_batch_bytes: memory covered per deadline check.

    :raises ValueError: if ``max_scan_results``, ``max_scan_seconds`` or
        ``scan_batch_bytes`` is not positive.

    .. note::
       The three numeric bounds are validated here as well as in
       ``parse_args``, so an embedder constructing this in code gets the same
       answer the CLI operator gets, and a config built in Python fails
       loudly instead of quietly: ``scan_batch_bytes=0`` would make every
       region its own scan batch (thousands of generator setups per scan on a
       desktop target), and ``max_scan_results=0`` would make every scan
       return nothing while flagging itself partial. Neither is unsafe — unlike
       the process allowlist, where a bad value silently disables the consent
       prompt — but both are indistinguishable from a broken server.
    """

    allow_write: bool = True
    confirm_writes: bool = False
    allowed_processes: Tuple[str, ...] = field(default=())
    allow_any_process: bool = False
    allow_system_processes: bool = False
    protect_self: bool = True
    max_scan_results: int = DEFAULT_MAX_SCAN_RESULTS
    max_scan_seconds: float = DEFAULT_MAX_SCAN_SECONDS
    scan_batch_bytes: int = DEFAULT_SCAN_BATCH_BYTES

    def __post_init__(self) -> None:
        # Mirrors the three checks in `parse_args`. Kept as ValueError rather
        # than `parser.error`: this constructor is library API, and the CLI
        # already reports its own violations before ever reaching here.
        if self.max_scan_results < 1:
            raise ValueError(
                "max_scan_results must be at least 1 (got %r)." % (self.max_scan_results,)
            )
        if self.max_scan_seconds <= 0:
            raise ValueError(
                "max_scan_seconds must be positive (got %r)." % (self.max_scan_seconds,)
            )
        if self.scan_batch_bytes < 1:
            raise ValueError(
                "scan_batch_bytes must be at least 1 (got %r)." % (self.scan_batch_bytes,)
            )

    def policy(self) -> ProcessPolicy:
        """Build the :class:`ProcessPolicy` this configuration describes."""
        return ProcessPolicy(
            allowed_names=self.allowed_processes,
            allow_system=self.allow_system_processes,
            allow_any=self.allow_any_process,
            protect_self=self.protect_self,
        )


def build_parser() -> argparse.ArgumentParser:
    """The ``pymemoryeditor-mcp`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="pymemoryeditor-mcp",
        description=(
            "Expose PyMemoryEditor's process-memory tools over the Model "
            "Context Protocol, so an AI assistant can run the Cheat "
            "Engine scan/refine/read loop against a live process."
        ),
        epilog=(
            "Needs no flags: it asks you before attaching to a process, and "
            "clients that honour the requiresUserInteraction hint (such as "
            "Claude Code) ask before each write; others may not. Pass "
            "--read-only to remove the write tool entirely, or "
            "--confirm-writes to have the server itself ask before each write "
            "(do one or the other if your client auto-approves tools), or "
            "--allow-process NAME to skip the attach prompt for a target you "
            "already trust."
        ),
    )
    parser.add_argument(
        "--read-only",
        action="store_true",
        dest="read_only",
        help=(
            "do not register the write tool, so the server can read and scan "
            "but never modify a target. On Windows the process handle is also "
            "opened without write rights, so the kernel enforces it."
        ),
    )
    parser.add_argument(
        "--confirm-writes",
        action="store_true",
        dest="confirm_writes",
        help=(
            "ask you to confirm every write through an approval prompt sent by "
            "the server itself, on any client that supports MCP elicitation. "
            "Use it when your client does not honour the "
            "requiresUserInteraction hint; on a client that cannot show the "
            "prompt, writes are refused. Unneeded on Claude Code, which "
            "already asks (it would ask twice)."
        ),
    )
    parser.add_argument(
        "--allow-process",
        action="append",
        default=[],
        metavar="NAME",
        dest="allowed_processes",
        help=(
            "pre-approve processes whose name contains NAME (case-insensitive), "
            "so attaching to them never prompts. Repeatable. Omitting it does "
            "not open the server up: unlisted targets ask for your approval at "
            "the moment they are needed."
        ),
    )
    parser.add_argument(
        "--allow-any-process",
        action="store_true",
        help=(
            "never ask — open any target the system denylist permits. Use it "
            "for scripted or non-interactive runs, where no one is there to "
            "answer a prompt. Interactively, prefer the default: it asks once "
            "per process and can remember your answer."
        ),
    )
    parser.add_argument(
        "--allow-system-processes",
        action="store_true",
        help=(
            "lift the built-in denylist of OS/credential processes "
            "(lsass.exe, launchd, systemd, ...). Rarely what you want."
        ),
    )
    parser.add_argument(
        "--scan-batch-bytes",
        type=int,
        default=DEFAULT_SCAN_BATCH_BYTES,
        metavar="BYTES",
        help=(
            "target memory covered between deadline checks during a scan "
            "(default: %(default)s). Smaller means a scan gives up closer to "
            "its time budget, at the cost of more per-batch overhead."
        ),
    )
    parser.add_argument(
        "--max-scan-results",
        type=int,
        default=DEFAULT_MAX_SCAN_RESULTS,
        metavar="N",
        help="addresses one scan may keep (default: %(default)s).",
    )
    parser.add_argument(
        "--max-scan-seconds",
        type=float,
        default=DEFAULT_MAX_SCAN_SECONDS,
        metavar="SECONDS",
        help="wall-clock budget for one scan (default: %(default)s).",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default="stdio",
        help=(
            "MCP transport (default: %(default)s). stdio is what desktop "
            "clients launch. The HTTP transports listen on 127.0.0.1 and carry "
            "no authentication: any local process -- or anyone the port is "
            "forwarded or proxied to -- can read this machine's process "
            "memory through them and answers the attach prompt itself. Writes "
            "over them are refused unless --allow-remote-write is also passed."
        ),
    )
    parser.add_argument(
        "--allow-remote-write",
        action="store_true",
        dest="allow_remote_write",
        help=(
            "keep the write tool registered on an HTTP transport (sse / "
            "streamable-http). Those transports have no authentication, so "
            "without this flag a writable server refuses to start on them: "
            "anyone who can reach the port could change memory on this "
            "machine. Only for a port you control end to end."
        ),
    )
    return parser


def parse_args(
    argv: Optional[Sequence[str]] = None,
) -> Tuple[ServerConfig, Transport]:
    """Parse ``argv`` into a :class:`ServerConfig` and a transport name."""
    args = build_parser().parse_args(argv)

    if args.max_scan_results < 1:
        build_parser().error("--max-scan-results must be at least 1.")
    if args.max_scan_seconds <= 0:
        build_parser().error("--max-scan-seconds must be positive.")
    if args.scan_batch_bytes < 1:
        # 0 or negative makes every region its own batch, so a desktop target
        # with thousands of regions pays thousands of generator setups per
        # scan — and the operator would get no error at launch.
        build_parser().error("--scan-batch-bytes must be at least 1.")

    if args.transport != "stdio" and not args.read_only and not args.allow_remote_write:
        # An HTTP transport is reachable by whoever can reach the port, with
        # nothing in the protocol to say who that is. Reading is already a
        # strong capability to publish; writing is one the operator has to
        # ask for by name.
        build_parser().error(
            "--transport %s serves this machine's memory without "
            "authentication, so writes over it are refused. Pass --read-only, "
            "or --allow-remote-write if the port is one you control end to "
            "end." % args.transport
        )

    # Stripped, not merely tested for blankness: a JSON args array carrying
    # "notepad.exe " (trailing space) would otherwise be stored verbatim, so
    # the substring would match no process at all — the pre-approval silently
    # doing nothing while the operator kept being prompted.
    allowed: List[str] = [
        stripped
        for stripped in (name.strip() for name in args.allowed_processes)
        if stripped
    ]

    config = ServerConfig(
        allow_write=not args.read_only,
        confirm_writes=args.confirm_writes,
        allowed_processes=tuple(allowed),
        allow_any_process=args.allow_any_process,
        allow_system_processes=args.allow_system_processes,
        max_scan_results=args.max_scan_results,
        max_scan_seconds=args.max_scan_seconds,
        scan_batch_bytes=args.scan_batch_bytes,
    )
    # argparse's `choices` already constrains this to the three names; the cast
    # just carries that guarantee into the type system.
    return config, cast(Transport, args.transport)


__all__ = (
    "DEFAULT_MAX_SCAN_RESULTS",
    "Transport",
    "DEFAULT_MAX_SCAN_SECONDS",
    "DEFAULT_SCAN_BATCH_BYTES",
    "ServerConfig",
    "build_parser",
    "parse_args",
)
