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
read-only default made the headline workflow — find a value, change it —
require a flag nobody discovers, which is a bad trade when the protections that
matter are elsewhere. Consent is enforced at the two points where it can
actually be given:

* **which process** — attaching to a target the operator did not pre-approve
  asks the user, live, and the prompt says whether writes are possible
  (:mod:`PyMemoryEditor.mcp.policy`);
* **each write** — ``write_value`` is tagged so a client prompts on every call,
  even in its most permissive auto-approve mode
  (see ``_ALWAYS_ASK`` in :mod:`PyMemoryEditor.mcp.server`).

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
#: 100 000 costs 4.2 MB per result set against 2.1 MB, and 21 ms to sort
#: against 10 ms. The figure that matters is not per set, though: a session
#: keeps ``MAX_SCANS_PER_SESSION`` (20) of them and a server keeps
#: ``MAX_OPEN_SESSIONS`` (8) sessions, so the ceiling on retained addresses
#: goes from ~336 MB to ~672 MB. Reaching it needs 160 capped result sets,
#: which a long refine chain across several targets can do.
#:
#: What it buys: a scan whose true hit count falls between the two ceilings
#: stops being flagged ``partial``, and refining a truncated set can converge
#: on an address that was never in it. That case is real but narrow — above
#: the new ceiling nothing changes, and a common value like ``int 0`` matches
#: millions and is out of reach at any sane cap.
#:
#: What it costs in time depends on the value's density, and an earlier
#: version of this comment got that wrong. Measured on ``int 0``, reaching
#: either ceiling took 0.02s against 0.03s — but that is the dense case, where
#: hits arrive faster than the clock can spend. For a sparser value the scan
#: has to walk further to collect twice as many hits, so the time roughly
#: doubles up to the 30-second budget. "Wall clock is unchanged" was true of
#: one measurement, not of the change.
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
        **On by default** — editing memory is what the library is for, and each
        write is confirmed by the client. Set it off with ``--read-only`` when
        you want the guarantee enforced below this process: the tool then does
        not exist, and on Windows the process handle carries no write rights.
    :param allowed_processes: process names pre-approved so they open without
        prompting — see :class:`~PyMemoryEditor.mcp.policy.ProcessPolicy`.
        Leaving it empty does **not** mean "anything goes": unlisted targets
        prompt the user instead.
    :param allow_any_process: never prompt — open any target the denylist
        permits. For scripted use, where there is nobody to ask.
    :param allow_system_processes: lift the system-process denylist.
    :param max_scan_results: per-scan cap on stored addresses.
    :param max_scan_seconds: per-scan wall-clock budget.
    :param scan_batch_bytes: memory covered per deadline check.

    :raises ValueError: if ``max_scan_results``, ``max_scan_seconds`` or
        ``scan_batch_bytes`` is not positive.

    .. note::
       The three numeric bounds are validated here as well as in
       ``parse_args``, so an embedder constructing this in code gets the same
       answer the CLI operator gets. They used to be checked only at the CLI,
       which meant a config built in Python failed quietly instead of loudly:
       ``scan_batch_bytes=0`` made every region its own scan batch (thousands
       of generator setups per scan on a desktop target), and
       ``max_scan_results=0`` made every scan return nothing while flagging
       itself partial. Neither is unsafe — that is why the process allowlist,
       where a bad value silently disables the consent prompt, was fixed first
       — but both are indistinguishable from a broken server.
    """

    allow_write: bool = True
    allowed_processes: Tuple[str, ...] = field(default=())
    allow_any_process: bool = False
    allow_system_processes: bool = False
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
            "your client confirms every write. Pass --read-only to remove the "
            "write tool entirely, or --allow-process NAME to skip the attach "
            "prompt for a target you already trust."
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
            "its time budget, at the cost of more per-batch overhead. The "
            "field existed and was honoured, but had no flag — so it could "
            "only be set from Python."
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
            "clients launch; the HTTP transports are for remote hosting and "
            "expose this machine's memory to whoever can reach the port."
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

    # Stripped, not merely tested for blankness: a JSON args array carrying
    # "notepad.exe " (trailing space) used to be stored verbatim, so the
    # substring matched no process at all — the pre-approval silently did
    # nothing while the operator kept being prompted.
    allowed: List[str] = [
        stripped
        for stripped in (name.strip() for name in args.allowed_processes)
        if stripped
    ]

    config = ServerConfig(
        allow_write=not args.read_only,
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
