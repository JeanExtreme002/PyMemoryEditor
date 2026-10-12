# -*- coding: utf-8 -*-

"""
Which processes an MCP client is allowed to attach to.

The MCP server hands a language model the capability a debugger has: read —
and, opt-in, write — the memory of another process. Every "may the agent touch
this?" decision lives here, in one place, so the answer never depends on
reading through tool code.

Three outcomes, not two. A target is **allowed** outright, **denied**
outright, or **needs approval** — the last one being what makes the server
usable for work you did not plan in advance. The operator does not have to name
every target at configuration time; an unlisted one simply prompts, and the
answer can be remembered for the rest of the server's life.

Two gates, both applied on every ``open_process``:

1. **The system denylist.** A per-platform set of processes that keep the
   machine running or hold the user's secrets: ``launchd`` / ``kernel_task``
   on macOS, ``systemd`` on Linux, ``lsass.exe`` / ``csrss.exe`` on Windows,
   plus the usual credential agents (``ssh-agent``, ``gpg-agent``, keyrings
   and password managers). Attaching to these is variously impossible (SIP,
   Windows PPL), a way to hang the box, or a way to read secrets — none of it
   is what a memory-editing agent is for. Lifted only by
   ``--allow-system-processes``.

   This list is a convenience guard against the *accidental* target, not an
   inventory of every process that matters: it cannot know which binary holds
   your secrets, and a renamed executable is not on it. It exists so a mistyped
   name or a confused model does not land on ``lsass.exe``.

   Independently of the denylist, the server refuses its **own** process and
   its **ancestors** — the MCP client that launched it, and any launcher in
   between (``uv`` under ``uvx``). No flag lifts that: a model writing into the
   process that enforces its policy, or into the client it is talking through,
   has no legitimate use.

2. **Consent for the target.** A process is opened without asking only if the
   operator pre-approved it (``--allow-process NAME``), it was approved earlier
   in this server's life and the approval was remembered, or the operator
   opted out of prompting entirely (``--allow-any-process``). Anything else
   returns :attr:`AccessDecision.needs_approval`, and the protocol layer asks
   the human before a handle is opened.

   That ordering is the point: consent is a *runtime* decision, so a model that
   has been confused — or prompt-injected by the very memory it just read —
   cannot widen its own reach. It can ask; only the person answers.

Both gates are name-based, and a name is not a security boundary — a PID can be
recycled and an executable can be renamed. The allowlist is a guard rail that
keeps an agent inside the task it was given; it is not a sandbox, and the
server is not a privilege boundary. It runs with exactly the rights of the user
who started it, which is why the denylist exists at all: to make the
*accidental* catastrophe hard, not the deliberate one impossible.
"""

import os
import re
import sys
import threading
from dataclasses import dataclass
from typing import Callable, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from .procinfo import ancestor_pids, process_identity


# Processes never opened unless ``--allow-system-processes`` is passed. Matched
# case-insensitively against the *exact* executable name — substring matching
# would over-block (``init`` would swallow every "…init…" binary the user
# actually wants).
_SYSTEM_PROCESSES: Dict[str, FrozenSet[str]] = {
    "win32": frozenset(
        {
            "system", "system idle process", "registry", "memory compression",
            "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe",
            "msmpeng.exe", "securityhealthservice.exe", "fontdrvhost.exe",
            "dwm.exe",
            # Credential agents and password managers.
            "ssh-agent.exe", "gpg-agent.exe", "keepassxc.exe", "1password.exe",
            "bitwarden.exe", "keepass.exe", "lastpass.exe", "dashlane.exe",
            "enpass.exe",
        }
    ),
    "linux": frozenset(
        {
            "systemd", "init", "kthreadd", "systemd-journald", "systemd-udevd",
            "systemd-logind", "systemd-resolved", "dbus-daemon", "dbus-broker",
            "polkitd", "sshd", "gdm", "gdm3", "gnome-keyring-daemon", "agetty",
            "sudo", "su",
            # Credential agents and password managers.
            "ssh-agent", "gpg-agent", "kwalletd5", "kwalletd6", "keepassxc",
            "1password", "bitwarden", "enpass",
        }
    ),
    "darwin": frozenset(
        {
            "kernel_task", "launchd", "windowserver", "loginwindow",
            "securityd", "secd", "opendirectoryd", "syspolicyd", "trustd",
            "amfid", "coreaudiod", "mds", "mds_stores", "mdworker", "keybagd",
            "sandboxd", "sudo", "su",
            # Credential agents and password managers.
            "ssh-agent", "gpg-agent", "keepassxc", "1password", "bitwarden",
            "1password 7", "keychain access", "lastpass", "dashlane", "enpass",
        }
    ),
}

#: Linux reports process names from ``/proc/<pid>/comm``, which the kernel
#: truncates to this many characters. The denylist carries the truncated form
#: of every longer entry (``gnome-keyring-daemon`` is seen as
#: ``gnome-keyring-d``), and the allowlist / grant matching in
#: :class:`ProcessPolicy` applies the same rule the other way round.
COMM_MAX_LENGTH = 15

_SYSTEM_PROCESSES["linux"] = frozenset(
    _SYSTEM_PROCESSES["linux"]
    | {name[:COMM_MAX_LENGTH] for name in _SYSTEM_PROCESSES["linux"]}
)


# PIDs that are structurally system-owned on every platform: 0 is the kernel /
# idle task, 1 is the init process (``launchd`` / ``systemd``), and 4 is the
# Windows ``System`` process — blocked on every platform rather than only on
# Windows, because a low pid is never a target worth the ambiguity. Checked
# alongside the name denylist because a
# process can be missing a readable name yet still be one of these.
_SYSTEM_PIDS: FrozenSet[int] = frozenset({0, 1, 4})


# Processes that are legitimate targets but routinely hold secrets in memory:
# web browsers (session cookies, saved passwords) and AI / MCP clients (API
# keys, conversation history). They are *not* denied — scanning a browser is
# an ordinary thing to want, and refusing it by default would break that for
# everyone already doing it. Instead the attach prompt warns about them and
# ``list_processes`` flags them, so the user approving one knows what it holds.
# Exact, case-insensitive names, like the denylist.
_SENSITIVE_PROCESSES: Dict[str, FrozenSet[str]] = {
    "win32": frozenset(
        {
            "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
            "vivaldi.exe", "iexplore.exe",
            "claude.exe", "cursor.exe", "windsurf.exe", "code.exe",
        }
    ),
    "linux": frozenset(
        {
            "chrome", "chromium", "chromium-browse", "firefox", "firefox-bin",
            "firefox-esr", "brave", "msedge", "opera", "vivaldi-bin",
            "claude", "cursor", "windsurf", "code",
        }
    ),
    "darwin": frozenset(
        {
            "google chrome", "chromium", "firefox", "safari", "microsoft edge",
            "brave browser", "opera", "vivaldi", "arc",
            "claude", "cursor", "windsurf", "code",
        }
    ),
}

#: Interpreters, shells and runtimes: one executable name shared by unrelated
#: programs. Remembering an approval for ``python3`` *by name* would approve
#: every Python script on the machine, which is not what anyone ticking
#: "remember" for one of them meant — so for these names a remembered approval
#: is scoped to the running instance (pid plus start time) instead. See
#: :meth:`ProcessPolicy.grant`.
_SHARED_RUNTIME = re.compile(
    r"^(?:python(?:w)?(?:\d+(?:\.\d+)*)?t?|pypy\d*(?:\.\d+)*|node(?:js)?|deno|bun"
    r"|java(?:w)?|ruby\d*(?:\.\d+)*|perl\d*(?:\.\d+)*|php\d*(?:\.\d+)*|dotnet"
    r"|mono|lua(?:jit)?\d*(?:\.\d+)*|julia|rscript|osascript|pwsh|powershell"
    r"|cmd|wscript|cscript|bash|sh|zsh|fish|dash|ksh|tcsh|electron"
    r"|wine(?:64)?(?:-preloader)?)(?:\.exe)?$"
)


def is_shared_runtime(name: str) -> bool:
    """Whether ``name`` is an interpreter / runtime many programs run as."""
    return bool(_SHARED_RUNTIME.match((name or "").strip().casefold()))


def _platform_key(platform: str) -> str:
    """Map a ``sys.platform`` string onto a key of :data:`_SYSTEM_PROCESSES`."""
    if platform.startswith("linux"):
        return "linux"
    return platform


def system_process_names(platform: str = sys.platform) -> FrozenSet[str]:
    """The denylisted executable names for ``platform`` (lowercase)."""
    return _SYSTEM_PROCESSES.get(_platform_key(platform), frozenset())


def sensitive_process_names(platform: str = sys.platform) -> FrozenSet[str]:
    """Names that are allowed but warned about: browsers and AI clients."""
    return _SENSITIVE_PROCESSES.get(_platform_key(platform), frozenset())


@dataclass(frozen=True)
class AccessDecision:
    """The outcome of a policy check.

    :param allowed: whether the process may be opened right now, with no
        further questions.
    :param reason: when denied, a message written for the *model* to relay to
        the user — it names the flag that would lift the block, because an
        agent that cannot explain why it was stopped tends to start guessing
        at workarounds instead.
    :param needs_approval: the target is not forbidden, but nobody has consented
        to it yet. The protocol layer must ask the human and, on a yes, retry
        the attach. ``allowed`` is ``False`` here too, so any caller that only
        checks ``allowed`` fails closed rather than silently attaching.
    """

    allowed: bool
    reason: str = ""
    needs_approval: bool = False


def _self_and_ancestor_pids() -> FrozenSet[int]:
    """This process, its parent and every ancestor: what ``protect_self``
    refuses. A function of its own so tests can swap the real chain out."""
    return frozenset({os.getpid(), os.getppid()}) | ancestor_pids()


class ProcessPolicy:
    """Decides whether a given ``(pid, name)`` may be attached to.

    :param allowed_names: pre-approved names — a process is opened without
        asking if its name contains one of these as a case-insensitive
        substring (so ``"game"`` matches ``"game.exe"`` and ``"Game Launcher"``,
        the same forgiving rule as ``OpenProcess(name=..., exact_match=False)``).
    :param allow_system: lift the system denylist.
    :param allow_any: never ask — approve any target the denylist permits. For
        scripted and non-interactive use, where there is nobody to prompt.
    :param protect_self: refuse this process (the server) and every ancestor
        of it — the MCP client that launched it, and anything in between such
        as ``uv`` under ``uvx`` — whatever the other flags say. On by default
        and not exposed as a CLI flag: nothing a model does to the process
        enforcing its own policy, or to the client it speaks through, is a
        legitimate request. Tests that attach to themselves turn it off.
    :param platform: overridable for tests; defaults to the host platform.
    :param identify: ``pid -> start identity`` (``None`` when unknown), used
        to scope a remembered approval to one running instance. Overridable
        for tests; defaults to the per-OS lookup in
        :mod:`~PyMemoryEditor.mcp.procinfo`.

    Instances are consulted from the server's tool threads, so the runtime
    grant set is guarded by a lock.
    """

    def __init__(
        self,
        *,
        allowed_names: Sequence[str] = (),
        allow_system: bool = False,
        allow_any: bool = False,
        protect_self: bool = True,
        platform: str = sys.platform,
        identify: Callable[[int], Optional[int]] = process_identity,
    ) -> None:
        if isinstance(allowed_names, str):
            # A str is a valid Sequence[str], so a scalar would be consumed
            # character by character: `allowed_names="notepad.exe"` would
            # become eleven single-letter rules and pre-approve every process
            # whose name contains any of those letters — silently turning the
            # consent prompt off. A JSON scalar where an array was meant is the natural
            # mistake for exactly the embedder the comment below describes.
            allowed_names = (allowed_names,)

        # Stripped here, not only in `parse_args`: an embedder building a
        # ServerConfig in code — or reading `allowed_processes` straight out of
        # an mcpServers args array, which is the case the CLI comment cites —
        # would otherwise keep the silent no-op that a trailing space causes.
        self._allowed_names: Tuple[str, ...] = tuple(
            stripped
            for stripped in (name.strip().casefold() for name in allowed_names)
            if stripped
        )
        self._allow_system = allow_system
        self._allow_any = allow_any
        self._denied = system_process_names(platform)
        self._sensitive = sensitive_process_names(platform)
        # The whole ancestor chain, not just getppid(): under `uvx` -- the
        # launch command the MCP Registry entry uses -- the parent is `uv`,
        # and the client this protection exists for sits one or two levels
        # further up. Taken once: the chain that launched the server does not
        # change while it runs.
        self._protected: FrozenSet[int] = (
            _self_and_ancestor_pids() if protect_self else frozenset()
        )
        self._identify = identify
        # Only Linux truncates names; applying the rule elsewhere would let a
        # 15-character name stand in for any longer one it happens to prefix.
        self._truncates_names = _platform_key(platform) == "linux"
        self._granted: Set[str] = set()
        # (pid, start identity, folded name): approvals remembered for one
        # running instance of a shared runtime. See grant().
        self._granted_instances: Set[Tuple[int, int, str]] = set()
        self._lock = threading.Lock()

    @property
    def allowed_names(self) -> Tuple[str, ...]:
        return self._allowed_names

    @property
    def allow_system(self) -> bool:
        return self._allow_system

    @property
    def allow_any(self) -> bool:
        return self._allow_any

    @property
    def protected_pids(self) -> FrozenSet[int]:
        """The pids refused unconditionally: this process and its ancestors."""
        return self._protected

    @property
    def granted_names(self) -> Tuple[str, ...]:
        """Names approved at runtime and remembered, oldest ordering not kept."""
        with self._lock:
            return tuple(sorted(self._granted))

    @property
    def granted_instances(self) -> Tuple[Tuple[str, int], ...]:
        """``(name, pid)`` of the running instances approved and remembered."""
        with self._lock:
            return tuple(sorted((name, pid) for pid, _ident, name in self._granted_instances))

    def is_sensitive(self, name: str) -> bool:
        """Whether ``name`` is a browser or AI client: allowed, but warned about."""
        return (name or "").strip().casefold() in self._sensitive

    def identify(self, pid: int) -> Optional[int]:
        """The start identity of ``pid`` (see :mod:`.procinfo`), or ``None``."""
        return self._identify(pid)

    def grant(
        self, name: str, pid: Optional[int] = None, identity: Optional[int] = None
    ) -> Optional[str]:
        """Remember an approval, so this target stops prompting.

        :returns: what was remembered — ``"name"``, ``"instance"``, or
            ``None`` when nothing could be (no name, or an instance whose
            start time cannot be read).

        Name-based rather than pid-based on purpose: "remember this process"
        should survive the target restarting, which is routine when you are
        editing a game between runs.

        Except for a shared runtime (``python3``, ``node``, ``java``, a shell —
        see :func:`is_shared_runtime`) when the caller says which ``pid`` was
        approved: that name is shared by every script on the machine, so
        remembering it would approve all of them. The grant is then scoped to
        that one running instance, keyed by pid *and* start time so a recycled
        pid does not inherit it. A caller that passes no ``pid`` gets the name
        rule it asked for. ``identity`` is the start identity the user was
        shown; without it the current one is read, which may already belong
        to a process that reused the pid.

        Matched **exactly** (case-insensitively), unlike ``allowed_names``.
        That asymmetry is deliberate. An operator typing
        ``--allow-process game`` chose a fragment and means "anything like
        this"; a user clicking *remember* consented to the one concrete process
        in front of them. Storing that as a substring rule would silently widen
        the grant — approving ``game`` would also pre-approve ``endgame`` and
        ``mygame-server``, which nobody agreed to.
        """
        folded = (name or "").casefold()
        if not folded:
            return None
        if pid is not None and is_shared_runtime(folded):
            if identity is None:
                identity = self._identify(pid)
            if identity is None:
                return None
            with self._lock:
                self._granted_instances.add((pid, identity, folded))
            return "instance"
        with self._lock:
            self._granted.add(folded)
        return "name"

    @property
    def mode(self) -> str:
        """How unlisted targets are handled: ``any``, ``allowlist`` or ``ask``."""
        if self._allow_any:
            return "any"
        if self._allowed_names:
            return "allowlist"
        return "ask"

    def _matches(self, folded: str, candidate: str) -> bool:
        """Whether a running process's name ``folded`` satisfies ``candidate``.

        ``candidate`` is an operator allowlist fragment (matched as a
        substring). On Linux a running process's name can be the kernel's
        15-character truncation of its real name, so a candidate that the
        truncated name *prefixes* matches too — otherwise
        ``--allow-process gnome-keyring-daemon`` could never match the
        ``gnome-keyring-d`` the kernel reports, and the pre-approval would
        silently never apply.
        """
        if candidate in folded:
            return True
        return (
            self._truncates_names
            and len(folded) == COMM_MAX_LENGTH
            and candidate.startswith(folded)
        )

    def _instance_granted(self, pid: int, folded: str) -> bool:
        """Whether this running instance was approved and remembered.

        The identity is read only when a grant names this pid and name, so the
        common case costs nothing; and an unreadable identity never matches.
        """
        with self._lock:
            candidates = [
                identity
                for granted_pid, identity, name in self._granted_instances
                if granted_pid == pid and name == folded
            ]
        if not candidates:
            return False
        current = self._identify(pid)
        return current is not None and current in candidates

    def _granted_matches(self, folded: str) -> bool:
        """Whether a remembered approval covers ``folded``. Caller holds the lock.

        Exact, like :meth:`grant` promises — with the same truncation
        allowance as :meth:`_matches`: a name remembered in full still covers
        the truncated form Linux reports for it.
        """
        if folded in self._granted:
            return True
        return (
            self._truncates_names
            and len(folded) == COMM_MAX_LENGTH
            and any(granted.startswith(folded) for granted in self._granted)
        )

    def check(self, pid: int, name: str) -> AccessDecision:
        """Apply both gates to one process."""
        folded = (name or "").casefold()

        if pid in self._protected:
            # Before every other gate, and lifted by none of them: this is the
            # server itself or the client it is talking through.
            return AccessDecision(
                False,
                'Process "%s" (pid %d) is %s and cannot be opened by it. No '
                "flag lifts this — pick a different target."
                % (
                    name or "unknown",
                    pid,
                    "this MCP server's own process"
                    if pid == os.getpid()
                    else "the MCP client that launched this server, or a process "
                    "between it and this server (such as uv)",
                ),
            )

        if not self._allow_system:
            if pid in _SYSTEM_PIDS or folded in self._denied:
                return AccessDecision(
                    False,
                    'Process "%s" (pid %d) is on the system-process denylist and '
                    "cannot be opened. These processes hold credentials or keep "
                    "the machine running. Restart the server with "
                    "--allow-system-processes if you genuinely need this target."
                    % (name, pid),
                )

        if folded:
            if any(self._matches(folded, allowed) for allowed in self._allowed_names):
                return AccessDecision(True)
            with self._lock:
                if self._granted_matches(folded):  # exact: see grant()
                    return AccessDecision(True)
            if self._instance_granted(pid, folded):
                return AccessDecision(True)

        if not folded and not self._allow_system:
            # A name this user cannot read is a name the denylist above could
            # not check — `lsass.exe` and a game look the same from here. So it
            # is never waved through by --allow-any-process: it goes to the
            # human, who can see more than this server can, and a client that
            # cannot ask refuses it. --allow-system-processes is the operator
            # saying the denylist does not matter, so it lifts this too.
            return AccessDecision(
                False,
                "The name of pid %d cannot be read, so this server cannot "
                "check it against the system-process denylist, and it needs "
                "the user's approval even with --allow-any-process. Tell the "
                "user to approve it when prompted, or to restart the server "
                "with --allow-system-processes if they accept opening "
                "unidentified processes." % pid,
                needs_approval=True,
            )

        if self._allow_any:
            return AccessDecision(True)

        # Not forbidden, just not consented to yet. `allowed` stays False so a
        # caller that ignores `needs_approval` refuses instead of attaching.
        return AccessDecision(
            False,
            'Attaching to "%s" (pid %d) needs the user\'s approval, and this '
            "server could not ask for it. Tell the user to approve it when "
            "prompted, or to restart the server with --allow-process %s (to "
            "pre-approve this target) or --allow-any-process (to stop asking "
            "altogether)." % (name, pid, name or "NAME"),
            needs_approval=True,
        )

    def filter(self, processes: Iterable[Tuple[int, str]]) -> List[Tuple[int, str]]:
        """Keep the processes that are not forbidden outright.

        A target awaiting approval still belongs in a listing — hiding it would
        leave the model unable to name what it wants to ask permission for.
        Only denylisted processes are dropped.
        """
        kept: List[Tuple[int, str]] = []
        for pid, name in processes:
            decision = self.check(pid, name)
            if decision.allowed or decision.needs_approval:
                kept.append((pid, name))
        return kept

    def describe(self) -> Dict[str, object]:
        """A JSON-friendly summary, surfaced through the ``server_info`` tool."""
        return {
            "mode": self.mode,
            "mode_note": _MODE_NOTES[self.mode],
            "preapproved": list(self._allowed_names) or None,
            "approved_this_session": list(self.granted_names) or None,
            "approved_instances_this_session": [
                "%s (pid %d)" % (name, pid) for name, pid in self.granted_instances
            ] or None,
            "system_processes_allowed": self._allow_system,
            "denied_system_process_count": len(self._denied),
            "self_protected": bool(self._protected),
        }


#: What each access mode means, written for the model to relay to the user.
_MODE_NOTES = {
    "any": (
        "Any process the denylist permits can be opened without asking. The "
        "operator passed --allow-any-process."
    ),
    "allowlist": (
        "Only pre-approved names open without asking; anything else prompts "
        "the user for approval."
    ),
    "ask": (
        "No target is pre-approved: the user is asked before each new process "
        "is opened. Say which process you want and why when the prompt appears."
    ),
}


__all__ = (
    "AccessDecision",
    "COMM_MAX_LENGTH",
    "ProcessPolicy",
    "is_shared_runtime",
    "sensitive_process_names",
    "system_process_names",
)
