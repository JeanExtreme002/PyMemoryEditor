# -*- coding: utf-8 -*-

"""
The process access gates.

This is the part of the server that decides what an agent can reach, so the
tests are written as statements about that boundary rather than about the
implementation: which processes are refused, which flag lifts each refusal, and
whether a refusal explains itself well enough that a model reports it instead
of hunting for a way around.
"""

import pytest

from PyMemoryEditor.mcp.policy import ProcessPolicy, system_process_names


def not_denied(policy: ProcessPolicy, pid: int, name: str) -> bool:
    """Whether the target is reachable at all — allowed now, or after asking.

    The denylist tests care about this rather than about ``allowed``: in the
    default *ask* mode nothing is allowed outright, so asserting ``allowed``
    would conflate "forbidden" with "needs consent".
    """
    decision = policy.check(pid, name)
    return decision.allowed or decision.needs_approval


class TestSystemDenylist:
    @pytest.mark.parametrize(
        "platform, name",
        [
            ("win32", "lsass.exe"),
            ("win32", "csrss.exe"),
            ("win32", "System"),
            ("linux", "systemd"),
            ("linux", "sshd"),
            ("darwin", "kernel_task"),
            ("darwin", "launchd"),
            ("darwin", "WindowServer"),
        ],
    )
    def test_system_processes_are_denied(self, platform, name):
        policy = ProcessPolicy(platform=platform)
        assert not policy.check(5000, name).allowed

    def test_denial_is_case_insensitive(self):
        policy = ProcessPolicy(platform="win32")
        assert not policy.check(5000, "LSASS.EXE").allowed
        assert not policy.check(5000, "LsAsS.ExE").allowed

    def test_denylist_matches_whole_names_only(self):
        # Substring matching would block a user's own binary for containing
        # "init" or "su" — over-blocking is a real cost, not a safe default.
        policy = ProcessPolicy(platform="linux")
        assert not_denied(policy, 5000, "systemd-inhibit-mygame")
        assert not_denied(policy, 5000, "sudoku")
        assert not_denied(policy, 5000, "initializer")

    @pytest.mark.parametrize("pid", [0, 1, 4])
    def test_structural_system_pids_are_denied_whatever_the_name(self, pid):
        policy = ProcessPolicy(platform="linux")
        assert not policy.check(pid, "game.exe").allowed

    def test_flag_lifts_the_denylist(self):
        policy = ProcessPolicy(platform="darwin", allow_system=True)
        assert not_denied(policy, 1, "launchd")
        # ...and with prompting off as well, it opens outright.
        assert ProcessPolicy(
            platform="darwin", allow_system=True, allow_any=True
        ).check(1, "launchd").allowed

    def test_reason_names_the_flag_that_would_help(self):
        policy = ProcessPolicy(platform="win32")
        reason = policy.check(5000, "lsass.exe").reason
        assert "--allow-system-processes" in reason

    @pytest.mark.parametrize("name", [
        "systemd-journal",   # systemd-journald, truncated by the kernel
        "systemd-resolve",   # systemd-resolved
        "gnome-keyring-d",   # gnome-keyring-daemon
    ])
    def test_names_the_linux_kernel_truncates_are_still_denied(self, name):
        # /proc/<pid>/comm is capped at 15 characters, so exact matching could
        # never deny the three longer entries — including the credential
        # process the module docstring cites as the reason for the denylist.
        decision = ProcessPolicy(platform="linux").check(5000, name)
        assert decision.allowed is False
        assert decision.needs_approval is False

    def test_truncation_does_not_over_block(self):
        # The truncated forms are exact matches too, not prefixes.
        policy = ProcessPolicy(platform="linux")
        assert policy.check(5000, "gnome-keyring-x").needs_approval
        assert policy.check(5000, "systemd-inhibit").needs_approval

    def test_every_platform_has_a_denylist(self):
        for platform in ("win32", "linux", "linux2", "darwin"):
            assert system_process_names(platform), platform

    def test_unknown_platform_denies_nothing_by_name(self):
        assert system_process_names("plan9") == frozenset()


class TestAllowlist:
    def test_absent_allowlist_asks_rather_than_permitting(self):
        # The security default: no pre-approved names does NOT mean anything
        # goes, it means the user is asked at the moment of use.
        policy = ProcessPolicy(platform="linux")
        decision = policy.check(5000, "game.exe")
        assert decision.allowed is False
        assert decision.needs_approval is True

    def test_allowlist_matches_as_a_substring(self):
        policy = ProcessPolicy(allowed_names=["game"], platform="linux")
        assert policy.check(5000, "game.exe").allowed
        assert policy.check(5001, "Game Launcher").allowed
        assert policy.check(5002, "mygame-64").allowed

    def test_allowlist_excludes_everything_else(self):
        policy = ProcessPolicy(allowed_names=["game"], platform="linux")
        assert not policy.check(5000, "chrome").allowed
        assert not policy.check(5001, "").allowed

    def test_several_names_are_all_honoured(self):
        policy = ProcessPolicy(allowed_names=["game", "server"], platform="linux")
        assert policy.check(1000, "game.exe").allowed
        assert policy.check(1001, "server.bin").allowed
        assert not policy.check(1002, "editor").allowed

    def test_allowlist_does_not_override_the_denylist(self):
        # A name matching both gates must still be refused: the allowlist is
        # the operator narrowing the scope, not widening it.
        policy = ProcessPolicy(allowed_names=["lsass"], platform="win32")
        assert not policy.check(5000, "lsass.exe").allowed

    def test_reason_names_both_ways_out(self):
        policy = ProcessPolicy(allowed_names=["game"], platform="linux")
        reason = policy.check(5000, "chrome").reason
        assert "--allow-process" in reason
        assert "--allow-any-process" in reason

    def test_empty_names_are_ignored_rather_than_matching_everything(self):
        # "" is a substring of every string; treating it as a rule would turn
        # `--allow-process ""` into an accidental allow-all.
        policy = ProcessPolicy(allowed_names=["", "game"], platform="linux")
        assert policy.allowed_names == ("game",)
        assert not policy.check(5000, "chrome").allowed


class TestRuntimeGrants:
    """Approvals remembered at runtime, and how far they reach."""

    def test_default_mode_is_ask(self):
        assert ProcessPolicy(platform="linux").mode == "ask"
        assert ProcessPolicy(allowed_names=["g"], platform="linux").mode == "allowlist"
        assert ProcessPolicy(allow_any=True, platform="linux").mode == "any"

    def test_a_grant_stops_the_prompting(self):
        policy = ProcessPolicy(platform="linux")
        assert policy.check(5000, "game.exe").needs_approval
        policy.grant("game.exe")
        assert policy.check(5000, "game.exe").allowed

    def test_a_grant_is_case_insensitive(self):
        policy = ProcessPolicy(platform="linux")
        policy.grant("Game.EXE")
        assert policy.check(5000, "game.exe").allowed

    def test_a_grant_follows_the_name_not_the_pid(self):
        # The point of "remember this process": it survives a restart, which
        # gives the target a new pid.
        policy = ProcessPolicy(platform="linux")
        policy.grant("game.exe")
        assert policy.check(9999, "game.exe").allowed

    def test_a_grant_matches_exactly_and_does_not_widen(self):
        # The user approved one concrete process. Storing that as a substring
        # rule — the way the operator's allowlist works — would silently
        # pre-approve processes nobody consented to.
        policy = ProcessPolicy(platform="linux")
        policy.grant("game")
        assert policy.check(5000, "game").allowed
        for name in ("game.exe", "endgame", "mygame-server"):
            assert policy.check(5001, name).needs_approval, name

    def test_the_operator_allowlist_still_matches_substrings(self):
        # Asymmetric on purpose: a flag typed by hand means "anything like
        # this"; a click on "remember" means "this one".
        policy = ProcessPolicy(allowed_names=["game"], platform="linux")
        assert policy.check(5000, "mygame-server").allowed

    def test_a_grant_cannot_override_the_denylist(self):
        policy = ProcessPolicy(platform="darwin")
        policy.grant("launchd")
        decision = policy.check(9000, "launchd")
        assert decision.allowed is False
        assert decision.needs_approval is False

    def test_granting_an_empty_name_is_ignored(self):
        policy = ProcessPolicy(platform="linux")
        policy.grant("")
        assert policy.granted_names == ()
        assert policy.check(5000, "anything").needs_approval

    def test_describe_reports_what_was_approved(self):
        policy = ProcessPolicy(platform="linux")
        policy.grant("game.exe")
        described = policy.describe()
        assert described["mode"] == "ask"
        assert described["approved_this_session"] == ["game.exe"]


class TestFilterAndDescribe:
    def test_filter_drops_denied_entries_but_keeps_askable_ones(self):
        # A target awaiting approval belongs in a listing: hiding it would
        # leave the model unable to name what it wants permission for.
        policy = ProcessPolicy(platform="linux")
        kept = policy.filter([(1, "systemd"), (5000, "game.exe"), (5001, "sshd")])
        assert kept == [(5000, "game.exe")]

    def test_describe_reports_the_live_policy(self):
        policy = ProcessPolicy(allowed_names=["game"], platform="linux")
        described = policy.describe()
        assert described["mode"] == "allowlist"
        assert described["preapproved"] == ["game"]
        assert described["system_processes_allowed"] is False
        assert described["denied_system_process_count"] > 0


class TestSelfProtection:
    """The server never opens itself or the client that launched it."""

    @pytest.fixture(params=["self", "parent"])
    def protected_pid(self, request):
        import os

        return os.getpid() if request.param == "self" else os.getppid()

    def test_refused_by_default(self, protected_pid):
        decision = ProcessPolicy(platform="linux").check(protected_pid, "python")
        assert decision.allowed is False
        assert decision.needs_approval is False
        assert "No flag lifts this" in decision.reason

    def test_no_flag_lifts_it(self, protected_pid):
        # allow_any and allow_system each lift one of the two ordinary gates;
        # neither reaches this one, and nor does a remembered approval.
        policy = ProcessPolicy(platform="linux", allow_any=True, allow_system=True)
        policy.grant("python")
        assert policy.check(protected_pid, "python").allowed is False

    def test_the_allowlist_does_not_lift_it(self, protected_pid):
        policy = ProcessPolicy(allowed_names=["python"], platform="linux")
        assert policy.check(protected_pid, "python3").allowed is False

    def test_the_reason_says_which_one_it_is(self):
        import os

        policy = ProcessPolicy(platform="linux")
        assert "server's own process" in policy.check(os.getpid(), "x").reason
        assert "client that launched" in policy.check(os.getppid(), "x").reason

    def test_opting_out_is_explicit(self, protected_pid):
        # Only for a caller that *is* the target — the test suite attaching to
        # itself. There is no CLI flag for it.
        policy = ProcessPolicy(platform="linux", allow_any=True, protect_self=False)
        assert policy.check(protected_pid, "python").allowed is True
        assert policy.protected_pids == frozenset()

    def test_filter_hides_them(self):
        import os

        policy = ProcessPolicy(platform="linux", allow_any=True)
        kept = policy.filter([(os.getpid(), "python"), (5000, "game.exe")])
        assert kept == [(5000, "game.exe")]

    def test_describe_reports_it(self):
        assert ProcessPolicy(platform="linux").describe()["self_protected"] is True
        assert (
            ProcessPolicy(platform="linux", protect_self=False).describe()["self_protected"]
            is False
        )


class TestCredentialAgentsAreDenied:
    @pytest.mark.parametrize(
        "platform, name",
        [
            ("linux", "ssh-agent"),
            ("linux", "gpg-agent"),
            ("linux", "kwalletd6"),
            ("linux", "keepassxc"),
            ("darwin", "ssh-agent"),
            ("darwin", "secd"),
            ("darwin", "1Password"),
            ("win32", "ssh-agent.exe"),
            ("win32", "KeePassXC.exe"),
            ("win32", "Bitwarden.exe"),
        ],
    )
    def test_denied(self, platform, name):
        decision = ProcessPolicy(platform=platform).check(5000, name)
        assert decision.allowed is False
        assert decision.needs_approval is False


class TestTruncatedNamesMatchTheAllowlist:
    """The mirror of the denylist's truncation rule.

    Linux reports ``gnome-keyring-daemon`` as ``gnome-keyring-d``; an operator
    types the full name. Substring matching alone could never pre-approve it.
    """

    def test_a_full_name_pre_approves_its_truncated_form(self):
        policy = ProcessPolicy(
            allowed_names=["my-very-long-game-name"], platform="linux"
        )
        assert policy.check(5000, "my-very-long-ga").allowed is True

    def test_a_remembered_full_name_covers_its_truncated_form(self):
        policy = ProcessPolicy(platform="linux")
        policy.grant("my-very-long-game-name")
        assert policy.check(5000, "my-very-long-ga").allowed is True

    def test_only_a_name_of_exactly_the_truncation_width_qualifies(self):
        # A shorter name was not truncated, so prefixing an allowed name means
        # nothing — "game" must not match "game-launcher-helper" by prefix.
        policy = ProcessPolicy(allowed_names=["game-launcher-helper"], platform="linux")
        assert policy.check(5000, "game-launcher").needs_approval is True

    def test_other_platforms_do_not_truncate(self):
        # macOS and Windows report full names, so a 15-character name that
        # happens to prefix an allowed one is a different process.
        policy = ProcessPolicy(allowed_names=["my-very-long-game-name"], platform="darwin")
        assert policy.check(5000, "my-very-long-ga").needs_approval is True


class TestTheWholeLaunchChainIsProtected:
    """Under ``uvx`` the server's parent is ``uv``; the client is further up."""

    def test_every_ancestor_is_protected(self):
        from PyMemoryEditor.mcp.procinfo import ancestor_pids

        policy = ProcessPolicy(platform="linux")
        assert ancestor_pids() <= policy.protected_pids
        for pid in ancestor_pids():
            decision = policy.check(pid, "uv")
            assert decision.allowed is False and decision.needs_approval is False
            assert "client that launched" in decision.reason

    def test_a_grandparent_is_found(self):
        # Our own child: its ancestors are this process and everything above
        # it, so the chain must reach past one level.
        import os
        import subprocess
        import sys

        from PyMemoryEditor.mcp.procinfo import ancestor_pids, parent_pid

        if parent_pid(os.getpid()) is None:
            pytest.skip("no parent lookup on this platform")
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"]
        )
        try:
            chain = ancestor_pids(child.pid)
            assert os.getpid() in chain
            if os.getppid() > 1:
                assert os.getppid() in chain
        finally:
            child.kill()
            child.wait()

    def test_the_parent_lookup_agrees_with_the_os(self):
        import os

        from PyMemoryEditor.mcp.procinfo import parent_pid, process_identity

        found = parent_pid(os.getpid())
        if found is None:
            pytest.skip("no parent lookup on this platform")
        assert found == os.getppid()
        assert process_identity(os.getpid()) == process_identity(os.getpid())

    def test_a_missing_process_reads_as_unknown(self):
        from PyMemoryEditor.mcp.procinfo import ancestor_pids, parent_pid, process_identity

        assert parent_pid(2**31 - 1) is None
        assert process_identity(2**31 - 1) is None
        assert ancestor_pids(2**31 - 1) == frozenset()

    def test_a_parent_younger_than_its_child_is_not_followed(self, monkeypatch):
        # Windows keeps a dead parent's id, which can since belong to a
        # stranger; that stranger started after the child, and is not ours.
        from PyMemoryEditor.mcp import procinfo

        parents = {500: 400, 400: 300, 300: 1}
        started = {500: 50, 400: 40, 300: 99}
        monkeypatch.setattr(procinfo, "parent_pid", parents.get)
        monkeypatch.setattr(procinfo, "start_identity", started.get)
        assert procinfo.ancestor_pids(500) == frozenset({400})

    def test_a_non_utf8_linux_name_does_not_end_the_walk(self, monkeypatch):
        # comm is whatever the process set (prctl PR_SET_NAME); decoding the
        # whole stat line as text raised, read as "unknown", and left every
        # ancestor above it -- the MCP client -- unprotected.
        import builtins
        import io

        from PyMemoryEditor.mcp import procinfo

        stat = b"4242 (\xff\xfe odd) name) S 77 4242 77 0 -1 4194560 " + b"0 " * 12 + b"123456 0\n"
        real_open = builtins.open

        def fake_open(path, mode="r", *args, **kwargs):
            if path == "/proc/4242/stat":
                if "b" not in mode:  # what the old text-mode read did
                    return io.TextIOWrapper(io.BytesIO(stat), encoding="utf-8")
                return io.BytesIO(stat)
            return real_open(path, mode, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", fake_open)
        fields = procinfo._linux_stat_fields(4242)
        assert fields is not None
        assert fields[0] == "S" and fields[1] == "77"  # state, ppid
        assert fields[19] == "123456"  # starttime (field 22)

    def test_a_cycle_terminates(self, monkeypatch):
        from PyMemoryEditor.mcp import procinfo

        monkeypatch.setattr(procinfo, "parent_pid", {10: 20, 20: 10}.get)
        monkeypatch.setattr(procinfo, "start_identity", lambda pid: None)
        assert procinfo.ancestor_pids(10) == frozenset({20})


class TestUnreadableNames:
    """A name the server cannot read is one the denylist cannot check."""

    def test_allow_any_still_asks(self):
        decision = ProcessPolicy(platform="linux", allow_any=True).check(5000, "")
        assert decision.allowed is False
        assert decision.needs_approval is True
        assert "--allow-system-processes" in decision.reason

    def test_the_allowlist_does_not_cover_it(self):
        policy = ProcessPolicy(allowed_names=["game"], allow_any=True, platform="linux")
        assert policy.check(5000, "").needs_approval is True

    def test_lifting_the_denylist_lifts_this_too(self):
        policy = ProcessPolicy(platform="linux", allow_any=True, allow_system=True)
        assert policy.check(5000, "").allowed is True

    def test_a_readable_name_is_unaffected(self):
        assert ProcessPolicy(platform="linux", allow_any=True).check(5000, "game").allowed


class TestRememberingASharedRuntime:
    """Remembering ``python3`` by name would approve every Python script."""

    def _policy(self, identities):
        return ProcessPolicy(platform="linux", identify=identities.get)

    @pytest.mark.parametrize("name", [
        "python3", "Python", "python3.12", "pythonw.exe", "node", "node.exe",
        "java", "javaw.exe", "dotnet", "bash", "pwsh.exe", "ruby", "Electron",
    ])
    def test_runtimes_are_recognised(self, name):
        from PyMemoryEditor.mcp.policy import is_shared_runtime

        assert is_shared_runtime(name)

    @pytest.mark.parametrize("name", ["game.exe", "pythonista", "nodejs-game", "javagame"])
    def test_ordinary_names_are_not(self, name):
        from PyMemoryEditor.mcp.policy import is_shared_runtime

        assert not is_shared_runtime(name)

    def test_the_grant_covers_only_that_instance(self):
        policy = self._policy({5000: 111, 5001: 222})
        assert policy.grant("python3", pid=5000) == "instance"
        assert policy.check(5000, "python3").allowed is True
        assert policy.check(5001, "python3").needs_approval is True
        assert policy.granted_names == ()
        assert policy.granted_instances == (("python3", 5000),)

    def test_a_recycled_pid_does_not_inherit_it(self):
        identities = {5000: 111}
        policy = self._policy(identities)
        policy.grant("node", pid=5000)
        identities[5000] = 999  # the pid now belongs to a new process
        assert policy.check(5000, "node").needs_approval is True

    def test_an_unknown_identity_is_not_remembered(self):
        policy = self._policy({})
        assert policy.grant("python3", pid=5000) is None
        assert policy.check(5000, "python3").needs_approval is True

    def test_other_names_are_still_remembered_by_name(self):
        policy = self._policy({})
        assert policy.grant("game.exe", pid=5000) == "name"
        assert policy.check(9999, "game.exe").allowed is True

    def test_a_grant_without_a_pid_keeps_the_name_rule(self):
        # The embedder API: grant(name) still means what it always meant.
        policy = self._policy({})
        assert policy.grant("python3") == "name"
        assert policy.check(9999, "python3").allowed is True

    def test_describe_reports_instances(self):
        policy = self._policy({5000: 1})
        policy.grant("python3", pid=5000)
        assert policy.describe()["approved_instances_this_session"] == ["python3 (pid 5000)"]


class TestSensitiveTargets:
    """Browsers and AI clients are allowed, but flagged."""

    @pytest.mark.parametrize("platform, name", [
        ("darwin", "Google Chrome"),
        ("darwin", "Claude"),
        ("win32", "msedge.exe"),
        ("linux", "firefox"),
        ("linux", "chromium-browse"),  # chromium-browser, truncated
    ])
    def test_flagged_but_not_denied(self, platform, name):
        policy = ProcessPolicy(platform=platform)
        assert policy.is_sensitive(name)
        assert policy.check(5000, name).needs_approval is True
        assert ProcessPolicy(platform=platform, allow_any=True).check(5000, name).allowed

    def test_ordinary_targets_are_not_flagged(self):
        assert not ProcessPolicy(platform="win32").is_sensitive("game.exe")


class TestMorePasswordManagersAreDenied:
    @pytest.mark.parametrize("platform, name", [
        ("win32", "KeePass.exe"),
        ("win32", "LastPass.exe"),
        ("darwin", "Keychain Access"),
        ("darwin", "1Password 7"),
        ("darwin", "Dashlane"),
        ("linux", "enpass"),
    ])
    def test_denied(self, platform, name):
        decision = ProcessPolicy(platform=platform).check(5000, name)
        assert decision.allowed is False and decision.needs_approval is False
