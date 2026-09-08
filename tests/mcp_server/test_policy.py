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
