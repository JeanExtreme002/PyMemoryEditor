# -*- coding: utf-8 -*-

# The package is expected to be installed in editable mode for tests:
#     pip install -e ".[dev]"
# That makes `import PyMemoryEditor` work without any sys.path manipulation.

import os

try:
    from hypothesis import HealthCheck, settings
except ImportError:  # the `tests` / `dev` extras install it; plain pytest may not
    settings = None


# Hypothesis profiles. Explicit rather than relying on Hypothesis's own CI
# detection, whose built-in `ci` profile only exists in recent releases and
# whose contents are Hypothesis's to change.
#
# `ci` is derandomized so a red CI run is reproducible: the same commit
# explores the same examples on every runner and every re-run, instead of a
# property failing once and passing on retry. `print_blob` puts the
# `@reproduce_failure` line in the log, the database is off (a runner throws
# it away), and the deadline is off because a shared runner's timing says
# nothing about the code. Per-test `@settings(...)` still override these.
#
# Selected with HYPOTHESIS_PROFILE=<name>, or automatically on CI (GitHub
# Actions sets CI=true). Locally the default profile keeps exploring new
# random examples on every run, which is where new failures come from.
if settings is not None:
    settings.register_profile(
        "ci",
        derandomize=True,
        print_blob=True,
        database=None,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    _profile = os.environ.get("HYPOTHESIS_PROFILE") or ("ci" if os.environ.get("CI") else None)
    if _profile:
        settings.load_profile(_profile)


# A test id is not just a label. pytest exports the running one through the
# PYTEST_CURRENT_TEST environment variable, and pytest-xdist addresses its
# workers by it -- so an id built from a large parametrized value is a real
# constraint, not cosmetics. Windows caps an environment variable at 32 767
# characters and raises `ValueError: the environment variable is longer than
# 32767 characters`; on Linux and macOS the same id costs CI wall clock
# instead, because the Actions log uploader took ~150s per 400 KB line.
#
# The mistake is platform-neutral but the failure is Windows-only, so a local
# run on Linux or macOS stays green and only CI tells you. This asserts the
# invariant everywhere: build large values inside the test body, not in
# `parametrize`.
MAX_TEST_ID = 4096


def pytest_collection_modifyitems(items):
    too_long = sorted(
        ((len(item.nodeid), item.nodeid[:120]) for item in items if len(item.nodeid) > MAX_TEST_ID),
        reverse=True,
    )
    if too_long:
        raise RuntimeError(
            "test ids longer than %d characters (they travel through the "
            "environment, which Windows caps at 32767):\n%s"
            % (MAX_TEST_ID, "\n".join("  %d chars: %s..." % row for row in too_long))
        )
