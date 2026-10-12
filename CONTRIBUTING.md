# Contributing to PyMemoryEditor

Thanks for your interest in contributing!

## Development setup

```bash
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
make install-dev            # pip install -e ".[dev]"
```

The `dev` extra installs the full toolchain and the GUI deps.

The `Makefile` is the single source of truth for the dev commands below — run
`make help` to see every target (docs, build, coverage, etc.). The raw command
each target wraps is shown in parentheses if you'd rather run it directly.

## Running the test suite

The tests read and write the memory of the test process itself; they should run
on any supported platform without elevated privileges.

```bash
make test-fast              # pytest tests -m "not slow"  (~20 s: unit, GUI and MCP tests)
make test                   # pytest tests -v             (everything, incl. live whole-process scans)
make test-mcp               # pytest tests/mcp_server     (the MCP server suite, ~10 s)
```

`test-fast` is the loop to iterate on; the `slow` and `scan_heavy` markers
(defined in `pyproject.toml`) hold the tests that scan the test process's whole
address space, which takes minutes on CI runners. The scan property tests
(`tests/scan/test_scan_properties.py`) are marked `slow` too, so run them
directly when you touch the scan kernels:

```bash
pytest tests/scan/test_scan_properties.py
```

On CI the Hypothesis tests run under a derandomized `ci` profile (selected
automatically when `CI` is set, or with `HYPOTHESIS_PROFILE=ci`), so a failure
reproduces on re-run; locally they keep exploring new examples.

### Testing one platform

The suite always exercises the backend of the OS it runs on (`win32/`,
`linux/` or `macos/`); tests written for another platform's backend skip
themselves.
So testing a platform means running the suite on it -- locally, in a VM, or
by opening a PR and reading that OS's CI cells. To mirror one CI cell on its
own OS:

```bash
QT_QPA_PLATFORM=offscreen pytest tests --ignore=tests/mcp_server   # build / build-macos
pytest tests/mcp_server -p no:pytest-qt                            # build-mcp (Linux)
pytest tests/mcp_server -p no:pytest-qt -m "not scan_heavy"        # build-mcp (Windows, macOS)
```

`pytest tests/platforms` runs only the platform-specific regression tests;
add `-k linux` (or `win32`, `macos`, `bitness`) to narrow them further. The
`speed` extra (NumPy) switches the scans to the vectorized path, which is what
the `build-speed` and macOS jobs run; leave it out to test the pure-Python one.

`tests/process/test_foreign_process.py` attaches to a child process. On macOS
that needs the `com.apple.security.cs.debugger` entitlement (see below), which
CI runners do not have, so it skips there: run it locally on a signed Python
before changing how the macOS backend opens a foreign task.

## Linting

```bash
make lint                   # flake8 PyMemoryEditor tests
```

## Type checking

```bash
make type-check             # mypy PyMemoryEditor
```

## Before you push

Run lint, type-check and the test suite in one go:

```bash
make pre-commit             # lint + type-check + test
```

The CI pipeline runs the same lint, mypy and tests, and blocks merges on failure.
The library matrix runs Python 3.10–3.15 on Ubuntu and Windows plus Python
3.10, 3.12 and 3.14 on macOS, so all three platform backends are exercised on
every push. Dedicated jobs also run the suite with the `speed` extra (NumPy) to keep
the vectorized scan path covered, and the MCP server suite once per OS. Even so,
contributors touching a specific backend are encouraged to run `pytest tests`
locally on that platform before submitting. `make ci` runs the same lint,
type-check and coverage-gated test invocations the workflow does.

## Project layout

```
PyMemoryEditor/
├── __init__.py          # Public API + platform dispatch
├── enums.py             # ScanTypesEnum (cross-platform)
├── process/             # Abstract base, errors, process info, util
├── util/                # Cross-platform helpers: scan and type conversion
├── win32/               # Windows implementation (kernel32, user32)
├── linux/               # Linux implementation (process_vm_readv/writev, /proc/<pid>/maps)
├── macos/               # macOS implementation (task_for_pid, mach_vm_*)
├── mcp/                 # Model Context Protocol server exposed as `pymemoryeditor-mcp`
└── app/                 # PySide6 (Qt) demo app exposed as `pymemoryeditor` CLI
```

The three platform packages implement `AbstractProcess` from `process/abstract.py`.
The public alias `OpenProcess` is chosen at import time in `__init__.py` based on
`sys.platform`.

### Platform-specific test notes
- **Linux**: requires `/proc/sys/kernel/yama/ptrace_scope=0` to attach to processes
  not descended from the test runner. Self-process tests work without changes.
- **macOS**: opening another process requires the Python binary to be signed with
  the `com.apple.security.cs.debugger` entitlement (or SIP off + root). Self-
  process tests work without changes.
- **Windows**: no special privileges needed for self-process tests.

## Submitting changes

1. Open an issue first for bug reports or substantial features.
2. Branch from `main`. Keep commits focused.
3. Run `make pre-commit` (lint + type-check + tests) locally before pushing.
4. Open a PR describing the change and how it was tested.
5. Give the PR a [Conventional Commits](https://www.conventionalcommits.org/) title,
   e.g. `fix: reject empty search targets` or `docs(mcp): document --allow-write`.
   A required check lints it: the type must be one of `feat`, `fix`, `perf`,
   `refactor`, `revert`, `docs`, `ci`, `build`, `chore`, `test`, `style`, and
   the subject must start lowercase and not end with a period. PRs are
   squash-merged, so the title becomes the commit message on `main`.

## Versioning

PyMemoryEditor follows [Semantic Versioning](https://semver.org/). The public
API is everything documented on Read the Docs, and its *behaviour* counts as
much as its signatures: a call that keeps its name and arguments but returns
a different value, accepts or rejects different input, or touches different
memory is a breaking change.

- **Major** (`4.0.0`): any breaking change, including a behaviour change to a
  documented default -- even when the old behaviour was a bug that someone
  could reasonably depend on (3.0.0's signed 3-byte reads are the model: the
  release notes lead with it, show the before/after and the way back).
- **Minor** (`3.3.0`): new features, and behaviour changes that only reject
  what was memory-unsafe or meaningless before. When a minor release does
  change a default (an opt-out such as `aligned=False` must exist), its
  release notes say **Behaviour change** in bold.
- **Patch** (`3.2.1`): fixes that make the code do what the docs already
  said.

The changelog is the
[GitHub Releases](https://github.com/JeanExtreme002/PyMemoryEditor/releases)
page: describe every user-visible change in the PR so it can be carried into
the release notes.

## Release process

Releases are cut by publishing a GitHub Release; nothing is uploaded from a
laptop.

1. Open a `chore: bump version to X.Y.Z` PR that sets the version in five
   places: `__version__` in `PyMemoryEditor/__init__.py`, the fallback
   `release` in `docs/conf.py`, and in `server.json` both `version` fields
   plus the `PyMemoryEditor[mcp]==X.Y.Z` pin in the package arguments.
   `tests/mcp_server/test_registry.py` fails if the package and `server.json`
   disagree.
2. Merge it and wait for the `Python Package` run on `main` to go green.
3. Publish a GitHub Release with the tag `vX.Y.Z` on that commit; its notes
   are the changelog for the version.
   `.github/workflows/publish.yml` then checks that the tag matches
   `__version__` and that the commit has a green `Python Package` run (it
   waits for one still in progress), builds and `twine check --strict`s the
   distributions, uploads them to PyPI by trusted publishing (no token), and
   lists the version on the MCP Registry.

If the CI gate fails because `main`'s run was cancelled by a later push, run
`gh workflow run python-package.yml --ref vX.Y.Z` and re-run the release
workflow once it is green. `make publish` is a manual fallback for when the
workflow itself is unavailable: it refuses to run outside a clean checkout of
the `v<__version__>` tag, but it uploads by API token and does not update the
MCP Registry.

## Reporting bugs

Please include:
- Operating system and architecture (e.g. Windows 11 x64, Ubuntu 22.04 x64).
- Python version (`python --version`).
- A minimal reproducer if possible.
- For Linux: whether `/proc/sys/kernel/yama/ptrace_scope` is `0` or `1`.

## Security

If you find a security issue, please see [`SECURITY.md`](https://github.com/JeanExtreme002/PyMemoryEditor/blob/main/SECURITY.md). **Do not** report via GitHub issues.
