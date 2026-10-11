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
make test-fast              # pytest tests -m "not slow"  (~20 s: unit, property and GUI tests)
make test                   # pytest tests -v             (everything, incl. live whole-process scans)
make test-mcp               # pytest tests/mcp_server     (the MCP server suite, ~10 s)
```

`test-fast` is the loop to iterate on; the `slow` and `scan_heavy` markers
(defined in `pyproject.toml`) hold the tests that scan the test process's whole
address space, which takes minutes on CI runners.

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
The library matrix runs Python 3.10–3.13 on Ubuntu and Windows plus a single
Python 3.12 cell on macOS, so all three platform backends are exercised on every
push. Dedicated jobs also run the suite with the `speed` extra (NumPy) to keep
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

## Reporting bugs

Please include:
- Operating system and architecture (e.g. Windows 11 x64, Ubuntu 22.04 x64).
- Python version (`python --version`).
- A minimal reproducer if possible.
- For Linux: whether `/proc/sys/kernel/yama/ptrace_scope` is `0` or `1`.

## Security

If you find a security issue, please see [`SECURITY.md`](https://github.com/JeanExtreme002/PyMemoryEditor/blob/main/SECURITY.md). **Do not** report via GitHub issues.
