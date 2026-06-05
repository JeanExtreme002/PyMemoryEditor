# Contributing to PyMemoryEditor

Thanks for your interest in contributing!

## Development setup

```bash
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
make install-dev            # pip install -e ".[dev]"
```

The `dev` extra includes `pytest`, `pytest-cov`, `flake8`, `mypy`, `build` and `twine`.

The `Makefile` is the single source of truth for the dev commands below — run
`make help` to see every target (docs, build, coverage, etc.). The raw command
each target wraps is shown in parentheses if you'd rather run it directly.

## Running the test suite

The tests read and write the memory of the test process itself; they should run
on any supported platform without elevated privileges.

```bash
make test                   # pytest tests -v
```

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
The test matrix runs on Ubuntu, Windows and macOS across multiple Python versions, so
all three platform backends are exercised on every push. A dedicated job also
runs the suite with the `speed` extra (NumPy) to keep the vectorized scan path
covered. Even so, contributors touching a specific backend are encouraged to
run `pytest tests` locally on that platform before submitting.

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

## Reporting bugs

Please include:
- Operating system and architecture (e.g. Windows 11 x64, Ubuntu 22.04 x64).
- Python version (`python --version`).
- A minimal reproducer if possible.
- For Linux: whether `/proc/sys/kernel/yama/ptrace_scope` is `0` or `1`.

## Security

If you find a security issue, please see [`SECURITY.md`](https://github.com/JeanExtreme002/PyMemoryEditor/blob/main/SECURITY.md). **Do not** report via GitHub issues.
