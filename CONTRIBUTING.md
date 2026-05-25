# Contributing to PyMemoryEditor

Thanks for your interest in contributing!

## Development setup

```bash
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

The `dev` extra includes `pytest`, `pytest-cov`, `flake8`, `mypy`, `build` and `twine`.

## Running the test suite

The tests read and write the memory of the test process itself; they should run
on any supported platform without elevated privileges.

```bash
pytest tests -v
```

## Linting

```bash
flake8 PyMemoryEditor tests
```

## Type checking

```bash
mypy PyMemoryEditor
```

The CI pipeline runs lint, mypy and tests, and blocks merges on failure.
macOS is intentionally not included in CI (free-tier runner congestion);
contributors with macOS hardware should run `pytest tests` locally before
submitting changes that touch the Mach backend.

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
3. Run lint + tests locally before pushing.
4. Open a PR describing the change and how it was tested.

## Reporting bugs

Please include:
- Operating system and architecture (e.g. Windows 11 x64, Ubuntu 22.04 x64).
- Python version (`python --version`).
- A minimal reproducer if possible.
- For Linux: whether `/proc/sys/kernel/yama/ptrace_scope` is `0` or `1`.

## Security

If you find a security issue, please see [`SECURITY.md`](SECURITY.md). **Do not** report via GitHub issues.
