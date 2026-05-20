# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- New `PyMemoryEditor.process.scanning.iter_search_results` helper owns the
  per-region / per-chunk scanning loop (filter regions → walk chunks → run
  the comparator → emit `(address[, progress])`). Win32, Linux and macOS
  `search_addresses_by_value` now delegate to it — removing ~150 LOC of
  duplication. The promise in `process/scanning.py`'s module docstring is
  finally implemented.
- `iter_search_results` reads `bufflength - 1` overlap bytes from the next
  chunk when scanning strings, so a match that straddles a chunk boundary
  on multi-GB regions is decoded correctly. Numeric scans are unaffected
  (their alignment already guarantees no straddle).
- Linux `process_vm_readv` / `process_vm_writev` bindings now declare
  `argtypes` explicitly. Previously only `restype` was set; on builds where
  the default C-int width is narrower than the pointer representation,
  ctypes could silently truncate iovec pointers before the kernel saw them
  — the same class of bug fixed in the Win32 backend during v2.

### Added
- `tests/test_scan_properties.py`: hypothesis-driven property tests that
  cross-validate the fast `struct.iter_unpack` path against a reference
  slow path for every ordered scan_type, over both signed integers and
  IEEE-754 floats. Catches inlining typos in the eight per-scan-type
  branches that the example-based suite can miss.
- `tests/test_str_boundary.py`: regression tests for the chunk-overlap fix
  above (straddling match found, in-chunk match not duplicated).
- `tests/test_app_smoke.py`: smoke tests for the Qt app — version flag,
  module imports, and (when `pytest-qt` is available) constructing the
  full `MainWindow` and `CheatTable` against a self-PID process.
- `docs/` Sphinx scaffold (`conf.py`, `index.rst`, `getting_started.rst`,
  `api.rst`, `platform_notes.rst`) plus `.readthedocs.yaml`. Publishable
  by wiring the repo to readthedocs.org; builds locally with
  `pip install -e ".[docs]" && sphinx-build -b html docs docs/_build/html`.
- `.github/workflows/release.yml`: tag-driven release pipeline that builds
  sdist + wheel, validates with `twine check --strict`, and uploads to
  PyPI via OIDC trusted-publishing (no long-lived secret).
- CI: `security-audit` job (continue-on-error during ramp-up) runs
  `pip-audit --strict` on every PR. Promote to a required check once the
  workflow has been quiet for a release cycle.
- `dev` extra now includes `pytest-qt`, `hypothesis`, and `PySide6` so a
  single `pip install -e ".[dev]"` provisions everything tests need.
- `docs` extra (`sphinx`, `sphinx-rtd-theme`) for the documentation build.

### Fixed
- Critical: `scan_memory` ordering comparisons (`BIGGER_THAN`, `SMALLER_THAN`,
  `VALUE_BETWEEN`, ...) on signed `int` values used to compare against the
  unsigned reinterpretation of the encoded bytes (e.g. `-1` was treated as
  `0xFFFFFFFF`), so "bigger than `-1`" never matched. Same problem affected
  `float` scans, which were ordered by their integer bit-pattern (so `-1.0f`
  appeared greater than `1.0f`). The scan now dispatches per `pytype` to use
  signed `struct b/h/i/q` for ints and IEEE-754 `struct f/d` for floats.
  Tests in `tests/test_scan.py` cover negative integers and floats.
- Win32: `kernel32`/`user32` are now loaded with
  `ctypes.WinDLL(..., use_last_error=True)`. The previous
  `ctypes.windll.LoadLibrary(...)` left `ctypes.get_last_error()` at zero, so
  every failure surfaced as `OSError: <api> failed.` without the underlying
  Win32 error code — the `WinError(code, ...)` branch in `_raise_last_error`
  was effectively dead.
- Linux: `MEMORY_BASIC_INFORMATION.Privileges` / `.Path` were `c_char_p`
  pointers tied to the lifetime of the originating Python `bytes` objects.
  Reading the struct after those bytes were GC'd was undefined behavior.
  Both fields are now fixed-size inline `c_char * N` arrays so the struct
  owns the storage.
- `search_by_addresses` now yields `(address, None)` for addresses that fall
  in gaps between memory regions, and for values whose
  `[address, address+bufflength)` would extend past the containing region.
  The previous per-backend code silently dropped gap-addresses and
  zero-padded reads that overflowed the last chunk.
- macOS: `_PAGE_GONE_KRS` now includes `KERN_NO_ACCESS` and
  `KERN_INVALID_ARGUMENT` so guard-page and freshly-unmapped-page reads
  during a scan are skipped rather than aborting the scan.
- App: `value_types.parse_value(str, ...)` used character count as the byte
  length; multi-byte UTF-8 strings (accents, CJK) were truncated. It now
  uses `len(value.encode("utf-8"))`.
- Win32: `ReadProcessMemory` now raises `OSError` when the kernel reports a
  partial read (`bytes_read < bufflength`). Previously a truncated read on
  a boundary-crossing region populated a buffer of mixed real-bytes-and-zeros
  that downstream decoding would silently treat as valid. Mirrors the
  existing partial-write check in `WriteProcessMemory`.
- Win32: `WindowsProcess.close()` no longer silently returns `False` when
  `CloseHandle` fails. It now raises `WinError`/`OSError` (with the actual
  Win32 code, courtesy of the `use_last_error=True` fix above) and the
  object is marked closed so subsequent `close()` calls don't retry against
  a handle the kernel already released.

### Changed
- New `PyMemoryEditor.process.region` module owns cross-platform region
  introspection. `get_memory_regions()` now enriches each yielded dict with
  `is_readable`, `is_writable`, `is_executable`, `is_shared` and `path`
  keys, so portable client code no longer has to introspect the
  per-platform `struct` field. The Qt app's `memory_map_dialog` uses these
  directly.
- New `PyMemoryEditor.process.scanning.iter_values_for_addresses` helper
  owns the chunking / boundary / gap-handling logic shared by all three
  backends. `search_by_addresses` on Win32, Linux and macOS now delegates
  to it — removing ~200 LOC of copy-paste and fixing the gap/truncation
  bugs in one place.
- Win32 enums (`ProcessOperationsEnum`, `MemoryProtectionsEnum`,
  `MemoryTypesEnum`, `MemoryAllocationStatesEnum`,
  `StandardAccessRightsEnum`) migrated from `Enum` to `IntFlag` so members
  compose with `|` and bitmask comparisons work without `.value`
  unwrapping. `PROCESS_ALL_ACCESS` bumped from the pre-Vista value
  `0x1F0FFF` to the modern `0x1FFFFF` (PyMemoryEditor targets Python 3.8+,
  which already required Vista or later).
- App `CheatTable` now runs its 10 Hz read/freeze loop on a background
  `QThread` (`_CheatPollWorker`); the UI receives values via a queued
  signal and never blocks on `read_process_memory`/`write_process_memory`.
- App `MemoryMapDialog` now runs `snapshot_memory_regions()` on a
  `_SnapshotWorker` thread — previously a refresh on a heavy target
  (browser, JVM with 100k regions) could freeze the dialog for seconds.
- App `OpenProcessDialog` enumerates processes via `_ProcessListWorker`
  off the UI thread on every 3 s auto-refresh.
- macOS: `MacProcess.__del__` calls `close()` best-effort so a leaked
  reference doesn't hold the target's task port forever. Context-manager
  usage is still preferred.
- App `application.main(argv=None)` accepts an explicit argv list — the
  previous signature collected positional args but ignored them.
- CI: mypy is now a required gate (`continue-on-error` removed). pytest
  enforces `--cov-fail-under=60` (the library code currently sits ~73%
  on a single platform — only one backend per matrix job is exercised, so
  the bar starts conservative). `-s -x` removed from pytest so the matrix
  reports clusters of failures instead of stopping on the first one.
- Makefile `security` target replaced `safety` (now paid/registered) with
  `pip-audit`. `install-dev` no longer redundantly re-installs `pytest-cov`
  and `mypy` (already in the `[dev]` extra).

### Added
- `process.snapshot_memory_regions()` materializes the region list so callers
  can reuse it across multiple scans without paying the enumeration cost each
  time. `search_by_value`, `search_by_value_between` and `search_by_addresses`
  now accept a `memory_regions=` keyword to consume the snapshot. Recommended
  for "scan → refine → refine" workflows.
- `bufflength` is now optional for numeric types: pass `None` (or omit on
  reads) to use the default — `int → 4`, `float → 8`, `bool → 1`. `str` and
  `bytes` continue to require an explicit length. Both reads and writes accept
  the inferred default.
- `util.value_to_bytes` / `util.values_to_bytes` helpers consolidate the
  per-backend conversion of scan target values to fixed-width byte strings,
  removing ~30 lines of duplication across `win32`, `linux` and `macos`.
- `tests/test_bufflength_inference.py`, `tests/test_region_snapshot.py` and
  `tests/test_str_decode_consistency.py` cover the new behavior cross-platform.
- CI now runs `mypy` on the package and reports coverage via `pytest-cov`.
- `SECURITY.md` on the repo root surfaces the private advisory channel for
  GitHub UI.
- Type-checker-friendly `OpenProcess` alias: the cross-platform `Union` is
  exposed under `TYPE_CHECKING` so IDEs/pyright see every backend's signature
  (including Windows-only `permission=`) regardless of the host OS.

### Changed
- `WindowsProcess` default `permission` now bundles
  `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` instead of `PROCESS_VM_READ`
  alone. Without `PROCESS_QUERY_INFORMATION`, `VirtualQueryEx` returns 0 and
  every `get_memory_regions`/`search_by_value*`/`snapshot_memory_regions`
  call comes back empty — so the minimal usable read-only set is both bits.
- `scan_memory` numeric fast path uses a `memoryview` instead of materializing
  a `bytes` copy of the chunk, avoiding an extra 256 MB copy per chunk in the
  hot path.
- `tests/conftest.py` no longer manipulates `sys.path`. The package must be
  installed in editable mode (`pip install -e ".[dev]"`).
- Cheat-table UI (Qt app) batches the 10 Hz refresh through
  `search_by_addresses` when entries share the same `(pytype, length)` —
  collapses N syscalls into chunked reads at the page level.

### Fixed
- Critical: `ProcessOperationsEnum.PROCESS_TERMINATE` was `0x0800`, the same
  value as `PROCESS_SUSPEND_RESUME`, making it a silent alias under Python's
  Enum semantics. Corrected to `0x0001` per MSDN. Callers that requested
  termination permission were getting suspend/resume instead.
- `read_process_memory(addr, str, n)` now decodes with `errors="replace"`,
  matching `convert_from_byte_array` (used by `search_by_addresses`). The same
  raw bytes used to raise `UnicodeDecodeError` on one path and succeed on the
  other.
- `scan_memory_for_exact_value` with `NOT_EXACT_VALUE` was O(n × m) — for each
  candidate offset it walked the full match list to check overlap. Now uses
  `bisect_left` over the (already sorted) match positions, dropping the inner
  step to O(log m). Practical win on multi-match scans of large regions.
- `search_by_addresses` now treats an explicitly-empty `memory_regions=[]` as
  "scan nothing", matching `search_by_value*`. Previously the truthy check
  silently re-enumerated the full address space when the caller passed an
  empty pre-filtered list.
- Win32 `WriteProcessMemory` now raises `OSError` when the kernel reports a
  partial write (`bytes_written < bufflength`). Previously a truncated write
  to a boundary-crossing region returned silently as success.
- macOS write-via-protect-flip path now emits a `ResourceWarning` when the
  `mach_vm_protect` restore step fails — the page in the target task is left
  more permissive than it started. The write itself still succeeds; this
  surfaces an otherwise invisible side-effect.
- `tests/test_chunking_integration.py::test_iter_region_chunks_unaligned_target`
  rewrote vacuous assertion (the previous expression accidentally compared
  the loop variables to themselves and always evaluated true).

### Docs
- `README.md`: fixed broken link to `ScanTypesEnum` (was pointing to a
  non-existent `win32/enums/scan_types.py`).
- `CONTRIBUTING.md`: added the `macos/` package to the project layout and a
  per-platform test-requirement note.
- `Makefile`: replaced references to the removed `requirements.txt` with
  `pip install -e ".[dev]"`. `install-deps`, `install-dev` and `update-deps`
  now work out-of-the-box.

### CI
- Test matrix now also includes Python 3.13.

## [2.0.0] - 2026-05-18

### Breaking changes
- `WindowsProcess.__init__` now defaults `permission` to `PROCESS_VM_READ` instead
  of `PROCESS_ALL_ACCESS`. Callers that write to memory must explicitly request
  `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION` (or a wider mask).
- Permission checks now use bitmask testing. Composing flags with bitwise OR is
  supported; passing flags that don't include the required bit will raise
  `PermissionError` cleanly.
- `get_process_id_by_process_name` now raises `AmbiguousProcessNameError` when
  more than one process matches the name. Use `get_process_ids_by_process_name`
  to retrieve the full list explicitly.
- The unused `PyMemoryEditor.linux.ptrace` package and the
  `PyMemoryEditor.util.search` package (KMP/BMH implementations) have been
  removed. They were not used in the scan code path.
- Python 3.6 and 3.7 are no longer supported. Minimum is now 3.8.

### Added
- **macOS support** via the Mach VM APIs (`task_for_pid`,
  `mach_vm_read_overwrite`, `mach_vm_write`, `mach_vm_region`). Opening the
  current process works without entitlements; opening other processes requires
  the Python binary to be signed with `com.apple.security.cs.debugger` (or SIP
  disabled and running as root). `window_title` lookup is not supported on
  macOS.
- Windows: `MEMORY_BASIC_INFORMATION` layout is now selected per target
  process via `IsWow64Process`, so 64-bit Python attached to a 32-bit (WOW64)
  target reads region info correctly. Previously the layout followed the
  host's bitness and corrupted fields when the bitnesses differed.
- Cross-platform `iter_region_chunks` helper. All three backends read memory
  regions in 256 MB chunks (aligned to `target_value_size`) so scanning a
  multi-GB region — e.g. a browser or JVM — no longer risks OOM in the
  scanner process. Both `search_by_value*` and `search_by_addresses` use this
  helper; chunks adjacent to a boundary read `bufflength - 1` extra bytes so
  values straddling the boundary are decoded correctly.
- `LinuxProcess` and `MacProcess` now accept (and silently ignore) the
  `permission` parameter, so cross-platform code can pass it without
  branching.
- `OpenProcess` accepts `case_sensitive=False` for `process_name` matching
  (default `False` on Windows, `True` elsewhere — matches OS conventions).
- `PyMemoryEditorError` base class for all library exceptions.
- `AmbiguousProcessNameError` for resolving processes by name when multiple
  match.
- `py.typed` marker so type checkers consume the bundled type hints.
- `__all__` declared on the package.
- Performance: numeric scans (`BIGGER_THAN`, `SMALLER_THAN`, `VALUE_BETWEEN`,
  ...) decode via `struct.iter_unpack` for sizes 1/2/4/8 bytes, with the
  comparison loop inlined per scan_type to eliminate generator and
  tuple-unpacking overhead. **~6–8× faster** than the pre-inline version on
  multi-million-iteration scans.
- macOS `write_process_memory` on a read-only page now transparently elevates
  the page protection via `mach_vm_protect`, performs the write, and restores
  the original protection. Matches the practical behavior of
  `WriteProcessMemory` on Windows.
- CI: runs `flake8` in addition to `pytest`, and includes `macos-latest` in
  the test matrix (3 OSes × 5 Python versions).
- Test files: `test_scan.py`, `test_errors.py`, `test_linux_types.py`
  (Linux-only regressions for 64-bit fields), `test_macos_protect.py`
  (macOS-only regression for protect-flip), `test_win32_permissions.py`
  (Win32-only regression for permission gate logic),
  `test_process_lookup.py` (cross-platform mock-based coverage of
  `AmbiguousProcessNameError` and the `case_sensitive` flag), and
  `test_chunking_integration.py` (covers chunking boundaries, the
  fast-path/slow-path of `iter_region_chunks`, and a Win32-only mock of
  `IsWow64Process` to validate `mbi_class_for_handle`).

### Fixed
- Critical: platform detection no longer matches `darwin` ("win" is a
  substring of "darwin"). The package uses `sys.platform == "win32"` and
  explicitly raises `ImportError` on unsupported platforms.
- Critical: `ReadProcessMemory`, `WriteProcessMemory`, `OpenProcess`, and
  `process_vm_readv/writev` calls now set `argtypes`/`restype` and check
  their return value, raising `OSError` on failure instead of silently
  returning zeroed buffers. Previously, failed reads returned `0`
  indistinguishable from real reads.
- Critical: `scan_memory` no longer skips the last value of each region
  (off-by-one in `range(... - target_value_size)`).
- Critical: `scan_memory_for_exact_value` with `NOT_EXACT_VALUE` operates on
  `target_value_size`-aligned offsets instead of yielding every non-matching
  byte.
- Critical: `WindowsProcess` permission check is now strict — any subset of
  `PROCESS_ALL_ACCESS` bits (e.g. `PROCESS_TERMINATE` alone) was previously
  enough to pass the read/write gate. The library now requires either the
  explicit `PROCESS_VM_READ` / `PROCESS_VM_WRITE | PROCESS_VM_OPERATION`
  bits or every bit of `PROCESS_ALL_ACCESS`.
- Windows: `SearchValuesByAddresses` now accepts both `MEM_PRIVATE` and
  `MEM_IMAGE` regions, matching `SearchAddressesByValue`. Previously an
  address found via `search_by_value` could silently fail to read in
  `search_by_addresses`.
- Linux scan now skips shared mappings (`s` flag in `/proc/<pid>/maps`).
  Matches the Win32/macOS filter on private memory and removes noise/CPU
  cost from scanning libc and other shared code.
- Linux/macOS scan loops distinguish "page is gone" (EFAULT/ENOMEM on Linux;
  KERN_INVALID_ADDRESS on macOS) — silently skipped — from real
  permission/configuration errors, which propagate as OSError so callers can
  diagnose them.
- Linux `MEMORY_BASIC_INFORMATION` fields widened to 64-bit (`BaseAddress`,
  `RegionSize`, `Offset`, `InodeID`). Mappings beyond 4 GB — common with
  huge pages or large file mmaps on x86_64 — are no longer silently
  truncated.
- Linux `/proc/<pid>/maps` parser now reads the inode in decimal (was being
  parsed as hex, producing a numerically-correct-looking but wrong value for
  any inode with hex-only digits).
- `convert_from_byte_array` decodes strings with `errors="replace"`,
  preventing `UnicodeDecodeError` from raw memory bytes that aren't valid
  UTF-8. Callers needing the raw bytes should pass `pytype=bytes`.
- Library exceptions call `super().__init__(message)`, so `repr(e)`,
  `e.args`, and logging utilities report the real message.
- `AbstractProcess.__init__` correctly handles `pid=0` (the System Idle
  Process) via `pid is not None` check instead of truthiness.
- `search_by_value_between` is correctly marked `@abstractmethod`.
- `ProcessInfo` no longer uses class-level mutable defaults.

### Changed
- `psutil` pinned to `>=5.9,<7` to guard against future major-version
  breakage.
- `requirements.txt` removed in favor of `pip install -e .[tests]`. New
  `dev` extra adds `flake8`, `build`, `twine`.
- Sample Tkinter app requests the minimum permission set it needs
  (`PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION`) and
  throttles UI refreshes during long scans (every 500 matches).

## [1.6.0] and earlier

See git history.
