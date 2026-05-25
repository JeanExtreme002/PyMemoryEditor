# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `AbstractProcess` is now exported from the top-level package
  (`from PyMemoryEditor import AbstractProcess`). Apps and downstream
  callers no longer need to reach into `PyMemoryEditor.process` to get
  the cross-platform process type. Internal imports across the bundled
  Qt app were updated to the public path; the old path
  (`PyMemoryEditor.process.AbstractProcess`) keeps working for
  backward compatibility.
- `.github/dependabot.yml` enables weekly version-update PRs for both
  `pip` (runtime + dev/extras) and `github-actions`. Minor/patch bumps
  of dev tooling (pytest*, hypothesis, flake8, mypy, build, twine) are
  bundled into a single grouped PR to keep volume manageable.
- `.pre-commit-config.yaml` mirrors the CI checks (flake8 + mypy on the
  shared layer) so developers can catch lint/type regressions locally
  before pushing. Activate with `pip install pre-commit && pre-commit install`.
- CLI smoke test in CI: every matrix cell now runs
  `pymemoryeditor --version` and asserts the printed value matches
  `PyMemoryEditor.__version__`. Catches regressions in the entry-point
  wiring and `application.main` argv handling without needing a display
  server (`QT_QPA_PLATFORM=offscreen`).
- New `type-check-shared` CI job runs strict `mypy` against
  `process/`, `util/`, `__init__.py` and `enums.py` and **blocks merges
  on regressions**. The existing full-package mypy run is renamed
  `type-check-full` and stays informational while the per-OS ctypes
  backends still lack typing coverage.
- `snapshot_memory_regions()` now pre-sorts regions by base address and
  tags each entry so the helpers in `process.scanning`
  (`iter_values_for_addresses`, `iter_search_results`) skip their
  per-call `sorted(...)` step on reuse. Practical win in tight refine
  loops that reuse the same snapshot across many `search_by_*` calls.

### Changed

- `WindowsProcess.__init__` default `permission` now includes write access:
  `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
  PROCESS_QUERY_INFORMATION`. The 2.0.0 release narrowed it to a read-only
  set to make least-privilege the default, but the friction of always
  opting into write for the common "scan + poke" workflow outweighed the
  safety benefit. Callers who genuinely want a read-only handle should
  pass `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` explicitly.
- `LinuxProcess` and `MacProcess` now emit a `UserWarning` when the caller
  passes a non-None `permission`. The argument is still accepted (for the
  documented cross-platform parity pattern of passing `None` outside Win32),
  but a real Windows-shaped mask used to disappear here without any signal —
  callers were left thinking they had requested write access on Linux/macOS
  when in fact those platforms govern access via `ptrace_scope` / Mach
  entitlements. `permission=None` stays silent so existing cross-platform
  code that already passes `None` everywhere outside Win32 is unaffected.
- The app module `PyMemoryEditor.app.cheat_table` was split into three
  files for maintainability:
  - `cheat_entry.py` owns the `CheatEntry` dataclass and its
    `to_dict` / `from_dict` serialization helpers.
  - `cheat_poll_worker.py` owns the `_CheatPollWorker` background
    `QThread` plus the `TICK_INTERVAL_MS` / `_BATCH_THRESHOLD`
    constants.
  - `cheat_table.py` is now just the `CheatTable` widget plus the
    `prompt_for_manual_entry` helper.
  All three names (`CheatEntry`, `_CheatPollWorker`,
  `prompt_for_manual_entry`) are re-exported from `cheat_table` so
  existing imports — including
  `tests/test_cheat_poll_worker.py` — keep working unchanged.
- `process.region` no longer wraps `hasattr` behind a `_has_attr`
  shim. Direct `hasattr(...)` calls inline; behavior unchanged.
- `process.scanning` replaces the two `transient_error_check = lambda` /
  `# noqa: E731` defaults with a named `_always_false` helper.
- `process/info.py` `window_title.setter` uses `pid is None or pid == 0`
  instead of a truthy check, aligning with `pid.setter` semantics.
- `app.scan_worker.RefineScanWorker` now logs (DEBUG-level) the `TypeError`
  it catches when the comparator receives incompatible types. The
  failing address is still dropped from the refine pass (no behavior
  change), but the cause is no longer silently swallowed.
- `AbstractProcess.read_process_memory` docstring documents that
  `pytype=str` decodes with `errors="replace"` — non-UTF-8 bytes become
  `U+FFFD`. Mirrors the long-standing runtime behavior.
- `MacProcess.write_process_memory` docstring now carries an explicit
  warning about the page-protection elevation side effect: on a restore
  failure the target page is left more permissive than it started.
  README's macOS notes section gained the same warning.
- `.flake8`: `E722` (bare except) removed from `ignore = …`. The codebase
  has no bare `except:` clauses today; keeping the rule active means a
  future regression gets caught.

### Removed

- `OpenProcess(window_title=...)` is no longer supported on any platform.
  The `window_title` keyword argument has been dropped from
  `AbstractProcess`, `WindowsProcess`, `LinuxProcess` and `MacProcess`;
  open processes by `process_name` or `pid` instead. The supporting
  Win32 plumbing has been removed too: `GetProcessIdByWindowTitle`,
  `get_process_id_by_window_title`, `WindowNotFoundError`, the
  `WNDENUMPROC` ctypes type, and the `user32.dll` bindings for
  `EnumWindows` / `GetWindowTextW` / `GetWindowThreadProcessId`.
  `WindowNotFoundError` is no longer exported from the top-level
  package.

### Fixed

- `tests/test_macos_protect.py` dropped a copy-paste artifact: the
  module loaded `_libsystem` twice (once via a stale
  `hasattr(ctypes, "util")` guard, then immediately overwritten by the
  correct `find_library("System")` call). Now loaded once at the top
  of the module after the `find_library` import.

## [2.0.0] - 2026-05-20

The 2.0.0 release adds native **macOS support** via the Mach VM APIs, fixes a
batch of latent correctness bugs in the Windows and Linux backends, replaces
the Tk demo with a Qt (PySide6) app, and tightens cross-platform robustness
across the board.

### Breaking changes

- `WindowsProcess.__init__` now defaults `permission` to
  `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` instead of
  `PROCESS_ALL_ACCESS`. Callers that write to memory must explicitly request
  `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION`
  (or a wider mask). `PROCESS_QUERY_INFORMATION` is required by `VirtualQueryEx`,
  which the region-enumeration code paths use internally — without it every
  `get_memory_regions` / `search_by_*` call comes back empty.
- Permission checks are now strict bitmask tests. Composing flags with bitwise
  OR is supported via `IntFlag`; passing flags that don't include the
  required bit raises `PermissionError`. Previously any subset of
  `PROCESS_ALL_ACCESS` (e.g. `PROCESS_TERMINATE` alone) would pass the gate.
- `get_process_id_by_process_name` now raises `AmbiguousProcessNameError` when
  more than one process matches the name. Use `get_process_ids_by_process_name`
  to retrieve the full list explicitly.
- `requirements.txt` removed in favor of `pip install -e ".[dev]"`. CI scripts
  that did `pip install -r requirements.txt` must migrate.
- `PyMemoryEditor.sample` (Tk demo) was removed and replaced by
  `PyMemoryEditor.app` (Qt / PySide6). The new app is the `pymemoryeditor`
  CLI entry point. Tk is no longer a (soft) requirement; the Qt app is an
  opt-in extra (`pip install "PyMemoryEditor[app]"`).
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
- macOS `write_process_memory` on a read-only page transparently elevates
  the page protection via `mach_vm_protect`, performs the write, and restores
  the original protection. Mirrors the practical behavior of
  `WriteProcessMemory` on Windows. The restore step emits a `ResourceWarning`
  if it fails so the caller learns the target page was left more permissive
  than it started.
- **Qt (PySide6) app** under `PyMemoryEditor.app`, exposed as the
  `pymemoryeditor` CLI. Exercises every public surface of the library: all
  eight `ScanTypesEnum` modes, the five value types (`bool`, `int`, `float`,
  `str`, `bytes`), `search_by_value`, `search_by_value_between`,
  `search_by_addresses`, `read_process_memory`, `write_process_memory`,
  `get_memory_regions` / `snapshot_memory_regions`, plus value freezing and
  a hex viewer. Available via the `app` extra
  (`pip install "PyMemoryEditor[app]"`).
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
- `process.snapshot_memory_regions()` materializes the region list so callers
  can reuse it across multiple scans without paying the enumeration cost each
  time. `search_by_value`, `search_by_value_between` and `search_by_addresses`
  now accept a `memory_regions=` keyword to consume the snapshot. Recommended
  for "scan → refine → refine" workflows.
- `bufflength` is now optional for numeric types: pass `None` (or omit on
  reads) to use the default — `int → 4`, `float → 8`, `bool → 1`. `str` and
  `bytes` continue to require an explicit length.
- `LinuxProcess` and `MacProcess` accept (and silently ignore) the
  `permission` parameter, so cross-platform code can pass it without
  branching.
- `OpenProcess` accepts `case_sensitive=False` for `process_name` matching
  (default `False` on Windows, `True` elsewhere — matches OS conventions).
- `PyMemoryEditorError` base class for all library exceptions, plus
  `AmbiguousProcessNameError` for resolving processes by name when multiple
  match.
- `py.typed` marker so type checkers consume the bundled type hints. The
  shared layer (`process/`, `util/`) is checked by mypy; per-OS backends
  expose hints in source but are not gated by mypy on a single host
  (their cross-OS ctypes symbols are platform-conditional).
- `__all__` declared on the package.
- Type-checker-friendly `OpenProcess` alias: the cross-platform `Union` is
  exposed under `TYPE_CHECKING` so IDEs / pyright see every backend's
  signature (including Windows-only `permission=`) regardless of the host OS.
- New `PyMemoryEditor.process.region` module owns cross-platform region
  introspection. `get_memory_regions()` enriches each yielded dict with
  `is_readable`, `is_writable`, `is_executable`, `is_shared` and `path`
  keys, so portable client code no longer has to introspect the
  per-platform `struct` field.
- New `PyMemoryEditor.process.scanning` module owns the chunking / boundary /
  gap-handling logic shared by all three backends. `iter_search_results`
  walks every chunk/region and dispatches the comparator;
  `iter_values_for_addresses` reads values at a sorted list of addresses,
  grouping syscalls by region and chunk. Win32, Linux and macOS
  `search_*` methods delegate to these helpers — removing ~350 LOC of
  duplication and fixing the gap/truncation bugs in one place.
- `util.value_to_bytes` / `util.values_to_bytes` helpers consolidate the
  per-backend conversion of scan target values to fixed-width byte strings,
  removing ~30 lines of duplication across `win32`, `linux` and `macos`.
- `SECURITY.md` on the repo root surfaces the private advisory channel for
  GitHub UI.
- `dev` extra now bundles `pytest`, `pytest-cov`, `pytest-qt`, `hypothesis`,
  `flake8`, `mypy`, `build`, `twine` and `PySide6` so a single
  `pip install -e ".[dev]"` provisions everything tests need.
- Performance: numeric scans (`BIGGER_THAN`, `SMALLER_THAN`, `VALUE_BETWEEN`,
  ...) decode via `struct.iter_unpack` for sizes 1/2/4/8 bytes, with the
  comparison loop inlined per scan_type to eliminate generator and
  tuple-unpacking overhead. **~6–8× faster** than the pre-inline version on
  multi-million-iteration scans.
- Test files: `test_scan.py`, `test_scan_properties.py` (hypothesis-driven,
  cross-validates the fast `struct.iter_unpack` path against a reference
  slow path for every ordered scan_type, over both signed integers and
  IEEE-754 floats), `test_str_boundary.py` (regression for the chunk-overlap
  fix when scanning strings across chunk boundaries), `test_errors.py`,
  `test_linux_types.py` (Linux-only regressions for 64-bit fields),
  `test_macos_protect.py` (macOS-only regression for protect-flip),
  `test_win32_permissions.py` (Win32-only regression for permission gate
  logic), `test_process_lookup.py` (cross-platform mock-based coverage of
  `AmbiguousProcessNameError` and the `case_sensitive` flag),
  `test_chunking_integration.py` (chunking boundaries, fast/slow paths of
  `iter_region_chunks`, mocked `IsWow64Process` to validate
  `mbi_class_for_handle`), `test_bufflength_inference.py`,
  `test_region_snapshot.py`, `test_str_decode_consistency.py`,
  `test_scanning_helper.py`, `test_partial_io.py` (strict partial-read
  check on Linux and macOS), and `test_app_smoke.py` (smoke tests for
  the Qt app).

### Fixed

- Critical: platform detection no longer matches `darwin` ("win" is a
  substring of "darwin"). The package uses `sys.platform == "win32"` and
  explicitly raises `ImportError` on unsupported platforms.
- Critical: `ReadProcessMemory`, `WriteProcessMemory`, `OpenProcess`, and
  `process_vm_readv` / `process_vm_writev` calls now set `argtypes` /
  `restype` and check their return value, raising `OSError` on failure
  instead of silently returning zeroed buffers. Previously, failed reads
  returned `0` indistinguishable from real reads.
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
- Critical: `ProcessOperationsEnum.PROCESS_TERMINATE` was `0x0800`, the same
  value as `PROCESS_SUSPEND_RESUME`, making it a silent alias under Python's
  Enum semantics. Corrected to `0x0001` per MSDN. Callers that requested
  termination permission were getting suspend/resume instead.
- Critical: `scan_memory` ordering comparisons (`BIGGER_THAN`, `SMALLER_THAN`,
  `VALUE_BETWEEN`, ...) on signed `int` values used to compare against the
  unsigned reinterpretation of the encoded bytes (e.g. `-1` was treated as
  `0xFFFFFFFF`), so "bigger than `-1`" never matched. Same problem affected
  `float` scans, which were ordered by their integer bit-pattern (so `-1.0f`
  appeared greater than `1.0f`). The scan now dispatches per `pytype` to use
  signed `struct b/h/i/q` for ints and IEEE-754 `struct f/d` for floats.
- Critical (Win32): `ReadProcessMemory` raises `OSError` when the kernel
  reports a partial read (`bytes_read < bufflength`). Previously a truncated
  read on a boundary-crossing region populated a buffer of mixed
  real-bytes-and-zeros that downstream decoding would silently treat as
  valid. Mirrors the existing partial-write check in `WriteProcessMemory`.
- Critical (Win32): `WriteProcessMemory` raises `OSError` when the kernel
  reports a partial write (`bytes_written < bufflength`). Previously a
  truncated write to a boundary-crossing region returned silently as success.
- Critical (Linux): `_process_vm_readv` / `_process_vm_writev` raise
  `_LinuxPartialIOError` on a short transfer (`result < length`) instead of
  silently returning the partial count. This protects
  `read_process_memory` / `write_process_memory` from leaving the caller's
  buffer half-filled with real bytes and half zero-initialized. Scan paths
  classify the partial as transient (same shape as a vanished page) so a
  partial chunk read mid-scan is skipped rather than aborting.
- Critical (macOS): `_mach_read` raises `MachPartialReadError` when
  `mach_vm_read_overwrite` returns KERN_SUCCESS but `outsize < size`. Same
  class of bug as the Linux/Win32 partial-transfer fixes above. The error
  inherits from `MachReadError` with `kr=KERN_INVALID_ADDRESS`, so the
  existing transient classifier in the scan path picks it up automatically.
- Win32: `kernel32` / `user32` are loaded with
  `ctypes.WinDLL(..., use_last_error=True)`. The previous
  `ctypes.windll.LoadLibrary(...)` left `ctypes.get_last_error()` at zero, so
  every failure surfaced as `OSError: <api> failed.` without the underlying
  Win32 error code — the `WinError(code, ...)` branch in `_raise_last_error`
  was effectively dead.
- Win32: `WindowsProcess.close()` no longer silently returns `False` when
  `CloseHandle` fails. It raises `WinError` / `OSError` (with the actual
  Win32 code, courtesy of the `use_last_error=True` fix above) and the
  object is marked closed so subsequent `close()` calls don't retry against
  a handle the kernel already released.
- Windows: `SearchValuesByAddresses` now accepts both `MEM_PRIVATE` and
  `MEM_IMAGE` regions, matching `SearchAddressesByValue`. Previously an
  address found via `search_by_value` could silently fail to read in
  `search_by_addresses`.
- Linux scan now skips shared mappings (`s` flag in `/proc/<pid>/maps`).
  Matches the Win32 / macOS filter on private memory and removes noise / CPU
  cost from scanning libc and other shared code.
- Linux / macOS scan loops distinguish "page is gone" (EFAULT / ENOMEM on
  Linux; KERN_INVALID_ADDRESS / KERN_NO_ACCESS / KERN_INVALID_ARGUMENT on
  macOS) — silently skipped — from real permission / configuration errors,
  which propagate as `OSError` so callers can diagnose them.
- Linux: `process_vm_readv` / `process_vm_writev` bindings declare `argtypes`
  explicitly. Previously only `restype` was set; on builds where the default
  C-int width is narrower than the pointer representation, ctypes could
  silently truncate iovec pointers before the kernel saw them — the same
  class of bug fixed in the Win32 backend during v2.
- Linux: `MEMORY_BASIC_INFORMATION.Privileges` / `.Path` were `c_char_p`
  pointers tied to the lifetime of the originating Python `bytes` objects.
  Reading the struct after those bytes were GC'd was undefined behavior.
  Both fields are now fixed-size inline `c_char * N` arrays so the struct
  owns the storage.
- Linux `MEMORY_BASIC_INFORMATION` fields widened to 64-bit (`BaseAddress`,
  `RegionSize`, `Offset`, `InodeID`). Mappings beyond 4 GB — common with
  huge pages or large file mmaps on x86_64 — are no longer silently
  truncated.
- Linux `/proc/<pid>/maps` parser now reads the inode in decimal (was being
  parsed as hex, producing a numerically-correct-looking but wrong value for
  any inode with hex-only digits).
- `search_by_addresses` yields `(address, None)` for addresses that fall
  in gaps between memory regions, and for values whose
  `[address, address+bufflength)` would extend past the containing region.
  The previous per-backend code silently dropped gap-addresses and
  zero-padded reads that overflowed the last chunk.
- `search_by_addresses` treats an explicitly-empty `memory_regions=[]` as
  "scan nothing", matching `search_by_value*`. Previously the truthy check
  silently re-enumerated the full address space when the caller passed an
  empty pre-filtered list.
- `scan_memory_for_exact_value` with `NOT_EXACT_VALUE` was O(n × m) — for each
  candidate offset it walked the full match list to check overlap. Now uses
  `bisect_left` over the (already sorted) match positions, dropping the inner
  step to O(log m). Practical win on multi-match scans of large regions.
- `read_process_memory(addr, str, n)` decodes with `errors="replace"`,
  matching `convert_from_byte_array` (used by `search_by_addresses`). The same
  raw bytes used to raise `UnicodeDecodeError` on one path and succeed on the
  other.
- `convert_from_byte_array` decodes strings with `errors="replace"`,
  preventing `UnicodeDecodeError` from raw memory bytes that aren't valid
  UTF-8. Callers needing the raw bytes should pass `pytype=bytes`.
- Library exceptions call `super().__init__(message)`, so `repr(e)`,
  `e.args`, and logging utilities report the real message.
- `AbstractProcess.__init__` correctly handles `pid=0` (the System Idle
  Process) via `pid is not None` check instead of truthiness.
- `search_by_value_between` is correctly marked `@abstractmethod`.
- `ProcessInfo` no longer uses class-level mutable defaults.
- macOS: `_PAGE_GONE_KRS` includes `KERN_NO_ACCESS` and
  `KERN_INVALID_ARGUMENT` so guard-page and freshly-unmapped-page reads
  during a scan are skipped rather than aborting the scan.
- macOS: `MacProcess.__del__` calls `close()` best-effort so a leaked
  reference doesn't hold the target's task port forever. Context-manager
  usage is still preferred.
- App: `value_types.parse_value(str, ...)` used character count as the byte
  length; multi-byte UTF-8 strings (accents, CJK) were truncated. It now
  uses `len(value.encode("utf-8"))`.
- App: `application.main(argv=None)` accepts an explicit argv list — the
  previous signature collected positional args but ignored them.

### Changed

- Win32 enums (`ProcessOperationsEnum`, `MemoryProtectionsEnum`,
  `MemoryTypesEnum`, `MemoryAllocationStatesEnum`,
  `StandardAccessRightsEnum`) migrated from `Enum` to `IntFlag` so members
  compose with `|` and bitmask comparisons work without `.value`
  unwrapping. `PROCESS_ALL_ACCESS` bumped from the pre-Vista value
  `0x1F0FFF` to the modern `0x1FFFFF` (PyMemoryEditor targets Python 3.8+,
  which already required Vista or later).
- `scan_memory` numeric fast path uses a `memoryview` instead of materializing
  a `bytes` copy of the chunk, avoiding an extra 256 MB copy per chunk in the
  hot path.
- `process.region.enrich_region` reads its constants from the existing
  `MemoryAllocationStatesEnum`, `MemoryTypesEnum`, `MemoryProtectionsEnum`
  (Win32) and `VM_PROT_*` (macOS) modules instead of duplicating bit values.
  Keeps the cross-platform predicates honest if the source enums ever
  change.
- `psutil` pinned to `>=5.9,<7` to guard against future major-version
  breakage.
- App `CheatTable` runs its 10 Hz read/freeze loop on a background
  `QThread` (`_CheatPollWorker`); the UI receives values via a queued
  signal and never blocks on `read_process_memory` / `write_process_memory`.
- App `MemoryMapDialog` runs `snapshot_memory_regions()` on a
  `_SnapshotWorker` thread.
- App `OpenProcessDialog` enumerates processes via `_ProcessListWorker`
  off the UI thread on every 3 s auto-refresh.
- App `CheatTable` batches the 10 Hz refresh through `search_by_addresses`
  when entries share the same `(pytype, length)` — collapses N syscalls
  into chunked reads at the page level.
- `tests/conftest.py` no longer manipulates `sys.path`. The package must be
  installed in editable mode (`pip install -e ".[dev]"`).
- `_validate_pytype` helper in `util.convert` replaces the 12 inline
  copies of the `pytype in (bool, int, float, str, bytes)` check across
  the three backends.
- Makefile `security` target uses `pip-audit` (PyPA-maintained) in place
  of the older `safety` tool (now paid / registered). `install-dev` no
  longer redundantly re-installs `pytest-cov` and `mypy` (already in the
  `[dev]` extra). Obsolete `lint-fix` (which referenced `black`, never a
  project dependency) removed.

### Docs

- `README.md`: documents the macOS entitlement requirement, the
  refine-scan workflow with `snapshot_memory_regions()`, and the new
  `pymemoryeditor` Qt CLI.
- `CONTRIBUTING.md`: adds the `macos/` package to the project layout and a
  per-platform test-requirement note.

## [1.6.0] and earlier

See git history.
