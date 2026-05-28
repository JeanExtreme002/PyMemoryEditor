# Troubleshooting

A directory of the failures users hit most often, and how to fix each one.

## Permission errors

### `PermissionError` when opening another process

The most common first hurdle — the OS is denying access.

<table>
<tr><th>Platform</th><th>Fix</th></tr>
<tr><td>🪟 <b>Windows</b></td><td>Run your terminal <b>as Administrator</b>. Anti-cheat-guarded processes may still refuse — that's expected and intentional.</td></tr>
<tr><td>🐧 <b>Linux</b></td><td>Run as root, or relax <code>ptrace_scope</code>:<br><code>sudo sysctl kernel.yama.ptrace_scope=0</code><br>Opening your own process always works.</td></tr>
<tr><td>🍎 <b>macOS</b></td><td>The Python binary must be signed with the <code>com.apple.security.cs.debugger</code> entitlement (or SIP off + root). Opening the <em>current</em> process always works — great for trying things out.</td></tr>
</table>

See [Platform Notes](platform-notes.md) for the full story.

### `PermissionError` from a specific operation (Windows)

You opened the process with a narrower permission mask than the operation
needs. The most common culprit is allocating memory without
`PROCESS_VM_OPERATION`:

```python
from PyMemoryEditor import OpenProcess, ProcessOperationsEnum

# Need PROCESS_VM_OPERATION for allocate_memory.
with OpenProcess(
    process_name="game.exe",
    permission=ProcessOperationsEnum.PROCESS_VM_READ
        | ProcessOperationsEnum.PROCESS_VM_WRITE
        | ProcessOperationsEnum.PROCESS_VM_OPERATION
        | ProcessOperationsEnum.PROCESS_QUERY_INFORMATION,
) as process:
    address = process.allocate_memory(64)
```

## Process lookup errors

### `ProcessNotFoundError`

No running process matches the given name. Names are **case-sensitive** by
default on Linux/macOS and **case-insensitive** on Windows. Try:

```python
OpenProcess(process_name="chrome", exact_match=False, case_sensitive=False)
```

Or pass `pid=` directly if you can find it via `ps`, Task Manager or
Activity Monitor.

### `AmbiguousProcessNameError`

More than one process matches a partial name. Pick a PID from `.pids` and
pass it explicitly:

```python
from PyMemoryEditor import OpenProcess, AmbiguousProcessNameError

try:
    process = OpenProcess(process_name="chrome", exact_match=False)
except AmbiguousProcessNameError as exc:
    print("Multiple matches:", exc.pids)
    process = OpenProcess(pid=exc.pids[0])
```

### `ProcessIDNotExistsError`

The given `pid=` doesn't correspond to any running process. The PID may have
been **recycled** between when you obtained it and when you opened it — this
happens with short-lived processes.

## Read / write failures

### A scan returns nothing on Windows

Region enumeration needs `PROCESS_QUERY_INFORMATION`, which the default
permission already includes. If you passed a custom `permission=` mask,
make sure that flag is in it.

```python
mask = ProcessOperationsEnum.PROCESS_VM_READ | ProcessOperationsEnum.PROCESS_QUERY_INFORMATION
```

### Reading an address gives garbage or raises `OSError`

Two common causes:

- **The page was freed** between scan and read (normal during live scans
  against active processes). Wrap one-off reads in `try/except OSError`.
- **The value type or size is wrong.** A 4-byte int read of an 8-byte value
  decodes the wrong half. Double-check the `pytype` and `bufflength`.

```python
try:
    value = process.read_process_memory(address, int, 4)
except OSError:
    value = None
```

### `ValueError: bufflength is required`

`str` and `bytes` reads need an explicit size — only numeric types have
defaults:

```python
# Wrong
process.read_process_memory(address, str)

# Right
process.read_process_memory(address, str, 32)
```

### `ResourceWarning` on macOS writes

The library elevated a read-only page's protection to write to it, then
failed to restore the original protection (usually because the target task
disappeared mid-call). The page is left more permissive than it started.

Treat the warning as a signal to investigate — see
[Platform Notes → macOS](project:#macos).

## Pointer issues

### `resolve_pointer_chain` returns garbage

- The target is a **32-bit** process and you didn't pass `ptr_size=4`.
- One of the offsets is wrong (off-by-one in the chain).
- The chain is **dynamic** and has already moved — use a `RemotePointer` to
  re-walk it on every access.

### `path.rebase()` raises `ValueError`

The path has no associated module — its base came from a caller-supplied
`static_ranges`. Such paths only work in the run they were found in;
re-discover the chain in the new run.

### `path.rebase()` raises `LookupError`

The module is no longer loaded in the target process. Either the module was
unloaded, or you're looking at a different process than the one you scanned.

## Logging

Need more detail? PyMemoryEditor logs to a standard `logging` logger named
`"PyMemoryEditor"` (silent by default). Turn it on to see exactly which
pages the library skips during a scan and why:

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("PyMemoryEditor").setLevel(logging.DEBUG)
```

The bundled app exposes the same stream in its **Log Console**
(Tools → Log Console).

See [Logging](guide/logging.md) for advanced routing.

## Reporting a bug

Still stuck? Open an issue at
[github.com/JeanExtreme002/PyMemoryEditor/issues](https://github.com/JeanExtreme002/PyMemoryEditor/issues).

Please include:

- The **OS** (with version) and **Python version**.
- The exact code that triggered the failure.
- The full traceback.
- Any `PyMemoryEditor` log output (run with `level=logging.DEBUG`).
