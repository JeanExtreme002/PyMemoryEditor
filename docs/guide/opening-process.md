# Opening a process

Everything starts with `OpenProcess` — the unified entry point for all three
operating systems. Under the hood it returns the right backend
(`WindowsProcess`, `LinuxProcess` or `MacProcess`), but you never have to care:
the API is identical.

## Basic usage

```python
from PyMemoryEditor import OpenProcess

with OpenProcess(process_name="notepad.exe") as process:
    print("PID:", process.pid)
```

The `with` block automatically calls `process.close()` when you leave it,
releasing any OS handle the backend acquired.

## Identify the process — by name or PID

You can identify the target in two ways:

<table>
<tr>
<th width="40%">Argument</th>
<th>What it does</th>
</tr>
<tr>
<td><code>process_name="notepad.exe"</code></td>
<td>Looks up the PID by name. Most natural way for desktop apps and games.</td>
</tr>
<tr>
<td><code>pid=1234</code></td>
<td>Skip the name lookup and attach to a known PID directly.</td>
</tr>
</table>

If you pass **both**, `pid` wins. If you pass **neither**, `TypeError` is raised.

## Name matching: case and partial matches

By default, `process_name` matching is:

- **Case-sensitive** on Linux and macOS.
- **Case-insensitive** on Windows (matches the OS convention).
- **Exact**: the name has to match the executable name exactly.

You can override both with keyword arguments:

```python
# Match "chrome.exe", "ChroMe.EXE", "chrome" — anywhere case-insensitively.
OpenProcess(process_name="chrome", case_sensitive=False, exact_match=False)
```

| Argument | Type | Default | Effect |
| --- | --- | --- | --- |
| `case_sensitive` | `bool` | platform-dependent | When `False`, ignores case. |
| `exact_match` | `bool` | `True` | When `False`, matches as a substring. |

If a partial match resolves to **more than one** process, an
`AmbiguousProcessNameError` is raised — pick one PID from the listed candidates
and pass it via `pid=` instead.

## Permissions (Windows-only)

Only the Windows backend accepts a `permission=` mask — it maps directly to the
[`PROCESS_*` access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
of `OpenProcess`. The default opens a **read + write** handle:

```python
# Default — same as:
OpenProcess(
    process_name="notepad.exe",
    permission=(
        ProcessOperationsEnum.PROCESS_VM_READ
        | ProcessOperationsEnum.PROCESS_VM_WRITE
        | ProcessOperationsEnum.PROCESS_VM_OPERATION
        | ProcessOperationsEnum.PROCESS_QUERY_INFORMATION
    ),
)
```

For a read-only handle (less powerful but useful for static analysis):

```python
from PyMemoryEditor import OpenProcess, ProcessOperationsEnum

OpenProcess(
    process_name="notepad.exe",
    permission=ProcessOperationsEnum.PROCESS_VM_READ
        | ProcessOperationsEnum.PROCESS_QUERY_INFORMATION,
)
```

For full control:

```python
OpenProcess(
    process_name="notepad.exe",
    permission=ProcessOperationsEnum.PROCESS_ALL_ACCESS,
)
```

```{admonition} 🐧🍎 On Linux and macOS
:class: note

The `permission` argument is **ignored** — those platforms govern access via
`ptrace_scope` (Linux) or Mach entitlements (macOS). Passing a value emits a
`UserWarning` so a Windows-shaped mask doesn't disappear silently.

See [Platform Notes](../platform-notes.md) for details.
```

## Closing the handle

When you're done, close the process:

```python
process.close()
```

Or use the context manager (recommended):

```python
with OpenProcess(pid=1234) as process:
    ...
# process is closed here, even if an exception was raised
```

Once closed, any further call raises `ClosedProcess`.

## Common errors

| Exception | Meaning |
| --- | --- |
| `ProcessNotFoundError` | No process matches the given `process_name`. |
| `ProcessIDNotExistsError` | The given `pid` doesn't exist on the system. |
| `AmbiguousProcessNameError` | More than one process matches a partial name — pick a PID from `.pids`. |
| `PermissionError` | The OS denied access — usually fixable; see [Troubleshooting](../troubleshooting.md). |
| `ClosedProcess` | Operation attempted on an already-closed handle. |

All exceptions inherit from `PyMemoryEditorError`, so you can catch them
collectively:

```python
from PyMemoryEditor import OpenProcess, PyMemoryEditorError

try:
    with OpenProcess(process_name="game.exe") as process:
        ...
except PyMemoryEditorError as e:
    print("Failed to open process:", e)
```
