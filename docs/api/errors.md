# Errors

PyMemoryEditor defines a small exception hierarchy. All custom exceptions
inherit from `PyMemoryEditorError`, so you can catch the whole library:

```python
from PyMemoryEditor import PyMemoryEditorError

try:
    with OpenProcess(process_name="game.exe") as process:
        ...
except PyMemoryEditorError as exc:
    print("Library error:", exc)
```

## The hierarchy

```text
Exception
└── PyMemoryEditorError
    ├── ClosedProcess
    ├── ProcessIDNotExistsError
    ├── ProcessNotFoundError
    └── AmbiguousProcessNameError
```

The library also raises **standard built-in exceptions** when they are the
more idiomatic match (`PermissionError`, `OSError`, `TypeError`, `ValueError`,
`NotImplementedError`).

## Custom exceptions

### `PyMemoryEditorError`

```{eval-rst}
.. py:exception:: PyMemoryEditorError
```

Base class for every PyMemoryEditor-specific exception. Catch it to handle
*any* library error.

### `ClosedProcess`

```{eval-rst}
.. py:exception:: ClosedProcess
```

Raised when you call any method on a process whose handle has already been
closed (manually or by leaving the `with` block).

```python
with OpenProcess(pid=1234) as process:
    pass

process.read_process_memory(0x1000, int)   # raises ClosedProcess
```

### `ProcessIDNotExistsError`

Raised when the given `pid=` doesn't correspond to a running process.

```{eval-rst}
.. py:exception:: ProcessIDNotExistsError

   .. py:attribute:: pid
      :type: int

      The PID that was looked up.
```

### `ProcessNotFoundError`

Raised when no running process matches the given `process_name=`.

```{eval-rst}
.. py:exception:: ProcessNotFoundError

   .. py:attribute:: process_name
      :type: str

      The process name that was looked up.
```

### `AmbiguousProcessNameError`

Raised when **more than one** running process matches the given
`process_name=` (typical when using `exact_match=False`).

```{eval-rst}
.. py:exception:: AmbiguousProcessNameError

   .. py:attribute:: process_name
      :type: str

      The process name that was looked up.

   .. py:attribute:: pids
      :type: List[int]

      PIDs of the matching processes — pick one and pass it via ``pid=``.
```

Example:

```python
from PyMemoryEditor import OpenProcess, AmbiguousProcessNameError

try:
    OpenProcess(process_name="chrome", exact_match=False)
except AmbiguousProcessNameError as exc:
    print("Multiple matches:", exc.pids)
    process = OpenProcess(pid=exc.pids[0])
```

## Standard exceptions

<table>
<tr><th>Exception</th><th>When it's raised</th></tr>
<tr><td><code>TypeError</code></td><td>Neither <code>process_name</code> nor <code>pid</code> provided to <code>OpenProcess</code>.</td></tr>
<tr><td><code>ValueError</code></td><td>Invalid <code>pytype</code>, missing <code>bufflength</code> for <code>str</code>/<code>bytes</code>, invalid <code>ptr_size</code>, malformed pattern, etc.</td></tr>
<tr><td><code>PermissionError</code></td><td>OS denied access to the target process or a specific region.</td></tr>
<tr><td><code>OSError</code></td><td>Low-level read/write failure (e.g. page was freed between scan and read).</td></tr>
<tr><td><code>NotImplementedError</code></td><td><code>allocate_memory</code> / <code>free_memory</code> on Linux.</td></tr>
<tr><td><code>UserWarning</code></td><td><code>permission=</code> passed on a non-Windows platform (silently ignored).</td></tr>
<tr><td><code>ResourceWarning</code></td><td>macOS: <code>mach_vm_protect</code> failed to restore a page's original protection after a write.</td></tr>
</table>

## Catching robustly

A pattern that handles every realistic failure mode:

```python
from PyMemoryEditor import (
    OpenProcess,
    PyMemoryEditorError,
    ProcessNotFoundError,
    AmbiguousProcessNameError,
)

try:
    with OpenProcess(process_name="game.exe") as process:
        for address in process.search_by_value(int, 4, 100):
            try:
                value = process.read_process_memory(address, int)
            except OSError:
                continue   # the page disappeared mid-scan — keep going
            print(hex(address), value)

except ProcessNotFoundError:
    print("The game isn't running.")
except AmbiguousProcessNameError as exc:
    print("Pick one PID:", exc.pids)
except PermissionError:
    print("OS denied access — see Platform Notes.")
except PyMemoryEditorError as exc:
    print("Library error:", exc)
```

```{seealso}
- [Troubleshooting](../troubleshooting.md)
- [Platform Notes](../platform-notes.md)
```
