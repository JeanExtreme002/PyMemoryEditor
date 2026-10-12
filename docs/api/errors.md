# Errors

PyMemoryEditor defines a small exception hierarchy. All custom exceptions
inherit from `PyMemoryEditorError`, so you can catch the whole library:

```python
from PyMemoryEditor import PyMemoryEditorError

try:
    with OpenProcess(name="game.exe") as process:
        ...
except PyMemoryEditorError as exc:
    print("Library error:", exc)
```

## The hierarchy

```text
Exception
└── PyMemoryEditorError
    ├── BitnessDetectionError
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
closed (manually or by leaving the `with` block). A generator returned by a
listing or scan method (`get_memory_regions`, `get_modules`, `get_threads`,
`search_by_*`) raises it too when it is resumed after `close()`, instead of
going on with the released handle.

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

Raised when no running process matches the given `name=`.

```{eval-rst}
.. py:exception:: ProcessNotFoundError

   .. py:attribute:: process_name
      :type: str

      The process name that was looked up.
```

### `AmbiguousProcessNameError`

Raised when **more than one** running process matches the given
`name=` (typical when using `exact_match=False`).

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
    OpenProcess(name="chrome", exact_match=False)
except AmbiguousProcessNameError as exc:
    print("Multiple matches:", exc.pids)
    process = OpenProcess(pid=exc.pids[0])
```

### `BitnessDetectionError`

Raised when `strict_bitness=True` and the target's 32-/64-bit width could
not be read from its own headers (the ELF class on Linux, the Mach-O magic
on macOS, `IsWow64Process` on Windows).

Without strict mode the library falls back to the host word size — a guess
that may silently produce wrong pointer-width defaults.

```{eval-rst}
.. py:exception:: BitnessDetectionError

   .. py:attribute:: pid
      :type: int

      The PID whose bitness could not be determined.
```

Example:

```python
from PyMemoryEditor import OpenProcess, BitnessDetectionError

try:
    with OpenProcess(pid=1234, strict_bitness=True) as process:
        print(process.is_64bit)
except BitnessDetectionError as exc:
    print(f"Could not detect bitness of PID {exc.pid}")
```

## Standard exceptions

<table>
<tr><th>Exception</th><th>When it's raised</th></tr>
<tr><td><code>TypeError</code></td><td>Neither <code>name</code> nor <code>pid</code> provided to <code>OpenProcess</code>; or a scan pattern that is not <code>str</code>, <code>bytes</code> or a compiled <code>re.Pattern</code>.</td></tr>
<tr><td><code>ValueError</code></td><td>Invalid <code>pytype</code>, missing <code>bufflength</code> for <code>str</code>/<code>bytes</code>, invalid <code>ptr_size</code>, malformed pattern, <code>byte_length</code> omitted for a regex pattern, etc.</td></tr>
<tr><td><code>PermissionError</code></td><td>OS denied access to the target process or a specific region.</td></tr>
<tr><td><code>OSError</code></td><td>Low-level read/write failure (e.g. page was freed between scan and read).</td></tr>
<tr><td><code>NotImplementedError</code></td><td><code>allocate_memory</code> / <code>free_memory</code> on Linux.</td></tr>
<tr><td><code>UserWarning</code></td><td><code>permission=</code> passed on a non-Windows platform (ignored, with this warning emitted).</td></tr>
<tr><td><code>ResourceWarning</code></td><td>macOS: <code>mach_vm_protect</code> failed to restore a page's original protection after a write.</td></tr>
</table>

## Read and write failures

A failed memory read or write is an `OSError`, **not** a
`PyMemoryEditorError`, so `except PyMemoryEditorError` does not catch it.
Catch `OSError` (or `PermissionError` for access denials). The attributes
depend on the platform:

<table>
<tr><th>Platform</th><th>Exception</th><th>Details</th></tr>
<tr><td>Windows</td><td><code>OSError</code> / <code>PermissionError</code></td><td><code>winerror</code> holds the Win32 error code. A short read or write is an <code>OSError</code> without a code.</td></tr>
<tr><td>Linux</td><td><code>OSError</code> / <code>PermissionError</code> / <code>ProcessLookupError</code></td><td><code>errno</code> holds the <code>process_vm_readv</code> / <code>process_vm_writev</code> error. A short transfer is an <code>OSError</code> subclass carrying <code>address</code>, <code>bytes_done</code> and <code>length</code>.</td></tr>
<tr><td>macOS</td><td><code>OSError</code> (reads: <code>MachReadError</code>)</td><td>A read failure is a <code>MachReadError</code> whose <code>kr</code> holds the <code>kern_return_t</code>; a short read is its subclass <code>MachPartialReadError</code>. Write failures are plain <code>OSError</code>s with the code in the message.</td></tr>
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
    with OpenProcess(name="game.exe") as process:
        for address in process.search_by_value(int, value=100):
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
