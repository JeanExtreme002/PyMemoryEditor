# `OpenProcess` (process API)

`OpenProcess` is the unified entry point. Depending on the host OS, it
resolves to:

<table>
<tr><th>Platform</th><th>Concrete class</th></tr>
<tr><td>🪟 Windows</td><td><code>PyMemoryEditor.win32.process.WindowsProcess</code></td></tr>
<tr><td>🐧 Linux</td><td><code>PyMemoryEditor.linux.process.LinuxProcess</code></td></tr>
<tr><td>🍎 macOS</td><td><code>PyMemoryEditor.macos.process.MacProcess</code></td></tr>
</table>

All three subclass `AbstractProcess` and share the API documented below.

```{eval-rst}
.. py:class:: AbstractProcess

   The cross-platform base class every backend implements. ``OpenProcess``
   returns one of its subclasses; the methods documented on this page are the
   shared, public surface.
```

## Construction

```{eval-rst}
.. py:class:: OpenProcess(*, process_name=None, pid=None, permission=None, case_sensitive=None, exact_match=True)

   Open a target process.

   :param str process_name: name of the target process.
   :param int pid: process ID. Takes precedence over ``process_name``.
   :param permission: **Windows only.** A
      :py:class:`ProcessOperationsEnum` value (or integer). Defaults to
      read+write (``PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
      | PROCESS_QUERY_INFORMATION``). On Linux and macOS this argument is
      accepted for API parity but **ignored**; passing a non-``None`` value
      emits ``UserWarning``.
   :param bool case_sensitive: when ``False``, ``process_name`` matching
      ignores case. Default is ``False`` on Windows, ``True`` elsewhere.
   :param bool exact_match: when ``False``, ``process_name`` matches as a
      substring (``"chrome"`` matches ``"chrome.exe"``).

   :raises ProcessNotFoundError: no process matches ``process_name``.
   :raises ProcessIDNotExistsError: ``pid`` doesn't exist.
   :raises AmbiguousProcessNameError: more than one process matches.
   :raises TypeError: neither ``process_name`` nor ``pid`` was provided.
   :raises PermissionError: the OS denied access.
```

### Examples

```python
# By name
with OpenProcess(process_name="game.exe") as process:
    ...

# By PID
with OpenProcess(pid=1234) as process:
    ...

# Partial, case-insensitive name match (Windows-friendly)
with OpenProcess(process_name="chrome", case_sensitive=False, exact_match=False) as process:
    ...

# Read-only handle (Windows only)
from PyMemoryEditor import ProcessOperationsEnum

with OpenProcess(
    process_name="game.exe",
    permission=ProcessOperationsEnum.PROCESS_VM_READ | ProcessOperationsEnum.PROCESS_QUERY_INFORMATION,
) as process:
    ...
```

## Attributes

```{eval-rst}
.. py:attribute:: pid
   :type: int
   :no-index:

   The PID of the target process.

.. py:attribute:: main_thread
   :type: Optional[ThreadInfo]

   The conventional "main thread" of the target — by convention, the thread
   with the smallest ``tid``. Returns ``None`` if the process has no listable
   threads (rare).
```

## Methods

### Read / write

```{eval-rst}
.. py:method:: read_process_memory(address, pytype, bufflength=None)

   Read a value from memory.

   :param int address: target memory address.
   :param Type pytype: ``bool``, ``int``, ``float``, ``str`` or ``bytes``.
   :param int bufflength: value size in bytes (optional for numeric types).
   :returns: the decoded value.

.. py:method:: write_process_memory(address, pytype, bufflength, value)

   Write a value to memory.

   :param int address: target memory address.
   :param Type pytype: one of the five supported types.
   :param int bufflength: value size in bytes (``None`` for numeric defaults).
   :param value: the value to write.
   :returns: the written value.
```

### Searching

```{eval-rst}
.. py:method:: search_by_value(pytype, bufflength, value, scan_type=ScanTypesEnum.EXACT_VALUE, *, progress_information=False, writeable_only=False, memory_regions=None)

   Yield every address holding ``value`` (compared per ``scan_type``).
   See :doc:`../guide/searching` for a full walkthrough.

.. py:method:: search_by_value_between(pytype, bufflength, start, end, *, not_between=False, progress_information=False, writeable_only=False, memory_regions=None)

   Yield every address whose value is in ``[start, end]`` (or outside, with
   ``not_between=True``).

.. py:method:: search_by_addresses(pytype, bufflength, addresses, *, raise_error=False, memory_regions=None)

   Read each address in ``addresses`` once, yielding ``(address, value)``.
   Far faster than looping over :py:meth:`read_process_memory`.

.. py:method:: search_by_pattern(pattern, *, byte_length=0, progress_information=False, memory_regions=None)

   Scan memory for a byte pattern — IDA-style hex, raw bytes regex, or a
   compiled :py:class:`re.Pattern`. See :doc:`../guide/pattern-scan`.
```

### Memory regions

```{eval-rst}
.. py:method:: get_memory_regions()

   Yield a :py:class:`MemoryRegion` per region — an immutable dataclass with
   ``address``, ``size``, ``is_readable``, ``is_writable``, ``is_executable``,
   ``is_shared``, ``path`` and the platform-specific ``struct``.

.. py:method:: snapshot_memory_regions()

   Materialize the region list once as a :py:class:`MemoryRegionSnapshot`
   (pre-sorted by base address), for reuse across iterative scans.
```

### Modules and threads

```{eval-rst}
.. py:method:: get_modules()

   Yield a :py:class:`ModuleInfo` for every loaded module.

.. py:method:: get_threads()

   Yield a :py:class:`ThreadInfo` for every thread inside the target.
```

### Pointers

```{eval-rst}
.. py:method:: resolve_pointer_chain(base_address, offsets, *, ptr_size=8)

   Walk a multi-level pointer chain and return the final address.

.. py:method:: get_pointer(base_address, offsets=None, *, pytype=int, bufflength=None, ptr_size=8)

   Build a :py:class:`RemotePointer` bound to this process — a live,
   re-resolving handle. See :doc:`../guide/pointers`.

.. py:method:: scan_pointer_paths(target_address, *, max_depth=5, max_offset=0x400, ptr_size=8, aligned=True, writable_only=True, static_ranges=None, max_results=None, memory_regions=None, progress_callback=None)

   Reverse pointer scan — yield :py:class:`PointerPath` recipes that resolve
   to ``target_address``. See :doc:`../guide/pointer-scan`.

.. py:method:: save_pointer_paths(paths, file)

   Save pointer paths to a JSON file.

.. py:method:: load_pointer_paths(file)

   Load pointer paths previously saved with :py:meth:`save_pointer_paths`.

.. py:method:: rescan_pointer_paths(paths, target_address)

   Keep only the paths that still resolve to ``target_address``.

.. py:method:: compare_pointer_scans(*sources)

   Intersect several saved scans — return the paths present in *every* one.
```

### Allocation

```{eval-rst}
.. py:method:: allocate_memory(size, *, permission=None)

   Reserve ``size`` bytes inside the target. Windows and macOS only.

.. py:method:: free_memory(address, size=0)

   Release a previously allocated region.
```

### Lifecycle

```{eval-rst}
.. py:method:: close()

   Close the process handle. Subsequent calls raise :py:exc:`ClosedProcess`.

.. py:method:: __enter__()
.. py:method:: __exit__(exc_type, exc_value, exc_traceback)

   The process is also a context manager — prefer the ``with`` block.
```

```{seealso}
- [`ScanTypesEnum`](enums.md)
- [`MemoryRegion`](memory-region.md)
- [`RemotePointer`](remote-pointer.md)
- [`PointerPath`](pointer-path.md)
- [`ModuleInfo`](module-info.md)
- [`ThreadInfo`](thread-info.md)
- [Errors](errors.md)
```
