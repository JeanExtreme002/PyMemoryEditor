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
.. py:class:: OpenProcess(*, process_name=None, pid=None, permission=<platform default>, case_sensitive=<platform default>, exact_match=True)

   Open a target process. ``OpenProcess`` resolves to the concrete backend for
   the host OS, so the ``permission`` and ``case_sensitive`` defaults are
   platform-specific (see below): on Windows ``permission`` defaults to the
   read+write mask and ``case_sensitive`` to ``False``; on Linux/macOS
   ``permission`` defaults to ``None`` (ignored) and ``case_sensitive`` to
   ``True``.

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

.. py:method:: write_process_memory(address, pytype, bufflength=None, value=...)

   Write a value to memory.

   :param int address: target memory address.
   :param Type pytype: one of the five supported types.
   :param int bufflength: value size in bytes. **Optional** (defaults to
      ``None``): numeric types fall back to their default width and ``str`` /
      ``bytes`` write the whole value. For ``str`` / ``bytes`` an explicit value
      is a *maximum* width that truncates the value and never pads — ``str``
      counts characters (applied before UTF-8 encoding, so multibyte characters
      are never split), ``bytes`` counts bytes. Because it is optional, pass
      ``value`` by keyword when omitting it (``write_process_memory(addr, int,
      value=9999)``).
   :param value: the value to write.
   :returns: the written value.
```

### Typed shortcuts

Convenience `read_*` / `write_*` pairs with the size and signedness baked into
the name — see :doc:`../guide/read-write` for examples. Widths are fixed and
identical on every platform.

```{eval-rst}
.. py:method:: read_char(address)
   :no-index:

   Read / write a signed 8-bit integer (1 byte). Pair: ``write_char(address, value)``.

.. py:method:: read_short(address)
   :no-index:

   Signed 16-bit integer (2 bytes). Pair: ``write_short``.

.. py:method:: read_int(address)
   :no-index:

   Signed 32-bit integer (4 bytes). Pair: ``write_int``.

.. py:method:: read_long(address)
   :no-index:

   Signed 32-bit integer (4 bytes, Win32 ``LONG``). Pair: ``write_long``.

.. py:method:: read_longlong(address)
   :no-index:

   Signed 64-bit integer (8 bytes). Pair: ``write_longlong``.

.. py:method:: read_uchar(address)
   :no-index:

   Unsigned variants of the above: ``read_uchar`` / ``read_ushort`` /
   ``read_uint`` / ``read_ulong`` / ``read_ulonglong`` (1 / 2 / 4 / 4 / 8 bytes),
   each with a matching ``write_*``.

.. py:method:: read_float(address)
   :no-index:

   32-bit float (4 bytes). Pair: ``write_float``.

.. py:method:: read_double(address)
   :no-index:

   64-bit double (8 bytes). Pair: ``write_double``.

.. py:method:: read_bool(address)
   :no-index:

   Boolean (1 byte). Pair: ``write_bool``.

.. py:method:: read_string(address, byte_count)
   :no-index:

   Read exactly ``byte_count`` bytes (a short read raises ``OSError``), decode
   UTF-8, and return the text up to the first NUL — so ``byte_count`` is the
   field width to read, not an upper bound. Pair:
   ``write_string(address, text, *, null_terminator=False)``.

.. py:method:: read_bytes(address, length)
   :no-index:

   Read ``length`` raw bytes. Pair: ``write_bytes(address, data)``.
```

### Searching

```{eval-rst}
.. py:method:: search_by_value(pytype, bufflength=None, value=..., scan_type=ScanTypesEnum.EXACT_VALUE, *, progress_information=False, writeable_only=False, memory_regions=None)

   Yield every address holding ``value`` (compared per ``scan_type``).
   ``bufflength`` is optional (numeric types use their default width; ``str`` /
   ``bytes`` infer it from ``value``) — pass ``value`` by keyword when omitting
   it. See :doc:`../guide/searching` for a full walkthrough.

.. py:method:: search_by_value_between(pytype, bufflength=None, start=..., end=..., *, not_between=False, progress_information=False, writeable_only=False, memory_regions=None)

   Yield every address whose value is in ``[start, end]`` (or outside, with
   ``not_between=True``).

.. py:method:: search_by_addresses(pytype, bufflength=None, addresses=..., *, raise_error=False, memory_regions=None)

   Read each address in ``addresses`` once, yielding ``(address, value)``.
   Far faster than looping over :py:meth:`read_process_memory`. ``bufflength``
   is optional for numeric types; ``str`` / ``bytes`` still need an explicit
   size (no value to infer from) — pass ``addresses`` by keyword when omitting
   it.

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
.. py:method:: resolve_pointer_chain(base_address, offsets, *, ptr_size=None)

   Walk a multi-level pointer chain and return the final address.

.. py:method:: get_pointer(base_address, offsets=None, *, pytype=int, bufflength=None, ptr_size=None)

   Build a :py:class:`RemotePointer` bound to this process — a live,
   re-resolving handle. See :doc:`../guide/pointers`.

.. py:method:: scan_pointer_paths(target_address, *, max_depth=5, max_offset=0x400, ptr_size=None, aligned=True, writable_only=True, static_ranges=None, max_results=None, memory_regions=None, progress_callback=None)

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
