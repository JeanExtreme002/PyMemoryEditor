# Utilities

A small set of helpers exposed under `PyMemoryEditor.util` for advanced
callers that want to operate on bytes directly — convert between Python and
ctypes types, compile AOB patterns without a live process, or chunk an
arbitrary region for scanning.

```python
from PyMemoryEditor.util import (
    resolve_bufflength,
    convert_from_byte_array,
    value_to_bytes,
    values_to_bytes,
    get_c_type_of,
    compile_pattern,
    iter_region_chunks,
    scan_memory,
    scan_memory_for_exact_value,
    PatternLike,
    DEFAULT_MAX_REGION_CHUNK,
)
```

## Type conversion

```{eval-rst}
.. py:function:: resolve_bufflength(pytype, bufflength)

   Return a concrete buffer length: the caller-provided value, or the default
   for numeric ``pytype`` when ``bufflength`` is ``None``.

   :raises ValueError: ``bufflength`` is required for ``pytype=str`` /
      ``pytype=bytes``.

.. py:function:: convert_from_byte_array(byte_array, pytype, length)

   Convert a ctypes byte array to a Python value of type ``pytype``. String
   decoding uses ``errors="replace"``.

.. py:function:: value_to_bytes(pytype, bufflength, value)

   Encode a single value as fixed-width bytes using the same ctypes
   representation the backend compares against.

.. py:function:: values_to_bytes(pytype, bufflength, value)

   Convert either a single value or a tuple of values (for
   ``VALUE_BETWEEN`` / ``NOT_VALUE_BETWEEN``) to the corresponding byte form.

.. py:function:: get_c_type_of(pytype, length)

   Return the underlying ctypes object for the given Python type and width.
```

## Pattern compilation

```{eval-rst}
.. py:function:: compile_pattern(pattern, *, byte_length=0)

   Compile ``pattern`` into a ``(re.Pattern[bytes], byte_length)`` pair.

   :param pattern: an IDA-style hex string, a raw bytes regex, or a compiled
      ``re.Pattern[bytes]``.
   :param int byte_length: required for regex / compiled patterns — the
      number of bytes one match consumes.
   :raises ValueError: malformed IDA-style token, or ``byte_length`` omitted
      for a regex / pre-compiled pattern.
```

### Example

```python
from PyMemoryEditor.util import compile_pattern

regex, byte_length = compile_pattern("48 8B ? 00 00")
print(regex.pattern)   # b'\\x48\\x8B.\\x00\\x00'
print(byte_length)     # 5
```

```{eval-rst}
.. py:data:: PatternLike

   Type alias: ``Union[str, bytes, re.Pattern[bytes]]``. The set of input
   forms ``compile_pattern`` accepts.
```

## Region chunking

```{eval-rst}
.. py:data:: DEFAULT_MAX_REGION_CHUNK

   Maximum chunk size used by :py:func:`iter_region_chunks` (currently
   16 MiB). Tunes the trade-off between syscall overhead (small chunks) and
   peak memory use (huge chunks).

.. py:function:: iter_region_chunks(region_size, item_size)

   Yield ``(offset, chunk_size)`` pairs that walk a single memory region in
   bounded-size chunks. The chunks slightly **overlap** so a pattern straddling
   a boundary is still emitted by the higher-level scanner.

.. py:function:: scan_memory(...)
.. py:function:: scan_memory_for_exact_value(...)

   Low-level scan kernels used by the backends. Public for advanced use only —
   the high-level :py:meth:`search_by_value` / :py:meth:`search_by_pattern`
   methods are the recommended API.
```

## Region predicates

The helpers in `PyMemoryEditor.process.region` operate on a **raw platform
struct** — the same ``struct`` field carried by a
[`MemoryRegion`](memory-region.md). Useful when you've obtained a platform
descriptor outside the normal flow and want to compute the portable booleans
yourself.

```python
from PyMemoryEditor.process.region import (
    is_region_readable,
    is_region_writable,
    is_region_executable,
    is_region_shared,
    region_path,
    make_region,
)
```

```{eval-rst}
.. py:function:: is_region_readable(struct)
.. py:function:: is_region_writable(struct)
.. py:function:: is_region_executable(struct)
.. py:function:: is_region_shared(struct)

   True/False from a platform descriptor (``MEMORY_BASIC_INFORMATION`` on
   Windows/Linux; the VM struct on macOS). For a fully-populated region,
   prefer the boolean attributes on :py:class:`MemoryRegion`
   (``region.is_readable``, etc.).

.. py:function:: region_path(struct)

   Best-effort path of the file backing the region, or ``""`` when unknown
   (Linux only — Windows/macOS would need extra syscalls).

.. py:function:: make_region(address, size, struct)

   Build a fully-populated :py:class:`MemoryRegion` from a platform struct.
   The four boolean fields and ``path`` are computed once via the predicates
   above. Backends call this once per region; user code rarely needs it.
```

```{seealso}
- [Memory regions](../guide/memory-regions.md)
- [Pattern scan](../guide/pattern-scan.md)
```
