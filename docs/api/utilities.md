# Utilities

A small set of helpers exposed under `PyMemoryEditor.util` for advanced
callers that want to operate on bytes directly — convert between Python and
ctypes types, compile AOB patterns without a live process, or chunk an
arbitrary region for scanning.

```python
from PyMemoryEditor.util import (
    resolve_bufflength,
    resolve_bufflength_for_value,
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
    NUMPY_AVAILABLE,
)
```

## Type conversion

```{eval-rst}
.. py:function:: resolve_bufflength(pytype, bufflength)

   Return a concrete buffer length: the caller-provided value, or the default
   for numeric ``pytype`` when ``bufflength`` is ``None``.

   :raises ValueError: ``bufflength`` is required for ``pytype=str`` /
      ``pytype=bytes``.

.. py:function:: resolve_bufflength_for_value(pytype, bufflength, *values)

   Like :py:func:`resolve_bufflength`, but for operations that already carry
   the value(s) being matched (the ``search_by_value`` family). When
   ``bufflength`` is ``None``: numeric / bool types fall back to the default
   width (int→4, float→8, bool→1); ``str`` / ``bytes`` infer the width from the
   longest encoded value instead of raising (``str`` encoded as UTF-8), so
   ``search_by_value(str, value="hi")`` works without the caller counting
   bytes. For a range search the shorter endpoint is NUL-padded up to this
   width.

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
   :raises TypeError: if ``pattern`` is not a ``str``, ``bytes`` or
      ``re.Pattern[bytes]``.
```

### Example

```python
from PyMemoryEditor.util import compile_pattern

regex, byte_length = compile_pattern("48 8B ? 00 00")
print(regex.pattern)   # b'H\x8b.\x00\x00'  (re.escape prints 0x48 as 'H')
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
   256 MiB). Tunes the trade-off between syscall overhead (small chunks) and
   peak memory use (huge chunks).

.. py:function:: iter_region_chunks(region_size, target_value_size, max_chunk=DEFAULT_MAX_REGION_CHUNK)

   Return an iterable of ``(offset, chunk_size)`` pairs that walk a single
   memory region in bounded-size chunks. Regions up to ``max_chunk`` return a
   single-element tuple (avoiding generator overhead in the common, hot path);
   larger ones return a lazy generator that yields **contiguous,
   non-overlapping** chunks whose size is a
   multiple of ``target_value_size`` so a typed numeric scan never splits a value
   across a boundary. Boundary handling for *patterns* is done one level up by
   the scanner (it overlaps consecutive chunks by ``pattern_length - 1`` bytes);
   arbitrary ``str`` matches in a region larger than ``max_chunk`` may still be
   missed at a chunk boundary — a documented limitation.

.. py:function:: scan_memory(...)
.. py:function:: scan_memory_for_exact_value(...)

   Low-level scan kernels used by the backends. Public for advanced use only —
   the high-level :py:meth:`search_by_value` / :py:meth:`search_by_pattern`
   methods are the recommended API.

.. py:data:: NUMPY_AVAILABLE

   ``True`` when NumPy is importable, in which case eligible numeric scans use
   the vectorized fast path. Install it via the ``speed`` extra
   (``pip install PyMemoryEditor[speed]``). Scan results are identical with or
   without it.
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

   True/False from a platform descriptor
   (``MEMORY_BASIC_INFORMATION_32`` / ``MEMORY_BASIC_INFORMATION_64`` on
   Windows; ``MEMORY_BASIC_INFORMATION`` on Linux; the VM struct on macOS). For
   a fully-populated region,
   prefer the boolean attributes on :py:class:`MemoryRegion`
   (``region.is_readable``, etc.).

.. py:function:: region_path(struct)

   Best-effort path of the file backing the region, or ``""`` when unknown.
   Linux reads it from ``/proc/<pid>/maps``; Windows uses
   ``GetMappedFileNameW`` (NT device path); macOS uses
   ``proc_regionfilename``.

.. py:function:: make_region(address, size, struct, *, path="")

   Build a fully-populated :py:class:`MemoryRegion` from a platform struct.
   The four boolean fields and ``path`` are computed once via the predicates
   above. When *path* is non-empty it overrides the struct-based
   ``region_path()`` lookup. Backends call this once per region; user code
   rarely needs it.
```

```{seealso}
- [Memory regions](../guide/memory-regions.md)
- [Pattern scan](../guide/pattern-scan.md)
```
