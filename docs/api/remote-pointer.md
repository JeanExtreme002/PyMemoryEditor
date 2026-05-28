# `RemotePointer`

A re-resolving, read/write handle to a typed value in a target process.

```python
from PyMemoryEditor import RemotePointer
```

Most users build a `RemotePointer` through `process.get_pointer(...)`. The
constructor is documented here for completeness.

## Construction

```{eval-rst}
.. py:class:: RemotePointer(process, base_address, offsets=None, *, pytype=int, bufflength=None, ptr_size=8)

   :param AbstractProcess process: the open process the value lives in.
   :param int base_address: starting address. For a direct handle this is the
      address of the value itself; for a pointer chain it is typically
      ``module_base + static_offset``.
   :param offsets: how to reach the value from ``base_address``:

      * ``None`` (default) — **direct handle**: ``address`` *is*
        ``base_address``, with no dereferencing. Use this to wrap an address
        you already have (e.g. from :py:meth:`search_by_value`).
      * a sequence (including the empty list ``[]``) — the value sits at the
        end of a pointer chain. ``address`` is recomputed on every access via
        :py:meth:`resolve_pointer_chain`. ``[]`` dereferences ``base_address``
        once; a non-empty list walks each offset, dereferencing all but the
        last.

   :param Type pytype: how to interpret the bytes — ``bool``, ``int``,
      ``float``, ``str`` or ``bytes``. Defaults to ``int``.
   :param int bufflength: value size in bytes. Optional for numeric types
      (int→4, float→8, bool→1); required for ``str`` / ``bytes``.
   :param int ptr_size: pointer width used when walking ``offsets`` — 8 for
      64-bit targets (default), 4 for 32-bit. Ignored for direct handles.
```

## Properties

```{eval-rst}
.. py:attribute:: process
   :type: AbstractProcess

   The process this pointer reads from / writes to.

.. py:attribute:: base_address
   :type: int

   The starting address the pointer was built with.

.. py:attribute:: offsets
   :type: Optional[Sequence[int]]

   The pointer-chain offsets, or ``None`` for a direct handle.

.. py:attribute:: address
   :type: int

   The address the value currently lives at. **Recomputed on every access**
   for a pointer chain — so each read reflects where the target's pointers
   point *now*.

.. py:property:: value

   Read or write the value at :py:attr:`address` using the bound type.

      .. code-block:: python

         hp_ptr.value           # read
         hp_ptr.value = 9999    # write
```

## Methods

```{eval-rst}
.. py:method:: read(pytype=None, bufflength=None)

   Read the value at :py:attr:`address`, optionally overriding the bound type
   for one-off reads.

   :param Type pytype: interpret the bytes as this type for this call only.
   :param int bufflength: override the bound buffer size.
   :returns: the decoded value.

.. py:method:: write(value, pytype=None, bufflength=None)

   Write ``value`` to :py:attr:`address`, optionally overriding the bound
   type. Returns whatever :py:meth:`write_process_memory` returns.
```

## Operators

`RemotePointer` supports C-style pointer arithmetic:

```{eval-rst}
.. py:method:: __add__(delta)
.. py:method:: __radd__(delta)

   ``ptr + n`` (or ``n + ptr``) → a **new** pointer ``n`` bytes ahead. Does
   not touch memory.

.. py:method:: __sub__(other)

   - ``ptr - n`` → a new pointer ``n`` bytes behind.
   - ``ptr - other`` (where ``other`` is a ``RemotePointer``) → the byte
     distance between the two resolved addresses.

.. py:method:: __int__()

   The resolved :py:attr:`address`. Useful for arithmetic and logging:

      .. code-block:: python

         print(f"HP is at 0x{int(hp_ptr):X}")

.. py:method:: __repr__()

   Diagnostic representation, e.g.
   ``<RemotePointer base=0x14010F4F4 -> [0, 344] pytype=int>``.
```

## Lazy chain folding

When you do `hp_ptr + 4`, the shift is folded into the **last** offset of the
chain (rather than the resolved address), so the returned pointer still
re-walks the chain on every access. In other words, `(hp_ptr + 4)` keeps
following the target as it moves around the heap — it doesn't snapshot the
address at shift time.

## Examples

### Direct handle from a scan

```python
addresses = list(process.search_by_value(int, 4, 100))
ptr = process.get_pointer(addresses[0], pytype=int, bufflength=4)

ptr.value = 9999
```

### Chained handle from a cheat-table entry

```python
# "game.exe" + 0x10F4F4 -> [+0x0] -> [+0x158]
module = next(m for m in process.get_modules() if m.name == "game.exe")
hp = process.get_pointer(
    module.base_address + 0x10F4F4,
    [0x0, 0x158],
    pytype=int,
    bufflength=4,
)
hp.value -= 10
```

### Walking sibling fields with arithmetic

```python
# HP and MP are stored side-by-side as 4-byte ints.
mp = hp + 4
mp.value = 100
```

### Reading the same address as a different type

```python
# Peek the same address as raw bytes without building a second handle.
print(hp.read(pytype=bytes, bufflength=4))
```

```{seealso}
- [Pointers](../guide/pointers.md)
- [Pointer scan](../guide/pointer-scan.md)
- [`PointerPath`](pointer-path.md)
```
