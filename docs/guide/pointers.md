# Pointers

In a running program, most values you care about are reached through a
**pointer chain** — a static base address plus a series of offsets that
ultimately land on the value. Cheat Engine's "pointer scan" feature is built
around this idea, and PyMemoryEditor offers the same workflow:

- **`resolve_pointer_chain`** — walk a chain you already know.
- **`RemotePointer`** — a live, re-resolving handle that re-walks the chain on
  every read/write.
- **`scan_pointer_paths`** — the reverse operation: find chains that resolve
  to a given address. See [Pointer scan](pointer-scan.md).

## Why pointer chains?

A scanned address (`0x1FA3C140`) typically **changes every run**: the OS loads
modules at randomized base addresses (ASLR), and the heap allocates objects in
different places each time you launch the program.

A **multi-level pointer**, in contrast, expresses a value as
`module + offset → [+x] → [+y] → …`. The *static base* (the module + static
offset) doesn't change between runs once ASLR is accounted for, so the same
recipe works every time.

## Walking a chain

`resolve_pointer_chain` performs the walk and returns the **final address**
where the value lives:

```python
# Cheat-table entry:  "game.exe" + 0x10F4F4 -> [+0x0] -> [+0x158]
module = next(m for m in process.get_modules() if m.name == "game.exe")
base = module.base_address + 0x10F4F4

hp_address = process.resolve_pointer_chain(base, [0x0, 0x158])
hp = process.read_process_memory(hp_address, int, 4)
```

### Method signature

```{eval-rst}
.. py:method:: resolve_pointer_chain(base_address, offsets, *, ptr_size=8)
   :no-index:

   Walk a multi-level pointer chain.

   Reads ``ptr_size`` bytes at ``base_address`` to obtain the first pointer,
   then for each offset in ``offsets[:-1]`` adds the offset and dereferences
   again. The **last** offset is added *without* dereferencing — the returned
   integer is the final address where the value of interest lives.

   :param int base_address: starting address — typically
      ``module_base + static_offset``.
   :param Sequence[int] offsets: sequence of offsets to walk. Pass ``[]`` to
      dereference ``base_address`` once and return that pointer.
   :param int ptr_size: pointer width — ``8`` for 64-bit targets (default),
      ``4`` for 32-bit.
   :returns: the final address (an ``int``).
```

```{admonition} 32-bit vs 64-bit
:class: warning

Pass `ptr_size=4` when the target is a 32-bit process; pass `ptr_size=8` (the
default) for 64-bit. Mixing them up reads pointers of the wrong width and
yields garbage addresses.
```

## Live pointers: `RemotePointer`

`resolve_pointer_chain` finds an address **once**. A `RemotePointer` wraps the
same recipe in a **reusable handle** — every time you read `.value`, the chain
is re-walked, so the handle keeps working even as the target moves things
around the heap.

```python
# A handle to the player's HP, behind a two-level pointer.
hp_ptr = process.get_pointer(
    base + 0x10F4F4,
    [0x0, 0x158],
    pytype=int,
    bufflength=4,
)

print(hp_ptr.value)   # read it
hp_ptr.value = 9999   # write it
```

### Direct vs chained handles

The `offsets` argument controls what `RemotePointer` does on every access:

<table>
<tr><th><code>offsets</code></th><th>Behavior</th></tr>
<tr><td><code>None</code> <em>(default)</em></td><td><b>Direct handle</b>: <code>address</code> = <code>base_address</code>, no dereferencing. Use this to wrap an address you already have (e.g. from <code>search_by_value</code>).</td></tr>
<tr><td><code>[]</code> (empty list)</td><td>Dereferences <code>base_address</code> once and reads the value at that pointer.</td></tr>
<tr><td><code>[o1, o2, ...]</code></td><td>Walks the chain on every access — <code>resolve_pointer_chain</code> semantics.</td></tr>
</table>

### Pointer arithmetic

`RemotePointer` supports C-style arithmetic. Adding an integer returns a
**new** handle, without touching memory:

```python
# Mana is stored right after HP, so just step 4 bytes forward.
mp_ptr = hp_ptr + 4
print(mp_ptr.value)
```

You can also subtract two pointers to get a byte distance:

```python
distance = mp_ptr - hp_ptr   # 4
```

### `RemotePointer` API

```{eval-rst}
.. py:class:: RemotePointer(process, base_address, offsets=None, *, pytype=int, bufflength=None, ptr_size=8)
   :no-index:

   A re-resolving, read/write handle to a typed value in a target process.

   .. py:property:: process
      :no-index:

      The :py:class:`AbstractProcess` this pointer reads from / writes to.

   .. py:property:: base_address
      :no-index:

      The starting address the pointer was built with.

   .. py:property:: offsets
      :no-index:

      The pointer-chain offsets, or ``None`` for a direct handle.

   .. py:property:: address
      :no-index:

      The address the value currently lives at — recomputed on every access
      for a pointer chain.

   .. py:property:: value
      :no-index:

      Read or write the value at :py:attr:`address` using the bound type.

   .. py:method:: read(pytype=None, bufflength=None)
      :no-index:

      Read the value at :py:attr:`address`, optionally overriding the bound
      type for one-off reads.

   .. py:method:: write(value, pytype=None, bufflength=None)
      :no-index:

      Write ``value`` to :py:attr:`address`, optionally overriding the bound
      type.

   .. py:method:: __add__(delta)
      :no-index:

      ``ptr + n`` → a new pointer ``n`` bytes ahead.

   .. py:method:: __sub__(other)
      :no-index:

      ``ptr - n`` → a new pointer ``n`` bytes behind.
      ``ptr - other`` (where ``other`` is a ``RemotePointer``) → the byte
      distance between the two resolved addresses.

   .. py:method:: __int__()
      :no-index:

      The resolved :py:attr:`address` — handy for arithmetic and logging.
```

## Building a handle from `process.get_pointer()`

A small convenience wrapper around the constructor:

```python
ptr = process.get_pointer(
    base_address=module.base_address + 0x10F4F4,
    offsets=[0x0, 0x158],
    pytype=int,
    bufflength=4,
    ptr_size=8,
)
```

```{seealso}
- [Pointer scan](pointer-scan.md) — discover chains that resolve to a given
  address.
- [API reference](../api/remote-pointer.md) — full `RemotePointer` reference.
```
