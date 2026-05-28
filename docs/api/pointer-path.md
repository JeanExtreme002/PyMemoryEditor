# `PointerPath`

A discovered static pointer path, returned by `scan_pointer_paths`.

```python
from PyMemoryEditor import PointerPath
```

Resolving `base_address` and then walking `offsets` with
`resolve_pointer_chain` lands on the target. When the base sits inside a
known module, `module` / `module_offset` express it ASLR-independently so the
path survives a restart — feed it to `rebase()` in the next run.

## Construction

```{eval-rst}
.. py:class:: PointerPath(base_address, offsets, module=None, module_offset=None, ptr_size=8)

   :param int base_address: absolute static base for *this* run (the slot
      whose pointer the chain dereferences first).
   :param Tuple[int, ...] offsets: forward-order offsets, ready to hand to
      :py:meth:`resolve_pointer_chain`.
   :param Optional[str] module: name of the module containing
      ``base_address`` (``None`` when the base falls in a caller-supplied
      static range with no known module).
   :param Optional[int] module_offset: ``base_address - module.base_address``
      — the portable, ASLR-independent part of the base. ``None`` when
      ``module`` is.
   :param int ptr_size: pointer width — ``8`` for 64-bit (default) or ``4``
      for 32-bit.
```

`PointerPath` is a `@dataclass(frozen=True)` — instances are immutable and
hashable.

## Attributes

<table>
<tr><th>Attribute</th><th>Type</th><th>Meaning</th></tr>
<tr><td><code>base_address</code></td><td><code>int</code></td><td>Absolute static base for the run the path was found in.</td></tr>
<tr><td><code>offsets</code></td><td><code>Tuple[int, ...]</code></td><td>Forward-order offsets.</td></tr>
<tr><td><code>module</code></td><td><code>Optional[str]</code></td><td>Module owning <code>base_address</code>.</td></tr>
<tr><td><code>module_offset</code></td><td><code>Optional[int]</code></td><td><code>base_address - module.base_address</code>.</td></tr>
<tr><td><code>ptr_size</code></td><td><code>int</code></td><td>Pointer width (4 or 8).</td></tr>
</table>

## Methods

### Resolving

```{eval-rst}
.. py:method:: resolve(process)

   Walk this path in ``process`` and return the final target address.

   :param AbstractProcess process: the open process.
   :returns: the target address (``int``).

.. py:method:: to_pointer(process, *, pytype=int, bufflength=None)

   Build a live :py:class:`RemotePointer` for the value at the end of this
   path.

   :returns: a :py:class:`RemotePointer` re-resolving on every access.
```

### Rebasing across runs

```{eval-rst}
.. py:method:: rebase(process)

   Return a copy with ``base_address`` recomputed from the live module base
   in ``process`` — the call that makes a saved path valid again after a
   restart moved the module (ASLR).

   :raises ValueError: this path has no associated module (its base came
      from a caller-supplied static range), so it cannot be rebased.
   :raises LookupError: the module is not loaded in ``process``.
```

### Serialization

```{eval-rst}
.. py:method:: to_dict()

   Serialise to a JSON-friendly dict (hex strings) for export. The
   ASLR-independent part — ``module`` + ``module_offset`` + ``offsets`` —
   is what makes a saved path replayable in a later run via
   :py:meth:`from_dict` + :py:meth:`rebase`.

.. py:classmethod:: from_dict(data)

   Rebuild a :py:class:`PointerPath` from :py:meth:`to_dict` output. Numeric
   fields accept either hex strings (``"0x158"``) or plain ints.
```

### Comparison & display

```{eval-rst}
.. py:method:: recipe()

   The ASLR-independent identity of this path:
   ``(module, module_offset, offsets)``. Two paths from different runs
   describe the *same* pointer when their recipes are equal.

.. py:method:: __str__()

   Cheat Engine-style textual representation, e.g.::

      "game.exe"+0x10F4F4 -> [+0x0] -> +0x158
```

## Example workflows

### Saving and reloading

```python
paths = list(process.scan_pointer_paths(address))
process.save_pointer_paths(paths, "pointers.json")

# Later, in a different run:
loaded = process.load_pointer_paths("pointers.json")
for path in loaded:
    live = path.rebase(process)
    print(live.resolve(process))
```

### Building a live handle from a saved path

```python
loaded = process.load_pointer_paths("pointers.json")
hp_ptr = loaded[0].rebase(process).to_pointer(process, pytype=int, bufflength=4)
hp_ptr.value = 9999
```

### Intersecting independent scans

```python
stable = process.compare_pointer_scans(
    "scan1.json", "scan2.json", "scan3.json",
)
print(f"{len(stable)} stable pointers")
```

```{seealso}
- [Pointer scan guide](../guide/pointer-scan.md)
- [`RemotePointer`](remote-pointer.md)
```
