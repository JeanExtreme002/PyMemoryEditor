# Pointer scan (reverse)

A scanned address is gone the next launch — the OS loads everything somewhere
new every time (ASLR). A pointer chain is the cure, but where do you *get* the
chain?

**`scan_pointer_paths`** is the inverse of `resolve_pointer_chain`: give it the
value's address *right now*, and the library finds the static paths
(`module + offsets`) that lead to it.

## The basic scan

```python
# The value is at this address right now (e.g. from search_by_value).
for path in process.scan_pointer_paths(0x1FA3C140):
    print(path)
    # "game.exe"+0x10F4F4 -> [+0x0] -> +0x158
    print(hex(path.resolve(process)))
```

Each result is a `PointerPath` — see [API reference](../api/pointer-path.md).
It carries everything you need to reconstruct the chain in another run.

## Method signature

```{eval-rst}
.. py:method:: scan_pointer_paths(target_address, *, max_depth=5, max_offset=0x400, ptr_size=8, aligned=True, writable_only=True, static_ranges=None, max_results=None, memory_regions=None, progress_callback=None)
   :no-index:

   :param int target_address: the dynamic address to find pointer paths to
      (typically just found via :py:meth:`search_by_value`).
   :param int max_depth: maximum number of pointer levels (offsets) in a chain.
      Deeper scans find more paths but cost exponentially more — 1–7 is typical.
   :param int max_offset: largest positive offset a single hop may add (the
      struct-size window). Bigger values catch fields deeper inside objects at
      the cost of many more candidate paths.
   :param int ptr_size: pointer width — ``8`` (default) for 64-bit, ``4`` for 32-bit.
   :param bool aligned: only consider pointers at natural alignment (default,
      much faster). Set ``False`` to also scan misaligned slots (slow).
   :param bool writable_only: build the pointer map from writable memory only
      (default — faster and usually correct).
   :param static_ranges: explicit ``(start, size)`` ranges to treat as valid
      chain bases. Defaults to the image range of every loaded module.
   :param int max_results: stop after yielding this many paths.
      Recommended for shallow exploration.
   :param memory_regions: optional snapshot from
      :py:meth:`snapshot_memory_regions`.
   :param callable progress_callback: ``callback(fraction)`` invoked as the
      pointer map is built (the long phase), ``fraction`` in ``[0, 1]``.
   :returns: a generator of :py:class:`PointerPath`.
```

## Tuning the scan

A first scan usually finds **many** candidates. Start narrow and widen only if
needed:

```python
for path in process.scan_pointer_paths(
    address,
    max_depth=2,        # start shallow
    max_offset=0x100,   # smaller struct window
    max_results=20,     # don't enumerate forever
):
    print(path)
```

The cost grows **exponentially** with `max_depth` — going from 4 to 6 is
usually a 10× slowdown.

```{admonition} macOS note
:class: tip

On macOS, `ModuleInfo.size` covers only the `__TEXT` segment, so global
pointers in `__DATA` may fall outside the default static set. The library
overrides this by walking every Mach-O segment internally, but if you pass
`static_ranges=` explicitly, remember to include `__DATA` ranges as well.
```

## Narrowing down to the real pointer

The reliable pointers are the ones that keep working **after** the value
moves. So you save a scan, restart the target, and rescan — keeping only the
paths that still land on the value. Repeat a couple of times and a handful of
solid pointers remain.

### Save → restart → rescan

```python
# Run 1 — scan and save.
pointer_paths = process.scan_pointer_paths(address)
process.save_pointer_paths(pointer_paths, "scan1.json")

# ... close the target, restart it, find the value's new address again ...

# Run 2 — keep only the saved paths that still reach it.
survivors = process.rescan_pointer_paths("scan1.json", new_address)
process.save_pointer_paths(survivors, "scan2.json")
```

### Compare independent scans

Prefer working from independent scans? Save one per run, then **intersect**
them — the paths present in *every* file are your stable pointers (no live
address needed):

```python
stable = process.compare_pointer_scans(
    "scan1.json", "scan2.json", "scan3.json",
)
```

Once you're down to one pointer, use it forever:

```python
live = path.rebase(process).to_pointer(process, pytype=int, bufflength=4)
live.value = 9999
```

## Persistence helpers

<table>
<tr><th>Method</th><th>What it does</th></tr>
<tr><td><code>save_pointer_paths(paths, file)</code></td><td>Serialize a list of paths to a JSON file.</td></tr>
<tr><td><code>load_pointer_paths(file)</code></td><td>Re-create the list from a saved file.</td></tr>
<tr><td><code>rescan_pointer_paths(paths, target)</code></td><td>Keep only the paths that still resolve to <code>target</code>.</td></tr>
<tr><td><code>compare_pointer_scans(*sources)</code></td><td>Intersect several saved scans — paths present in every one.</td></tr>
</table>

The saved file stores each path's **module + offsets** — the ASLR-independent
part — so it stays valid even though absolute addresses change.

## The `PointerPath` dataclass

A summary of the methods you'll use most:

```{eval-rst}
.. py:class:: PointerPath
   :no-index:

   .. py:method:: resolve(process)
      :no-index:

      Walk this path in ``process`` and return the final target address.

   .. py:method:: to_pointer(process, *, pytype=int, bufflength=None)
      :no-index:

      Build a live :py:class:`RemotePointer` for the value at the end of this
      path.

   .. py:method:: rebase(process)
      :no-index:

      Return a copy with ``base_address`` recomputed from the module's
      **current** load address — the call that makes a saved path valid again
      after a restart.

   .. py:method:: to_dict()
      :no-index:

      Serialise to a JSON-friendly dict (hex strings) for export.

   .. py:classmethod:: from_dict(data)
      :no-index:

      Rebuild a :py:class:`PointerPath` from :py:meth:`to_dict` output.
```

See the full reference at [API → PointerPath](../api/pointer-path.md).

```{seealso}
- [Pointers](pointers.md) — walking chains you already know.
- [API → PointerPath](../api/pointer-path.md)
```
