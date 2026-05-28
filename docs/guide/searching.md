# Searching memory

The bread and butter of memory editing — find every address in the process
that holds a value you can describe.

PyMemoryEditor offers three search APIs:

<table>
<tr><th>Method</th><th>What it does</th></tr>
<tr><td><a href="#search-by-value"><code>search_by_value</code></a></td><td>Find every address holding a specific value (with eight comparison modes).</td></tr>
<tr><td><a href="#search-by-range"><code>search_by_value_between</code></a></td><td>Find every address whose value is inside (or outside) a range.</td></tr>
<tr><td><a href="#search-by-addresses"><code>search_by_addresses</code></a></td><td>Look up the values at a known list of addresses — the refine step.</td></tr>
</table>

For locating **code or byte patterns** (AOB / signatures), see the dedicated
[Pattern scan guide](pattern-scan.md).

## Search by value

```python
from PyMemoryEditor import OpenProcess

with OpenProcess(process_name="game.exe") as process:
    for address in process.search_by_value(int, 4, 100):
        print(f"Found at 0x{address:X}")
```

`search_by_value` is a **generator** — it yields one match at a time as it
scans. Wrap it with `list(...)` only if you actually need every match in
memory.

### Method signature

```{eval-rst}
.. py:method:: search_by_value(pytype, bufflength, value, scan_type=ScanTypesEnum.EXACT_VALUE, *, progress_information=False, writeable_only=False, memory_regions=None)
   :no-index:

   :param Type pytype: ``bool``, ``int``, ``float``, ``str`` or ``bytes``.
   :param int bufflength: value size in bytes (1, 2, 4, 8). Pass ``None`` for
      numeric types to use the default.
   :param value: the value to look for.
   :param ScanTypesEnum scan_type: comparison mode — see below.
   :param bool progress_information: when ``True``, yields ``(address, info)`` tuples
      so you can update a progress bar.
   :param bool writeable_only: when ``True``, only scans writable regions
      (faster, drops read-only static data).
   :param memory_regions: an optional snapshot — see :ref:`refine-scan-workflow`.
   :returns: a generator of addresses (or ``(address, info)`` tuples).
```

### Comparison modes

The optional `scan_type` controls how each value in memory is compared to your
target. Every mode is a member of `ScanTypesEnum`:

<table>
<tr><th>Mode</th><th>Match when…</th></tr>
<tr><td><code>EXACT_VALUE</code> <em>(default)</em></td><td>value == target</td></tr>
<tr><td><code>NOT_EXACT_VALUE</code></td><td>value != target</td></tr>
<tr><td><code>BIGGER_THAN</code></td><td>value &gt; target</td></tr>
<tr><td><code>SMALLER_THAN</code></td><td>value &lt; target</td></tr>
<tr><td><code>BIGGER_THAN_OR_EXACT_VALUE</code></td><td>value &ge; target</td></tr>
<tr><td><code>SMALLER_THAN_OR_EXACT_VALUE</code></td><td>value &le; target</td></tr>
<tr><td><code>VALUE_BETWEEN</code></td><td>min &le; value &le; max  (use <code>search_by_value_between</code>)</td></tr>
<tr><td><code>NOT_VALUE_BETWEEN</code></td><td>value &lt; min or value &gt; max</td></tr>
</table>

```python
from PyMemoryEditor import OpenProcess, ScanTypesEnum

with OpenProcess(process_name="game.exe") as process:
    # Every address that holds a value bigger than 1_000_000.
    for address in process.search_by_value(
        int, 4, 1_000_000,
        scan_type=ScanTypesEnum.BIGGER_THAN,
    ):
        print(hex(address))
```

### Showing progress

Long scans on big processes can take a while. Pass `progress_information=True`
to get a small dict with each match:

```python
for address, info in process.search_by_value(int, 4, target, progress_information=True):
    pct = info["progress"] * 100
    print(f"0x{address:X} | {pct:5.1f}%")
```

The `info` dict has at least a `progress` key (a float in `[0, 1]`).

## Search by range

For value ranges (e.g. "find every address holding 100..200"):

```python
for address in process.search_by_value_between(int, 4, 100, 200):
    print(hex(address))

# The inverse — every address whose value is OUTSIDE the range:
for address in process.search_by_value_between(
    int, 4, 100, 200, not_between=True,
):
    print(hex(address))
```

### Method signature

```{eval-rst}
.. py:method:: search_by_value_between(pytype, bufflength, start, end, *, not_between=False, progress_information=False, writeable_only=False, memory_regions=None)
   :no-index:
```

Same parameters as `search_by_value`, plus:

- `start`, `end` — the range boundaries (inclusive).
- `not_between` — when `True`, returns values **outside** the range.

## Search by addresses

When you already know **which addresses to check** (typically because you
scanned earlier), `search_by_addresses` is the right tool — it reads each
memory **page** only once and pulls every requested address out of it.

```python
addresses = [0x10000, 0x10010, 0x10020, ...]

for address, value in process.search_by_addresses(int, 4, addresses):
    print(f"0x{address:X} -> {value}")
```

If an address falls in an unmapped page, the value is `None` (unless
`raise_error=True`).

### Method signature

```{eval-rst}
.. py:method:: search_by_addresses(pytype, bufflength, addresses, *, raise_error=False, memory_regions=None)
   :no-index:

   :param Sequence[int] addresses: addresses to inspect.
   :param bool raise_error: when ``True``, raises ``OSError`` instead of yielding
      ``None`` for an unreadable address.
   :param memory_regions: optional snapshot.
   :returns: a generator of ``(address, value)`` tuples.
```

(refine-scan-workflow)=

## The refine-scan workflow

For the classic Cheat-Engine loop — *"first scan → restrict → restrict"* —
enumerate the memory regions **once** and reuse the snapshot across every
subsequent call. On heavy targets (browsers, JVMs with 100 000+ regions) this
is a massive win because the per-call region enumeration is the dominant cost
otherwise.

```python
with OpenProcess(pid=1234) as process:
    regions = process.snapshot_memory_regions()

    # First pass — every address holding 100.
    candidates = list(process.search_by_value(int, None, 100, memory_regions=regions))

    # Refine — keep only those that now hold 95.
    refined = [
        addr
        for addr, value in process.search_by_addresses(int, None, candidates, memory_regions=regions)
        if value == 95
    ]
```

All of `snapshot_memory_regions()`, `search_by_value`, `search_by_value_between`
and `search_by_addresses` accept the same `memory_regions=` keyword. Pass an
empty list (`[]`) to explicitly scan nothing.

```{admonition} Keep the snapshot sorted
:class: tip

The snapshot is pre-sorted by base address and tagged so that helpers skip
their per-call `sorted(...)` step on reuse. Don't reorder the returned list
manually; if you must slice or filter, pass the result of
`sorted(my_slice, key=...)` — the helpers re-sort defensively when the tag is
missing.
```

## Working with strings and bytes

All of the above methods work with `str` and `bytes` too:

```python
# Find every memory address holding the literal string "PLAYER".
for address in process.search_by_value(str, 6, "PLAYER"):
    print(hex(address))
```

For `bytes`, comparison ordering depends on your system's `byteorder` —
something to keep in mind when using `BIGGER_THAN` / `SMALLER_THAN` on raw
bytes.

```{seealso}
- [Pattern scan](pattern-scan.md) — find data by **shape** with regex and AOB
  signatures.
- [Pointers](pointers.md) — once you've found a candidate, follow it through a
  pointer chain.
```
