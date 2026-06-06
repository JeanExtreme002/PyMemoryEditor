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
.. py:method:: search_by_value(pytype, bufflength=None, value=..., scan_type=ScanTypesEnum.EXACT_VALUE, *, progress_information=False, writeable_only=False, memory_regions=None)
   :no-index:

   :param Type pytype: ``bool``, ``int``, ``float``, ``str`` or ``bytes``.
   :param int bufflength: value size in bytes (1, 2, 4, 8). **Optional** —
      defaults to ``None``: numeric types use their default width and ``str`` /
      ``bytes`` infer it from the encoded length of ``value``. Since it is
      optional, pass ``value`` by keyword when omitting it
      (``search_by_value(int, value=100)``).
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
.. py:method:: search_by_value_between(pytype, bufflength=None, start=..., end=..., *, not_between=False, progress_information=False, writeable_only=False, memory_regions=None)
   :no-index:
```

Same parameters as `search_by_value`, plus:

- `start`, `end` — the range boundaries (inclusive).
- `not_between` — when `True`, returns values **outside** the range.

`bufflength` is optional here too (defaults to `None`); pass `start` / `end` by
keyword when you omit it: `search_by_value_between(int, start=100, end=200)`.

## Search by addresses

When you already know **which addresses to check** (typically because you
scanned earlier), `search_by_addresses` is the right tool — it reads each
memory **page** only once and pulls every requested address out of it.

```python
addresses = [0x10000, 0x10010, 0x10020, ...]

for address, value in process.search_by_addresses(int, 4, addresses):
    print(f"0x{address:X} -> {value}")
```

If an address isn't backed by any mapped region (it falls in a gap, or its
`[address, address+bufflength)` runs past the end of its region), the value is
**always** `None` — `raise_error` does not turn that into an exception, because
there is nothing there to read. `raise_error=True` only affects an address that
*is* inside a mapped region but whose read fails (e.g. the page vanished): then
it raises `OSError` instead of yielding `None`.

### Method signature

```{eval-rst}
.. py:method:: search_by_addresses(pytype, bufflength=None, addresses=..., *, raise_error=False, memory_regions=None)
   :no-index:

   :param int bufflength: value size in bytes. **Optional** for numeric types
      (defaults to ``None`` → int→4, float→8, bool→1). ``str`` / ``bytes`` still
      require an explicit size — there is no value to infer it from, only
      addresses to read. Pass ``addresses`` by keyword when omitting it.
   :param Sequence[int] addresses: addresses to inspect.
   :param bool raise_error: when ``True``, raises ``OSError`` instead of yielding
      ``None`` for an address that is inside a mapped region but fails to read.
      Addresses with no backing region always yield ``None`` regardless.
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
    candidates = list(process.search_by_value(int, value=100, memory_regions=regions))

    # Refine — keep only those that now hold 95.
    refined = [
        addr
        for addr, value in process.search_by_addresses(int, addresses=candidates, memory_regions=regions)
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

## Scan acceleration (the `speed` extra)

By default every scan runs in pure Python, with the hottest paths already
delegated to C primitives: `bytes.find` for exact matches, `struct.iter_unpack`
to decode a region, and a **regex byte-class prefilter** for ordered *string*
comparisons (`BIGGER_THAN` / `SMALLER_THAN` / `VALUE_BETWEEN` on `str`), which
skips the long runs of non-matching bytes in C instead of stepping every offset.
What stays in Python is the per-value **comparison loop** of the ordered
*numeric* scans: for a multi-megabyte region it boxes and compares millions of
values one at a time.

Installing the optional [`speed`](../installation.md#install-with-scan-acceleration-speed)
extra replaces that loop with a single vectorized NumPy comparison:

```bash
pip install "PyMemoryEditor[speed]"
```

There is **nothing to enable** — PyMemoryEditor detects NumPy at import time and
routes the typed numeric scans through it automatically. Under the hood, each
region becomes a zero-copy typed array and the comparison runs once over the
whole array in C/SIMD:

```python
arr  = np.frombuffer(region, dtype="<i4")   # bytes -> int32 array, no copy
mask = arr > target                          # one C-level comparison
offsets = np.flatnonzero(mask) * 4           # match positions -> byte offsets
```

```{admonition} Identical results, just faster
:class: note

The NumPy path returns exactly the same addresses, in the same order, as the
pure-Python loop — it is a drop-in fast path, not a behavior change. An
equivalence test suite asserts this across every scan type, byte width and
signedness. If NumPy is not installed, the pure-Python loop runs instead and
nothing breaks.
```

### When it helps (and when it doesn't)

The win scales with how **selective** the scan is, because building the result
list is work both paths share — the acceleration is in the *comparison*, not in
emitting matches.

<table>
<tr><th>Scenario</th><th>Typical speedup</th></tr>
<tr><td>Selective scan of a large region (few matches — the usual first scan / refine step)</td><td><b>~10–30×</b></td></tr>
<tr><td>Scan where most values match (e.g. <code>&gt; 0</code> on mostly-positive data)</td><td>~2× (result building dominates)</td></tr>
<tr><td><code>str</code> ordered scans (<code>&gt;</code>, <code>&lt;</code>, <code>between</code>)</td><td>no NumPy fast path — instead C-accelerated by the regex byte-class prefilter (independent of the <code>speed</code> extra)</td></tr>
<tr><td><code>bytes</code> scans, or unusual widths (3/6/7 bytes)</td><td>no change (no NumPy fast path; pure-Python loop)</td></tr>
<tr><td><code>EXACT_VALUE</code> via <code>search_by_value</code></td><td>already <code>bytes.find</code> in C — NumPy not used</td></tr>
</table>

You can check whether the fast path is active:

```python
from PyMemoryEditor.util import NUMPY_AVAILABLE
print("NumPy acceleration:", NUMPY_AVAILABLE)
```

## Working with strings and bytes

All of the above methods work with `str` and `bytes` too:

```python
# Find every memory address holding the literal string "PLAYER".
for address in process.search_by_value(str, 6, "PLAYER"):
    print(hex(address))
```

Ordering for the comparison modes differs by type:

- **`str`** compares the UTF-8 bytes **lexicographically** (big-endian), so
  `"AA" < "AB" < "B"`. The shorter of two values is NUL-padded to `bufflength`
  before comparing, and a reversed `VALUE_BETWEEN` range (`start > end`) simply
  matches nothing.
- **`bytes`** compares using your system's `byteorder` — something to keep in
  mind when using `BIGGER_THAN` / `SMALLER_THAN` on raw bytes.

```{seealso}
- [Pattern scan](pattern-scan.md) — find data by **shape** with regex and AOB
  signatures.
- [Pointers](pointers.md) — once you've found a candidate, follow it through a
  pointer chain.
```
