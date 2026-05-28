# Memory regions

A process's address space is split into **regions** — contiguous blocks of
memory, each with its own size, permissions and origin. Understanding the
region map is the foundation of memory editing: every read, write or scan
ultimately touches a region.

## Listing the regions

`get_memory_regions()` is a generator that yields one
[`MemoryRegion`](../api/memory-region.md) per region:

```python
with OpenProcess(process_name="game.exe") as process:
    for region in process.get_memory_regions():
        print(
            hex(region.address),
            region.size,
            "R" if region.is_readable else "-",
            "W" if region.is_writable else "-",
            "X" if region.is_executable else "-",
            "shared" if region.is_shared else "",
        )
```

## The `MemoryRegion` dataclass

Each region is an instance of `MemoryRegion` — an immutable
`@dataclass(frozen=True)` with the following fields:

<table>
<tr><th>Field</th><th>Type</th><th>Meaning</th></tr>
<tr><td><code>address</code></td><td><code>int</code></td><td>Base address of the region.</td></tr>
<tr><td><code>size</code></td><td><code>int</code></td><td>Region size in bytes.</td></tr>
<tr><td><code>is_readable</code></td><td><code>bool</code></td><td>True if the region can be read.</td></tr>
<tr><td><code>is_writable</code></td><td><code>bool</code></td><td>True if the region can be written.</td></tr>
<tr><td><code>is_executable</code></td><td><code>bool</code></td><td>True if the region contains executable code.</td></tr>
<tr><td><code>is_shared</code></td><td><code>bool</code></td><td>True if the region is a shared/file-backed mapping.</td></tr>
<tr><td><code>path</code></td><td><code>str</code></td><td>File backing the region (Linux only — empty on Windows/macOS).</td></tr>
<tr><td><code>struct</code></td><td>platform-specific</td><td>Raw platform descriptor (see below).</td></tr>
</table>

```{admonition} Immutability
:class: tip

`MemoryRegion` is frozen, so any region you obtain from
`get_memory_regions()` or `snapshot_memory_regions()` is safe to share across
threads or pass through functions without defensive copies.
```

### The platform-specific `struct`

The `struct` attribute carries the underlying OS-specific descriptor. You
usually won't need it — the portable booleans above are enough. When you do:

- **Windows** — `MEMORY_BASIC_INFORMATION_{32,64}` with `Protect` (PAGE_* bitmask)
  and `Type` (`MEM_PRIVATE` / `MEM_IMAGE` / `MEM_MAPPED`).
- **Linux** — a small struct with `Privileges` (bytes like `rwxp` / `rwxs`).
- **macOS** — a struct with `Protection` (`VM_PROT_*` bitmask) and `Shared`.

## Snapshotting for refine workflows

For iterative scans (the Cheat Engine "First Scan → Next Scan" loop),
`snapshot_memory_regions()` materializes the region list once so subsequent
calls can reuse it:

```python
regions = process.snapshot_memory_regions()

# Pass the same snapshot to as many scans as you want.
candidates = list(process.search_by_value(int, 4, 100, memory_regions=regions))
refined = list(process.search_by_addresses(int, 4, candidates, memory_regions=regions))
```

The return type is `MemoryRegionSnapshot` — a thin `list` subclass that
behaves exactly like `list[MemoryRegion]`. Internally, the scan helpers
detect via `isinstance(memory_regions, MemoryRegionSnapshot)` that the list
is already address-sorted and skip the per-call `sorted(...)` step.

```{admonition} Filtered snapshots are not pre-sorted anymore
:class: note

When you build a new list from a snapshot (`[r for r in snap if r.is_writable]`),
the result is a plain `list`, not a `MemoryRegionSnapshot`. The scan helpers
will re-sort it defensively — safe but slightly slower for huge region maps.
Pass the original snapshot when you can.
```

See [Searching memory](searching.md#the-refine-scan-workflow) for the full
recipe.

## Filtering regions yourself

Once you have the snapshot, you can filter it however you like before handing
it to a scan:

```python
# Only writable regions (skip read-only static data — much faster).
writable = [r for r in regions if r.is_writable]

for address in process.search_by_value(int, 4, target, memory_regions=writable):
    ...
```

## A complete region map

A small script that prints a textual memory map (similar to the GUI app's
Memory Map dialog):

```python
from PyMemoryEditor import OpenProcess

with OpenProcess(process_name="game.exe") as process:
    print(f"{'ADDRESS':<18}{'SIZE':>14}  RWX  Source")

    for region in process.get_memory_regions():
        rwx = "".join([
            "R" if region.is_readable else "-",
            "W" if region.is_writable else "-",
            "X" if region.is_executable else "-",
        ])
        print(
            f"0x{region.address:016X}  "
            f"{region.size:>12,}  {rwx}  "
            f"{region.path or ''}"
        )
```

```{seealso}
- [API → `MemoryRegion`](../api/memory-region.md)
- [Modules & threads](modules-threads.md) — list loaded DLLs/SOs/dylibs and threads.
- [Searching memory](searching.md) — the high-level scan API.
```
