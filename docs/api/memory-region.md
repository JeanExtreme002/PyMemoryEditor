# `MemoryRegion`

A single memory region in a target process's address space.

```python
from PyMemoryEditor import MemoryRegion
```

`MemoryRegion` is a `@dataclass(frozen=True)` yielded by
`process.get_memory_regions()`. Each instance describes one contiguous block
of memory with its address, size, permissions and backing path.

## Fields

```{eval-rst}
.. py:class:: MemoryRegion(address, size, struct=None, is_readable=False, is_writable=False, is_executable=False, is_shared=False, path="")

   .. py:attribute:: address
      :type: int

      Base address of the region.

   .. py:attribute:: size
      :type: int

      Region size in bytes.

   .. py:attribute:: struct
      :type: Any

      Platform-specific descriptor. Portable code should rely on the boolean
      fields below instead of poking at this directly. Shape varies:

      - **Windows** — ``MEMORY_BASIC_INFORMATION_{32,64}`` with ``Protect``
        (PAGE_* bitmask) and ``Type`` (``MEM_PRIVATE`` / ``MEM_IMAGE`` /
        ``MEM_MAPPED``).
      - **Linux** — small struct with ``Privileges`` (bytes like ``rwxp`` /
        ``rwxs``).
      - **macOS** — struct with ``Protection`` (``VM_PROT_*`` bitmask) and
        ``Shared``.

   .. py:attribute:: is_readable
      :type: bool

      ``True`` when the region can be read.

   .. py:attribute:: is_writable
      :type: bool

      ``True`` when the region can be written.

   .. py:attribute:: is_executable
      :type: bool

      ``True`` when the region contains executable code.

   .. py:attribute:: is_shared
      :type: bool

      ``True`` when the region is a shared/file-backed mapping.

   .. py:attribute:: path
      :type: str

      Best-effort path of the file backing the region, or ``""`` when
      unknown. Linux exposes this directly from ``/proc/<pid>/maps``;
      Windows and macOS would need extra syscalls and report ``""``.
```

## `MemoryRegionSnapshot`

```{eval-rst}
.. py:class:: MemoryRegionSnapshot

   A pre-sorted snapshot of memory regions returned by
   :py:meth:`AbstractProcess.snapshot_memory_regions`. Behaves exactly like a
   plain ``list[MemoryRegion]`` — the only purpose of the subclass is to let
   the scanning helpers detect via ``isinstance`` that the input is already
   sorted by ``address`` and skip the per-call ``sorted(...)`` step.

   Slicing or filtering with a list comprehension drops the
   :py:class:`MemoryRegionSnapshot` type (you get a plain ``list``). The
   scan helpers re-sort defensively whenever the input is not a
   :py:class:`MemoryRegionSnapshot`, so this is safe but slightly slower for
   very large region maps.
```

## Examples

### Iterating regions

```python
with OpenProcess(process_name="game.exe") as process:
    for region in process.get_memory_regions():
        print(f"0x{region.address:016X}  {region.size:>12,}")
```

### Filtering by permission

```python
writable = [r for r in process.get_memory_regions() if r.is_writable]
```

### Building a snapshot for the refine loop

```python
snapshot = process.snapshot_memory_regions()
assert isinstance(snapshot, MemoryRegionSnapshot)
# Reuse across many scans:
for addr in process.search_by_value(int, 4, 100, memory_regions=snapshot):
    ...
```

```{seealso}
- [Memory regions guide](../guide/memory-regions.md)
- [Searching memory](../guide/searching.md) — uses the snapshot to skip
  region enumeration on the refine loop.
- [Utilities API](utilities.md) — low-level predicates `is_region_readable`
  etc. for callers that hold a raw platform struct.
```
