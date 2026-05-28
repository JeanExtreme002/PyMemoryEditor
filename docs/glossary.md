# Glossary

A short reference of the terms used throughout this documentation.

```{glossary}

Address
   A numeric position in a process's virtual memory. PyMemoryEditor uses
   Python ``int``s for addresses and prints them as hex (``0x14010F4F4``).

ASLR
   *Address Space Layout Randomization* — a kernel feature that loads modules
   (and randomizes some allocations) at different base addresses each run.
   It is the reason a scanned address is "gone" on the next launch, and the
   reason {term}`pointer scans <Pointer scan>` exist.

AOB
   *Array Of Bytes* — a byte signature used to locate code or data by its
   shape. PyMemoryEditor accepts IDA-style strings (``"48 8B ? ? 00"``) as
   well as raw bytes regex patterns. See [Pattern scan](guide/pattern-scan.md).

Base address
   The address at which a {term}`module` is loaded for the current run.
   Combine it with a static offset (``module.base_address + 0x10F4F4``) to
   reach a known location despite {term}`ASLR`.

Cheat table
   A list of saved addresses (and the values to write to them). The bundled
   GUI app stores cheat tables as JSON.

ctypes
   The [Python stdlib module](https://docs.python.org/3/library/ctypes.html)
   used by PyMemoryEditor to call OS APIs without a native build step.

Direct handle
   A {term}`RemotePointer` whose ``offsets`` is ``None`` — its resolved
   address is just the ``base_address``, with no dereferencing. The result
   of wrapping a freshly-scanned address.

Memory region
   A contiguous block of virtual memory in a process, with a single set of
   permissions (R/W/X/shared). ``get_memory_regions()`` enumerates them.

Module
   A file mapped into a process — the main executable plus every shared
   library it loaded. PyMemoryEditor surfaces them as
   :py:class:`ModuleInfo`.

Pointer chain
   A static base plus a series of offsets:
   ``module + offset → [+x] → [+y] → ... → +n``. Walking the chain lands on a
   value's current address — useful because the value typically lives at
   a different absolute address every run.

Pointer scan
   The reverse of walking a chain: given a value's *current* address, find
   the chains (recipes) that resolve to it. See
   [Pointer scan](guide/pointer-scan.md).

Process
   An OS-level running program. PyMemoryEditor identifies a process by name
   or PID.

PID
   *Process Identifier* — the OS-assigned integer that uniquely names a
   running process at a point in time.

ptrace_scope
   The Linux kernel's policy for which non-child processes can be attached
   to. See [Platform Notes → Linux](project:#linux).

Refine scan
   An iterative scan: an initial scan returns many candidates, the value
   changes in the target, and the candidate list is narrowed to only those
   that still match. The classic Cheat Engine workflow.

RemotePointer
   A live, re-resolving handle to a typed value in another process. Reading
   ``.value`` walks any associated chain again, so the handle keeps working
   as the target moves things around in memory.

Scan
   To search the memory of a process for an address matching some criterion
   — a value, a range, or a byte pattern.

SIP
   *System Integrity Protection* — macOS's kernel-level protection that
   prevents most processes from being inspected. Affects how PyMemoryEditor
   attaches to processes on macOS.

Static base
   An address that is **fixed at a known offset from a module's base** —
   the kind of address a pointer chain can start from and still work after
   a restart.

TID
   *Thread Identifier* — the OS-assigned integer naming a thread. The
   meaning varies per OS (see [`ThreadInfo`](api/thread-info.md)).
```
