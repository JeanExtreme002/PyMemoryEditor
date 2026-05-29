# User Guide

Task-oriented walkthroughs of every PyMemoryEditor workflow, from opening a
process to following multi-level pointer chains. Each page is self-contained
and cross-links to the relevant [API reference](../api/index.md).

New here? Read the [Quick Start](../quickstart.md) first, then come back for
the in-depth version.

## What's covered

- **Core workflow** — open a process, read/write values, and find addresses by
  value or byte pattern. This is the classic Cheat Engine loop.
- **Inspecting the process** — enumerate memory regions, loaded modules and
  threads.
- **Pointers** — walk pointer chains you know, and reverse-scan to discover the
  chains that survive a restart.
- **Advanced** — reserve and release memory inside the target.

For diagnostics, see [Logging](logging.md) in the Reference section.

```{toctree}
:caption: Core workflow
:maxdepth: 1

opening-process
read-write
searching
pattern-scan
```

```{toctree}
:caption: Inspecting the process
:maxdepth: 1

memory-regions
modules-threads
```

```{toctree}
:caption: Pointers
:maxdepth: 1

pointers
pointer-scan
```

```{toctree}
:caption: Advanced
:maxdepth: 1

allocate-free
```
