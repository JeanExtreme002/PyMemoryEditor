# The PyMemoryEditor GUI App

PyMemoryEditor ships with a **polished cross-platform GUI** built on
**PySide6 (Qt for Python)**. It's a Cheat Engine-inspired memory scanner that
exercises every public surface of the library — so it doubles as a living
demo and a teaching tool.

If you're new to memory editing, **start with the app** before writing code.

<p align="center">
  <img src="https://raw.githubusercontent.com/JeanExtreme002/PyMemoryEditor/main/assets/screenshots/app.png" alt="PyMemoryEditor app attached to a running process" width="820" />
</p>

## Install

```bash
pip install "PyMemoryEditor[app]"
```

The `app` extra pulls in PySide6 and other dependencies. The core library remains dependency-free.

## Launch

From any terminal:

```bash
pymemoryeditor
```

The app opens with the **Open Process** dialog, where you pick a target by
name or PID.

## What's inside

**🎯 Scanner**
- Every `ScanTypesEnum` mode
- All integer widths, Float, Double, Boolean, String (UTF-8), and Byte Array
- Range, AOB / byte-signature (IDA-style), and regex search

**🧲 Refine workflow**
- **First Scan → Next Scan** (Cheat Engine style)
- Six more comparison modes (increased, decreased, changed, …)
- Live progress bar

**📋 Cheat table**
- Live value updates
- Freeze or overwrite values continuously
- Per-entry custom labels
- JSON import / export

**🗺️ Memory map**
- All regions with their attributes (address, size, R/W/X permissions)
- Auto-refresh as the memory layout changes
- Allocate and free memory directly from the map

**🔬 Hex viewer**
- Live hex dump with in-place write-back
- Jump to any address, with auto-refresh

**📦 Modules**
- All loaded modules (DLLs / .so / .dylib) with base address, size, and path
- Auto-refresh as modules are loaded or unloaded
- Double-click to open in the Hex Viewer

**🧩 Pointer scan**
- Same engine as `scan_pointer_paths`
- Save / load scans as JSON
- Rescan and compare to narrow results down

```{admonition} Cross-platform dark theme
:class: tip

The app ships with several built-in dark themes (Kali Teal by default). Pick one
from the **Theme** button on the toolbar; your choice is remembered between runs.
```

## Typical workflow

1. **Open a process** from the startup dialog (or later via `File → Change Process…`).
2. **Run a First Scan**: pick the value type, type the value you can see, hit
   *First Scan*.
3. **Refine** with Next Scan after the value changes — pick *Exact Value* with
   the new number, or one of the *increased / decreased / changed* shortcuts.
4. **Double-click** a result to add it to the
   **Cheat Table**.
5. **Freeze** the value with the checkbox or change it from the Cheat Table.
6. (Optional) **Run a Pointer Scan** on the result to find a chain that
   survives restarts.

## When the target exits

The app polls the target while you work — the Memory Map, Modules and Threads
windows re-read it on a timer (a few times a second for Threads), and the main
window checks every couple of seconds that it is still alive.

When the process goes away (or you switch to another one via
`File → Change Process…`), you get **one** notice per window rather than one per
poll: the main window tells you the target exited, and any open auxiliary window
reports the failure once, stops refreshing, and says so in its status line
(`auto-refresh stopped`). Its table stays on the last data it read, so you can
still copy an address out of it. Close and reopen the window to point it at a
live target again.

Brief hiccups don't trigger any of that — a read that fails and recovers within
a few seconds is left alone, so a busy target loading libraries won't interrupt
you.

## Importing & exporting

The Cheat Table and Pointer Scan results are stored as plain **JSON**, so you
can:

- Share a cheat table with a friend.
- Version-control your saved pointer scans.
- Diff scans by hand.

The pointer-scan format is documented in [`PointerPath`](api/pointer-path.md).

## When to use the app vs the library

<div class="vs-cards">
<div class="vs-card">

**Use the GUI when…**

- You're exploring a target interactively.
- You're learning memory editing.
- You want to inspect what's available before writing code.

</div>
<div class="vs-card">

**Use the library when…**

- You want to script a workflow or build a tool.
- You want to embed memory access into a bigger application.
- You need batch processing, automation, or CI integration.

</div>
</div>
<br>

```{seealso}
- [Quick Start](quickstart.md) — the same workflow, in code.
- [Logging](guide/logging.md) — the Log Console exposes the library's logger.
```
