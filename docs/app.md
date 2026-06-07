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

The `app` extra adds PySide6 and psutil to the install (psutil powers the
GUI's process picker). The library itself stays dependency-free.

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
- Int8 / Int16 / Int32 / Int64, Float / Double, Boolean, String (UTF-8) and
  Byte Array value types
- Range search
- AOB / byte signature search (IDA-style)
- Regex (string) search — a text regex matched against UTF-8 memory. The
  Length field sets the maximum match width; matching is byte-wise, so `.`
  spans one byte (use `.+` for multibyte characters)

**🔁 Refine workflow**
- **First Scan → Next Scan** (Cheat Engine style)
- Six Next Scan comparisons (increased / decreased / changed / unchanged, plus
  increased-by / decreased-by)
- Live progress

**📋 Cheat table**
- Freeze / write values continuously
- Per-entry custom labels
- JSON import/export

**🔗 Pointer scan**
- Same engine as `scan_pointer_paths`
- Save scans to JSON
- Rescan / compare scans to narrow them down
- Send a resolved address straight to the Cheat Table

**🗺️ Memory map**
- All regions with R/W/X flags
- Backing file path per region (Linux; blank where the OS doesn't expose it)

**🔬 Hex viewer**
- Live dump with write-back
- Go to any address, with auto-refresh

**🪵 Log console**
- Same stream as `logging.getLogger("PyMemoryEditor")`
- Pick the log level (DEBUG / INFO / WARNING / ERROR) at runtime

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
4. When the list is small, **double-click** a result to add it to the
   **Cheat Table**.
5. **Freeze** the value with the checkbox or change it from the Cheat Table.
6. (Optional) **Run a Pointer Scan** on the result to find a chain that
   survives restarts.

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
