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

The `app` extra adds PySide6 to the install. The library itself stays
dependency-free.

## Launch

From any terminal:

```bash
pymemoryeditor
```

The app opens with the **Open Process** dialog, where you pick a target by
name or PID.

## What's inside

<table>
<tr>
<td width="50%" valign="top">

### 🎯 Scanner

- Every `ScanTypesEnum` mode
- All five value types (`int`, `float`, `bool`, `str`, `bytes`)
- Range search
- AOB / byte signature search
- Regex search

### 🔁 Refine workflow

- **First Scan → Next Scan** (Cheat Engine style)
- Eight Next Scan comparisons (increased, decreased, changed, unchanged, …)
- Live progress

### 📋 Cheat table

- Freeze / write values continuously
- Per-entry custom labels
- JSON import/export

</td>
<td width="50%" valign="top">

### 🔗 Pointer scan

- Same engine as `scan_pointer_paths`
- Save scans to JSON
- Rescan / compare scans to narrow them down
- Build live `RemotePointer` from a result

### 🗺️ Memory map

- All regions with R/W/X flags
- Source file / module per region (where available)

### 🔬 Hex viewer

- Live dump with write-back
- Address goto, navigation

### 🪵 Log console

- Same stream as `logging.getLogger("PyMemoryEditor")`
- Toggle DEBUG verbosity at runtime

</td>
</tr>
</table>

```{admonition} Cross-platform dark theme
:class: tip

The app ships with a dark theme that follows the system on macOS and Windows
11 and uses a manual toggle elsewhere. Themes live under
**View → Theme**.
```

## Typical workflow

1. **Open a process** from the dialog (or `File → Open Process`).
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

<table>
<tr><th>Use the GUI when…</th><th>Use the library when…</th></tr>
<tr><td>You're exploring a target interactively.</td><td>You want to script a workflow or build a tool.</td></tr>
<tr><td>You're learning memory editing.</td><td>You want to embed memory access into a bigger application.</td></tr>
<tr><td>You want to inspect what's available before writing code.</td><td>You need batch processing, automation, or CI integration.</td></tr>
</table>

```{seealso}
- [Quick Start](quickstart.md) — the same workflow, in code.
- [Logging](guide/logging.md) — the Log Console exposes the library's logger.
```
