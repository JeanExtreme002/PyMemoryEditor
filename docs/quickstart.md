# Quick Start

Five minutes from `pip install` to overwriting a value in another process.

## 1. Install

```bash
pip install PyMemoryEditor
```

(See [Installation](installation.md) for the GUI app or installing from source.)

## 2. Open a process

PyMemoryEditor exposes a single entry point: `OpenProcess`. You can target a
process by **name** or **PID**:

```python
from PyMemoryEditor import OpenProcess

# By process name
process = OpenProcess(process_name="notepad.exe")

# Or by PID
process = OpenProcess(pid=1234)
```

The recommended pattern is a `with` block — it closes the handle automatically:

```python
with OpenProcess(process_name="notepad.exe") as process:
    ...
```

By default, `OpenProcess` opens a **read + write** handle. No special permission
flag needed for the common case.

## 3. Read and write a value

The building blocks are `read_process_memory` and `write_process_memory`.
For numeric types (`int`, `float`, `bool`) the size is inferred.

```python
from PyMemoryEditor import OpenProcess

with OpenProcess(process_name="notepad.exe") as process:
    address = 0x0005000C

    # Read 4 bytes as an int
    value = process.read_process_memory(address, int)
    print("Current:", value)

    # Write a new value (pass None to use the default size)
    process.write_process_memory(address, int, None, value + 7)
```

Strings and raw bytes need an explicit size:

```python
name = process.read_process_memory(address, str, 32)
```

## 4. Run your first scan

You rarely know the address of a value up front — you **find it by scanning**.
`search_by_value` yields every address holding a given value:

```python
with OpenProcess(process_name="game.exe") as process:
    for address in process.search_by_value(int, 4, 100):
        print(f"Found at 0x{address:X}")
```

That's the same operation Cheat Engine performs in its **First Scan** button.
[See the searching guide](guide/searching.md) for all eight comparison modes
and the refine workflow.

## 5. The Cheat Engine workflow

The classic loop is:

1. **Scan** for a value you can see (e.g. your health is `100`) — you get back
   many candidate addresses.
2. **Let the value change** in the target (you take damage → `95`).
3. **Refine**: keep only the addresses that now hold the new value. Repeat
   until one address remains — that's your value.
4. **Read, write or freeze** it.

```python
with OpenProcess(process_name="game.exe") as process:
    # 1. First scan — every address currently holding 100.
    candidates = list(process.search_by_value(int, 4, 100))

    # 3. After the value drops to 95 in-game, keep only the matches that agree.
    survivors = [
        address
        for address, value in process.search_by_addresses(int, 4, candidates)
        if value == 95
    ]

    # 4. Overwrite the survivors back to a high value.
    for address in survivors:
        process.write_process_memory(address, int, 4, 9999)
```

For big targets, see [the refine-scan workflow](guide/searching.md#the-refine-scan-workflow)
to cache the region map once.

## 6. Pointer scanning — make an address survive restarts

The address you just found is **useless next launch**. The OS loads everything
somewhere new every time (ASLR), so `0x1FA3C140` today is garbage tomorrow.
The fix is a **static pointer path**: a chain that starts at a fixed location
inside a loaded module and dereferences its way to your value — so the same
recipe keeps working across restarts.

PyMemoryEditor finds these for you. `scan_pointer_paths` is a **reverse pointer
scan** (Cheat Engine's "Pointer scan"): give it the value's address *right now*,
and it discovers the static paths that resolve to it.

```python
with OpenProcess(process_name="game.exe") as process:
    # The value lives here this run (e.g. from search_by_value above).
    for path in process.scan_pointer_paths(0x1FA3C140, max_depth=4):
        print(path)
        # "game.exe"+0x10F4F4 -> [+0x0] -> +0x158
        print(hex(path.resolve(process)))
```

Each result is a `PointerPath` carrying the module + offsets — the part that
survives a restart. Save the reliable ones and reuse them later:

```python
with OpenProcess(process_name="game.exe") as process:
    paths = list(process.scan_pointer_paths(0x1FA3C140, max_depth=4))
    process.save_pointer_paths(paths, "health.json")

# ...next launch, the absolute address has changed but the path still works:
with OpenProcess(process_name="game.exe") as process:
    survivors = process.rescan_pointer_paths("health.json", 0x2B7C0140)
    pointer = survivors[0].rebase(process).to_pointer(process)
    pointer.write(9999)
```

[See the pointer scan guide](guide/pointer-scan.md) for tuning the scan
(`max_depth`, `max_offset`), the multi-run refine workflow, and intersecting
independent scans with `compare_pointer_scans`.

## Next steps

- 📖 [User guide](guide/opening-process.md) — every workflow, in depth.
- 🖥️ [The bundled GUI app](app.md) — same features, no code required.
- 📚 [API reference](api/openprocess.md) — every public class and method.
- 🛟 [Troubleshooting](troubleshooting.md) — common errors and how to fix them.

```{admonition} ⚖️ Responsible use
:class: warning

PyMemoryEditor talks to other processes through OS-level APIs. **Only point it
at processes you own or have explicit permission to inspect.**
```
