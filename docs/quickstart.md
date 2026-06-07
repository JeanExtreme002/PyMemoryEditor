# Quick Start

Five minutes from [`pip install`](installation.md) to overwriting a value in another process.

## 1. Open a process

PyMemoryEditor exposes a single entry point: [`OpenProcess`](guide/opening-process.md). Target a
process by **name** or **PID**:

```python
from PyMemoryEditor import OpenProcess

# By process name
process = OpenProcess(name="notepad.exe")

# Or by PID
process = OpenProcess(pid=1234)
```

The recommended pattern is a `with` block — it closes the handle automatically:

```python
with OpenProcess(name="notepad.exe") as process:
    ...
```

## 2. Read and write a value

The easiest way is the **typed shortcuts** — the size is baked into the method
name, so there's nothing to remember:

```python
from PyMemoryEditor import OpenProcess

with OpenProcess(name="notepad.exe") as process:
    address = 0x0005000C

    value = process.read_int(address)      # read a 4-byte int
    print("Current:", value)

    process.write_int(address, value + 7)  # write it back
```

There's a `read_*` / `write_*` pair for every common type:

```python
name = process.read_string(address, 32)  # reads a 32-byte field, returned up to the first NUL
```

For the generic API, see [Reading and writing memory](guide/read-write.md).

## 3. Run your first scan

You rarely know the address of a value up front — you **find it by scanning**.
`search_by_value` yields every address holding a given value:

```python
from PyMemoryEditor import OpenProcess

target_value = 100

with OpenProcess(name="game.exe") as process:
    for address in process.search_by_value(int, value=target_value):
        print(f"Found at 0x{address:X}")
```

That's the same operation Cheat Engine performs in its **First Scan** button.
[See the searching guide](guide/searching.md) for all eight comparison modes
and the refine workflow.

## 4. The Cheat Engine workflow

The classic loop is:

1. **Scan** for a value you can see (e.g. your health is `100`)
2. **Let the value change** in the target (you take damage → `95`).
3. **Refine**: keep only the addresses that now hold the new value. 
4. **Read, write or freeze** it.

```python
with OpenProcess(name="game.exe") as process:
    # 1. First scan — every address currently holding 100.
    candidates = list(process.search_by_value(int, value=100))

    # 3. After the value drops to 95 in-game, keep only the matches that agree.
    survivors = [
        address
        for address, value in process.search_by_addresses(int, addresses=candidates)
        if value == 95
    ]

    # 4. Overwrite the survivors back to a high value.
    for address in survivors:
        process.write_int(address, 9999)
```

For big targets, see [the refine-scan workflow](guide/searching.md#the-refine-scan-workflow)
to cache the region map once.

## 5. Pointer scanning — make an address survive restarts

Addresses change every launch (ASLR). A **pointer path** starts from a fixed
module offset and dereferences its way to your value — surviving restarts.

```python
# 1. Scan — find pointer paths that resolve to the target address.
with OpenProcess(name="game.exe") as process:
    # ... search for the address
    paths = list(process.scan_pointer_paths(target_address, max_depth=3))
    process.save_pointer_paths(paths, "health.json")

# ... restart the game, find the value's new address again ..

# 2. Rescan — keep only paths that still resolve to the new address.
with OpenProcess(name="game.exe") as process:
    # ... search for the new address again
    survivors = process.rescan_pointer_paths("health.json", new_target_address)
    process.save_pointer_paths(survivors, "health.json")

# 3. Load — use the saved paths directly.
with OpenProcess(name="game.exe") as process:
    paths = process.load_pointer_paths("health.json")
    pointer = paths[0].rebase(process).to_pointer(process)
    pointer.write(9999)
```

[See the pointer scan guide](guide/pointer-scan.md) for tuning options and the
multi-run refine workflow.

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
