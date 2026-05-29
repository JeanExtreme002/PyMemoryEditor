# Modules and threads

Beyond memory regions, PyMemoryEditor exposes two more inspection APIs:

- **`get_modules()`** — every executable and shared library loaded into the
  process.
- **`get_threads()`** — every thread currently running inside the process.

Both return immutable dataclass instances and are cross-platform.

## Loaded modules

A *module* is a file mapped into the process — the main executable plus every
shared library it loaded (`.exe`/`.dll` on Windows, the binary and `.so` files
on Linux, the Mach-O image and `.dylib` files on macOS).

```python
with OpenProcess(process_name="game.exe") as process:
    for module in process.get_modules():
        print(
            module.name,
            hex(module.base_address),
            module.size,
            module.path,
        )
```

### The `ModuleInfo` dataclass

```{eval-rst}
.. py:class:: ModuleInfo
   :no-index:

   .. py:attribute:: name
      :no-index:
      :type: str

      File name of the module — e.g. ``"game.exe"``, ``"libc.so.6"``.

   .. py:attribute:: path
      :no-index:
      :type: str

      Full path of the backing file on disk when the OS exposes it; falls back
      to ``name`` when only the name is available.

   .. py:attribute:: base_address
      :no-index:
      :type: int

      Address where the module is loaded **for this run**. Combine it with a
      static offset (``base_address + offset``) to reach a known location
      despite ASLR — the natural feed into
      :py:meth:`resolve_pointer_chain`.

   .. py:attribute:: size
      :no-index:
      :type: int

      Module size in bytes. ``0`` when the backend cannot determine it.
      Platform-specific: full image on Windows/Linux; ``__TEXT`` segment size
      on macOS.

   .. py:attribute:: raw
      :no-index:
      :type: Any

      Underlying platform handle for advanced follow-up calls.
```

### Finding a module by name

```python
def find_module(process, name):
    for module in process.get_modules():
        if module.name == name:
            return module
    return None

with OpenProcess(pid=1234) as process:
    main_module = find_module(process, "game.exe")
    if main_module:
        # Use module.base_address + static_offset as the base of a pointer chain.
        hp_addr = process.resolve_pointer_chain(
            main_module.base_address + 0x10F4F4, [0x0, 0x158],
        )
```

## Threads

`get_threads()` yields a `ThreadInfo` for every thread running inside the
target. It's useful for introspection ("how many workers does it spawn?",
"is the main thread still alive?").

```python
with OpenProcess(process_name="game.exe") as process:
    for thread in process.get_threads():
        print(thread.tid, thread.state, thread.priority)

    print("Main thread:", process.main_thread.tid)
```

### The `ThreadInfo` dataclass

```{eval-rst}
.. py:class:: ThreadInfo
   :no-index:

   .. py:attribute:: tid
      :no-index:
      :type: int

      Thread identifier. **The meaning is platform-specific**:

      - **Linux** — POSIX TID; same namespace as PID.
      - **Windows** — kernel-assigned DWORD thread id.
      - **macOS** — Mach thread port name.

   .. py:attribute:: start_address
      :no-index:
      :type: Optional[int]

      Thread entry point when the OS exposes it cheaply; ``None`` otherwise.

   .. py:attribute:: state
      :no-index:
      :type: Optional[str]

      Short human-readable state (e.g. ``"R"``/``"S"`` on Linux). ``None`` on
      platforms that don't surface it.

   .. py:attribute:: priority
      :no-index:
      :type: Optional[int]

      Scheduling priority as reported by the OS. Scale is platform-specific;
      ``None`` when not exposed.

   .. py:attribute:: raw
      :no-index:
      :type: Any

      Underlying platform handle (``THREADENTRY32`` on Windows, the TID path on
      Linux, a Mach port int on macOS). Useful for advanced follow-up calls.
```

### The `main_thread` shortcut

The `process.main_thread` property is a convenience for the conventional "main
thread" — by convention, the thread with the smallest `tid`:

```python
print(process.main_thread.tid)
```

It returns `None` if the target has no listable threads (rare; typically means
the process just exited).

```{admonition} Cross-platform tid semantics
:class: warning

Don't mix `tid`s with `pid`s, and don't compare `tid`s across operating
systems. On Linux a TID and a PID share a namespace; on Windows and macOS they
don't.
```

```{seealso}
- [Memory regions](memory-regions.md) — list the process's address space.
- [Pointers](pointers.md) — use `module.base_address + offset` as a static base.
```
