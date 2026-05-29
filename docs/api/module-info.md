# `ModuleInfo`

A single module — executable or shared library — loaded in a process.

```python
from PyMemoryEditor import ModuleInfo
```

`ModuleInfo` is a `@dataclass(frozen=True)` returned by `process.get_modules()`.
Each entry corresponds to a file mapped into the address space — the main
executable plus every shared library it loaded (`.dll` on Windows, `.so` on
Linux, `.dylib` on macOS).

## Fields

```{eval-rst}
.. py:class:: ModuleInfo(name, path, base_address, size=0, raw=None)

   .. py:attribute:: name
      :type: str

      File name of the module (e.g. ``"game.exe"``, ``"libc.so.6"``).

   .. py:attribute:: path
      :type: str

      Full path of the backing file on disk when the OS exposes it; falls
      back to ``name`` when only the name is available.

   .. py:attribute:: base_address
      :type: int

      Address where the module is loaded for this run. Combine it with a
      static offset (``base_address + offset``) to reach a known location
      despite ASLR — the natural feed into
      :py:meth:`resolve_pointer_chain`.

   .. py:attribute:: size
      :type: int

      Size of the module in memory, in bytes. ``0`` when the backend cannot
      determine it. The meaning is **platform-specific**:

      - **Windows** — full module image (``modBaseSize``).
      - **Linux** — mapped span (covers ``.data`` / ``.bss``).
      - **macOS** — ``__TEXT`` segment size; a single whole-module size is
        ill-defined for dyld-shared-cache dylibs.

   .. py:attribute:: raw
      :type: Any

      Underlying platform handle/key used to look up the module — the
      ``MODULEENTRY32.hModule`` on Windows, the mapped path on Linux, the
      Mach-O load address on macOS. Useful for advanced callers that need
      to make follow-up OS-specific calls.
```

## Examples

### Listing every module

```python
with OpenProcess(process_name="game.exe") as process:
    for module in process.get_modules():
        print(f"{module.name:32}  0x{module.base_address:016X}  {module.size:>12}")
```

### Finding the main executable

```python
main = next(m for m in process.get_modules() if m.name.endswith(".exe"))
print(f"{main.name} loaded at 0x{main.base_address:X}")
```

### Using `base_address` as a pointer-chain root

```python
module = next(m for m in process.get_modules() if m.name == "game.exe")
hp_addr = process.resolve_pointer_chain(
    module.base_address + 0x10F4F4, [0x0, 0x158],
)
```

```{seealso}
- [Modules and threads guide](../guide/modules-threads.md)
- [Pointers](../guide/pointers.md)
```
