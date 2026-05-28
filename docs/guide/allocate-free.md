# Allocating and freeing memory

PyMemoryEditor can **reserve** new memory inside the target process and
**release** it later. This is useful for storing custom data the target
program will read, or for staging code injection scenarios.

## Allocating

`allocate_memory(size)` reserves a new region in the target's address space
and returns its base address. The OS may round the size up to the page
size:

```python
with OpenProcess(process_name="game.exe") as process:
    address = process.allocate_memory(64)
    process.write_process_memory(address, int, 4, 1337)
```

## Freeing

`free_memory(address)` releases the region. The library remembers each
allocation's size, so you don't have to:

```python
process.free_memory(address)
```

Pass an explicit `size=` only when freeing a region that this object **did not
allocate** (e.g. one inherited from another script):

```python
process.free_memory(address, size=4096)
```

## Method signatures

```{eval-rst}
.. py:method:: allocate_memory(size, *, permission=None)
   :no-index:

   Reserve and commit ``size`` bytes inside the target process's address space
   and return the base address of the new region.

   :param int size: number of bytes to allocate (rounded up to the OS page
      size by the kernel).
   :param permission: optional, **platform-specific** protection for the new
      region — see the platform table below.
   :returns: the base address of the new region.
   :raises NotImplementedError: on Linux (see below).

.. py:method:: free_memory(address, size=0)
   :no-index:

   Release a region previously returned by :py:meth:`allocate_memory`.

   :param int address: base address returned by :py:meth:`allocate_memory`.
   :param int size: size of the region in bytes. May be left ``0`` to reuse
      the size recorded when the region was allocated (required on macOS,
      ignored on Windows where ``MEM_RELEASE`` frees the whole allocation).
      Pass an explicit size only to free a region this object did not
      allocate.
   :returns: ``True`` on success.
   :raises NotImplementedError: on Linux.
```

## Platform behavior

<table>
<tr>
<th>Platform</th>
<th>Status</th>
<th>Default <code>permission</code></th>
<th>Underlying API</th>
</tr>
<tr>
<td>🪟 <b>Windows</b></td>
<td>✅ Supported</td>
<td><code>PAGE_EXECUTE_READWRITE</code> (executable + writable)</td>
<td><code>VirtualAllocEx</code> / <code>VirtualFreeEx</code></td>
</tr>
<tr>
<td>🍎 <b>macOS</b></td>
<td>✅ Supported</td>
<td>Mach default (read+write)</td>
<td><code>mach_vm_allocate</code> / <code>mach_vm_deallocate</code></td>
</tr>
<tr>
<td>🐧 <b>Linux</b></td>
<td>❌ <b>Not supported</b></td>
<td>—</td>
<td>Raises <code>NotImplementedError</code></td>
</tr>
</table>

```{admonition} Why no Linux?
:class: warning

Linux has no syscall to allocate memory in another process's address space —
`mmap` only affects the calling process. Cross-process allocation would
require a **ptrace-based engine** to make the target call `mmap` itself.
PyMemoryEditor doesn't ship one. Calling `allocate_memory` or `free_memory`
on Linux raises `NotImplementedError`.
```

## Choosing a permission

The `permission=` argument mirrors `OpenProcess(permission=...)`.

### On Windows

Pass a `MemoryProtectionsEnum` (or the underlying integer):

```python
from PyMemoryEditor import OpenProcess
from PyMemoryEditor.win32.enums.memory_protections import MemoryProtectionsEnum

with OpenProcess(process_name="game.exe") as process:
    # Allocate a read-only buffer.
    address = process.allocate_memory(64, permission=MemoryProtectionsEnum.PAGE_READONLY)
```

Common values:

<table>
<tr><th>Value</th><th>Meaning</th></tr>
<tr><td><code>PAGE_NOACCESS</code></td><td>No access at all.</td></tr>
<tr><td><code>PAGE_READONLY</code></td><td>Read-only.</td></tr>
<tr><td><code>PAGE_READWRITE</code></td><td>Read + write.</td></tr>
<tr><td><code>PAGE_EXECUTE_READ</code></td><td>Read + execute.</td></tr>
<tr><td><code>PAGE_EXECUTE_READWRITE</code> <em>(default)</em></td><td>Read + write + execute.</td></tr>
</table>

### On macOS

Pass a `VM_PROT_*` bitmask (or leave `None` for the default of read+write):

```python
# read+write+execute (may fail under the hardened runtime).
process.allocate_memory(4096, permission=VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)
```

```{admonition} Hardened runtime on Apple Silicon
:class: note

Requesting **executable** allocations may fail on macOS, especially on Apple
Silicon under the hardened runtime. Stick to read+write if you don't need to
execute injected code.
```

## A complete example

```python
from PyMemoryEditor import OpenProcess

with OpenProcess(process_name="game.exe") as process:
    address = process.allocate_memory(128)
    try:
        # Write something to it
        process.write_process_memory(address, str, 128, "Hello from PyMemoryEditor!")

        # Read it back
        msg = process.read_process_memory(address, str, 128)
        print(msg.split("\x00", 1)[0])
    finally:
        process.free_memory(address)
```

```{seealso}
- [Reading and writing memory](read-write.md)
- [Platform Notes](../platform-notes.md)
```
