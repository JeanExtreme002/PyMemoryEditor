# Platform Notes

PyMemoryEditor abstracts away the OS, but the OS still gets a say in **what
you're allowed to touch**. This page documents the differences that matter
for real-world use.

A one-line summary:

<table class="platform-grid">
<tr><th>Platform</th><th>Permission model</th><th>Allocate / free</th></tr>
<tr><td class="platform-name">🪟 <b>Windows</b></td><td data-label="Permission model"><code>OpenProcess</code> access mask</td><td data-label="Allocate / free">✅ <code>VirtualAllocEx</code> / <code>VirtualFreeEx</code></td></tr>
<tr><td class="platform-name">🐧 <b>Linux</b></td><td data-label="Permission model"><code>ptrace_scope</code> + process ownership</td><td data-label="Allocate / free">❌ Not supported</td></tr>
<tr><td class="platform-name">🍎 <b>macOS</b></td><td data-label="Permission model">Mach entitlements (<code>com.apple.security.cs.debugger</code>) or SIP off + root</td><td data-label="Allocate / free">✅ <code>mach_vm_allocate</code> / <code>mach_vm_deallocate</code></td></tr>
</table>

---

(windows)=

## 🪟 Windows

```{tip}
Works out of the box for most cases.
```

### Process name matching

Names are matched **case-insensitively** by default to match the OS
convention. Pass `case_sensitive=True` to opt out.

### The `permission` keyword

`OpenProcess(permission=...)` accepts a `ProcessOperationsEnum` (or integer)
mask that maps directly to the [`PROCESS_*` access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).

The default mask is **read + write + region enumeration**:

```python
PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
```

For a **read-only** handle, narrow the mask:

```python
from PyMemoryEditor import OpenProcess, ProcessOperationsEnum

with OpenProcess(
    name="notepad.exe",
    permission=ProcessOperationsEnum.PROCESS_VM_READ
        | ProcessOperationsEnum.PROCESS_QUERY_INFORMATION,
) as process:
    ...
```

For full control:

```python
OpenProcess(name="game.exe", permission=ProcessOperationsEnum.PROCESS_ALL_ACCESS)
```

### Running as Administrator

To attach to **elevated apps, services or another user's processes**, run your
terminal **as Administrator**. Opening such a process without it fails with
`PermissionError` (`winerror == 5`), and the message lists the likely causes.

SYSTEM services can still refuse an administrator unless your own code enables
`SeDebugPrivilege` — PyMemoryEditor never enables privileges for you. Protected
processes (anti-cheat, antivirus, PPL system processes) cannot be opened for
memory access from user mode at all.

### Memory allocation

`allocate_memory` defaults to `PAGE_EXECUTE_READWRITE` so the region is
usable for both data and injected code. Pass an explicit
`MemoryProtectionsEnum` value to narrow it.

`free_memory` releases only what this object allocated unless you pass an
explicit `size=` — see [Allocating and freeing](guide/allocate-free.md).

---

(linux)=

## 🐧 Linux

```{tip}
Access is governed by `ptrace_scope` and process ownership.
```

### The `permission` keyword

**Ignored** on Linux — access is governed by `ptrace_scope` and process
ownership. The library uses `process_vm_readv` / `process_vm_writev`, which
don't take a permission mask.

Passing `permission=` something other than `None` emits a `UserWarning`.

### `ptrace_scope`

Access depends on:

- **Process ownership** — you can always read processes you own.
- **`ptrace_scope`** — the kernel's policy for non-child targets.

If the target is **not** a child of the caller and `ptrace_scope=1` (the
common default), you'll see a `PermissionError` (`EPERM`) from the first
read, write or scan. Fixes:

```bash
# Run as root (easiest):
sudo python my_script.py

# Or relax ptrace_scope (system-wide, lasts until reboot):
sudo sysctl kernel.yama.ptrace_scope=0

# Persist it across reboots:
echo "kernel.yama.ptrace_scope=0" | sudo tee /etc/sysctl.d/10-ptrace.conf
```

A `PermissionError` raised while *opening* the process (reading
`/proc/<pid>/maps`) is a different problem: that file is not gated by
`ptrace_scope`, so the denial means the target belongs to another user or is
not dumpable (setuid binaries, `prctl(PR_SET_DUMPABLE, 0)`). Run as root or
as the target's owner.

### Process identity

Linux addresses a process by pid, so the backend binds to the original process
when it opens it — with a pidfd (kernel 5.3+), or with the process start time
from `/proc/<pid>/stat` where pidfds are unavailable (older kernels, strict
seccomp profiles). Once that process has exited, writes, scans and
region/module/thread listings raise `ProcessIDNotExistsError`, even if a new
process has been given the same pid. Single-value reads are checked too when a
pidfd is available; without one they skip the check for speed, and a read of
an exited target fails with the kernel's `OSError` (`ESRCH`). `close()`
releases the pidfd.

### Writes to read-only pages

`process_vm_writev` honours page protection and Linux has no way to change
another process's page protection from outside, so `write_process_memory`
on a **read-only page** fails with `OSError` (`EFAULT`) — the same error an
unmapped address gives. Windows and macOS elevate the page protection for
the write instead; see the [macOS write side effect](#macos-write-side-effect).

### Memory allocation — not supported

Linux has no syscall to allocate memory in another process's address space —
`mmap` only affects the calling process. PyMemoryEditor's
`allocate_memory` / `free_memory` raise `NotImplementedError` on Linux.

A proper implementation would require a **ptrace-based engine** that makes
the target call `mmap` itself — out of scope for a pure-Python library.

---

(macos)=

## 🍎 macOS

```{tip}
Access is governed by Mach entitlements (or SIP off + root).
```

### The `permission` keyword

**Ignored** on macOS. The library uses Mach VM APIs (`task_for_pid`,
`mach_vm_read_overwrite`, `mach_vm_write`, `mach_vm_region`), which don't
take a permission mask.

### Opening another process

Requires the Python binary to be signed with the
`com.apple.security.cs.debugger` entitlement **or** SIP disabled and running
as root. Without either, `task_for_pid()` returns an authorization error.

### Opening the current process

`task_for_pid()` always succeeds for *the calling task* (we use
`mach_task_self_` directly), so **opening your own process always works** —
ideal for self-inspection, tests, and tutorials.

```python
import os
from PyMemoryEditor import OpenProcess

with OpenProcess(pid=os.getpid()) as process:
    # Always works on macOS, no entitlement needed.
    for region in process.get_memory_regions():
        ...
```

### macOS write side effect

```{admonition} ResourceWarning on macOS writes
:class: warning

`write_process_memory` on a **read-only page** transparently elevates the
page protection via `mach_vm_protect` (with `VM_PROT_COPY`), performs the
write, and tries to restore the original protection — region by region, when
the write crosses into a neighbour with a different protection.

An executable page keeps `EXECUTE` during the write where the kernel allows
RWX. Under W^X (Apple Silicon, the hardened runtime) it does not, so the page
is briefly non-executable, and a target thread executing on that exact page
during the write can crash.

**If the restore step fails** (e.g. the target task disappears mid-call),
the library emits a `ResourceWarning` and the target page is left more
permissive than it started. Treat the warning as a signal to investigate.
```

This side effect is unique to macOS — the Win32 and Linux backends do not
share it. On Windows, `WriteProcessMemory` changes the page protection
itself (which is why the handle needs `PROCESS_VM_OPERATION`), and Linux
cannot change it at all: writing to a read-only page there fails with
`OSError` (`EFAULT`) — see [Linux → Writes to read-only pages](#writes-to-read-only-pages).

### `ModuleInfo.size` quirk

On macOS, `ModuleInfo.size` returns the **`__TEXT` segment size**, not the
full module image. A single whole-module size is ill-defined for
dyld-shared-cache dylibs.

For pointer scanning, the library internally walks every Mach-O segment to
find static ranges (so global pointers in `__DATA` *are* considered static
bases). You only need to worry about this if you pass `static_ranges=`
explicitly to `scan_pointer_paths`.

### Allocation under the hardened runtime

`allocate_memory` defaults to **read+write** (the Mach default). Requesting
**executable** allocations may fail under the hardened runtime, particularly
RWX on Apple Silicon.

---

## Summary

```{admonition} Where to next?
:class: tip

- Stuck on a permission error? See [Troubleshooting](troubleshooting.md).
- Want to allocate memory? See [Allocating and freeing](guide/allocate-free.md).
- Need to inspect a region's flags? See [Memory regions](guide/memory-regions.md).
```
