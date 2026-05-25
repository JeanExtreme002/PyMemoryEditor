# Security Policy

## Reporting a Vulnerability

**Please do not open a public issue for a suspected vulnerability.** Use one
of the channels below instead so the impact can be assessed and a fix
prepared before details become public.

- **Preferred:** open a [private security advisory] on GitHub. This creates a
  private thread visible only to the maintainers and the reporter, supports
  CVE assignment, and lets us coordinate a coordinated disclosure timeline.
- **Alternative:** email `contact@jeanloui.dev` with subject
  `[PyMemoryEditor security]`.

When reporting, please include:

- Affected version(s).
- Operating system, architecture, and Python build (32 / 64-bit).
- A minimal reproducer or proof-of-concept.
- The impact you observed and any prerequisites (privileges, kernel
  configuration, target process attributes).

## Scope

PyMemoryEditor is a library that reads, writes, and searches the memory of
other processes via OS-level APIs (`ReadProcessMemory` / `WriteProcessMemory`
on Windows, `process_vm_readv` / `process_vm_writev` on Linux, the Mach VM
APIs on macOS). Operations that require elevated privileges, special
entitlements, or relaxed `ptrace_scope` are documented in the README — those
requirements are not security defects.

In scope:

- Memory corruption, crashes, or undefined behavior in the library itself
  (e.g. unchecked syscall returns, ctypes signature mismatches, buffer
  overruns in the Python layer).
- Permission-gate bypasses on Windows (e.g. a read or write succeeding
  without the matching `PROCESS_VM_*` bit).
- Silent partial reads / writes that misreport success.
- Use of `mach_vm_protect` on macOS leaving the target task in a more
  permissive state than it started without surfacing it to the caller.

Out of scope:

- Using PyMemoryEditor on a target you are not authorized to inspect (this
  is a misuse question, not a library defect).
- Cheating detection or anti-cheat bypass requests.

[private security advisory]: https://github.com/JeanExtreme002/PyMemoryEditor/security/advisories/new
