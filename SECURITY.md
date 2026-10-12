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

### MCP server

The optional MCP server (`pymemoryeditor-mcp`, the `mcp` extra) hands the
library to an AI model, so it carries guarantees of its own. Reports that
break any of them are in scope:

- Attaching to a process the user did not approve (by the attach prompt,
  `--allow-process` or `--allow-any-process`), to a process on the built-in
  OS/credential denylist without `--allow-system-processes`, to the server
  itself or its client, or to a recycled pid after the user approved a name.
- Writing to a target when the server runs with `--read-only`, or without
  the server's own confirmation when it runs with `--confirm-writes`.
- A writable server listening on the unauthenticated `sse` /
  `streamable-http` transports without `--allow-remote-write`.
- Tool input (addresses, sizes, patterns, handles) that crashes the server,
  reads or writes outside what the call asked for, or escapes the scan time
  and result limits.

Not in scope: what a model does with the access the user granted (a model
reading a process it was allowed to open is the feature), a client that
auto-approves tool calls, and prompt injection through the *contents* of a
target's memory, which the server returns as data. These are covered by the
[MCP guide]'s safety section.

[MCP guide]: https://pymemoryeditor.readthedocs.io/en/latest/mcp.html#safety
[private security advisory]: https://github.com/JeanExtreme002/PyMemoryEditor/security/advisories/new
