# `ThreadInfo`

A single thread inside a target process.

```python
from PyMemoryEditor import ThreadInfo
```

`ThreadInfo` is a `@dataclass(frozen=True)` returned by `process.get_threads()`.
Each backend fills in the fields its OS surfaces cheaply; fields left `None`
mean "this platform does not expose that attribute via the API we use".

## Fields

```{eval-rst}
.. py:class:: ThreadInfo(tid, start_address=None, state=None, priority=None, raw=None)

   .. py:attribute:: tid
      :type: int

      Thread identifier. **The meaning of `tid` is platform-specific:**

      - **Linux** — POSIX TID. Same namespace as PID; ``gettid()`` returns
        this.
      - **Windows** — kernel-assigned global thread id (DWORD) from
        ``THREADENTRY32``.
      - **macOS** — Mach thread port name from ``task_threads``. Not the
        BSD pthread id.

   .. py:attribute:: start_address
      :type: Optional[int]

      Entry point of the thread, when the OS exposes it cheaply. ``None``
      when not available.

   .. py:attribute:: state
      :type: Optional[str]

      Short human-readable state — e.g. ``"R"`` / ``"S"`` on Linux. ``None``
      when not available.

   .. py:attribute:: priority
      :type: Optional[int]

      Scheduling priority value as reported by the OS. The scale is
      platform-specific; ``None`` when not available.

   .. py:attribute:: raw
      :type: Any

      Underlying platform handle/struct (``THREADENTRY32`` on Windows, the
      TID string from ``/proc/<pid>/task/`` on Linux, a Mach port int on
      macOS). Useful for advanced callers that need to make follow-up
      OS-specific calls.
```

```{admonition} Don't mix tids across platforms
:class: warning

A `tid` returned on Linux is **not** comparable to a `tid` returned on
Windows or macOS — they live in different namespaces. The same warning
applies to mixing `tid` and `pid` values, which only share a namespace on
Linux.
```

## Examples

### Listing threads

```python
with OpenProcess(process_name="game.exe") as process:
    for thread in process.get_threads():
        print(thread.tid, thread.state, thread.priority)
```

### The main thread shortcut

```python
print("Main thread:", process.main_thread.tid)
```

`process.main_thread` returns the thread with the lowest `tid` — by
convention the "main" thread. It returns `None` if the process has no
listable threads (rare; usually means it just exited).

### Counting workers

```python
threads = list(process.get_threads())
print(f"{len(threads)} threads running")
```

```{seealso}
- [Modules and threads guide](../guide/modules-threads.md)
```
