# Enums

## `ScanTypesEnum`

```{eval-rst}
.. py:class:: ScanTypesEnum

   Comparison modes for :py:meth:`search_by_value` and
   :py:meth:`search_by_value_between`.
```

```python
from PyMemoryEditor import ScanTypesEnum
```

<table>
<tr><th>Member</th><th>Value</th><th>Matches when…</th></tr>
<tr><td><code>EXACT_VALUE</code></td><td data-label="Value"><code>0</code></td><td data-label="Matches when…">value == target <em>(default)</em></td></tr>
<tr><td><code>NOT_EXACT_VALUE</code></td><td data-label="Value"><code>1</code></td><td data-label="Matches when…">value != target</td></tr>
<tr><td><code>BIGGER_THAN</code></td><td data-label="Value"><code>2</code></td><td data-label="Matches when…">value &gt; target</td></tr>
<tr><td><code>SMALLER_THAN</code></td><td data-label="Value"><code>3</code></td><td data-label="Matches when…">value &lt; target</td></tr>
<tr><td><code>BIGGER_THAN_OR_EXACT_VALUE</code></td><td data-label="Value"><code>4</code></td><td data-label="Matches when…">value &ge; target</td></tr>
<tr><td><code>SMALLER_THAN_OR_EXACT_VALUE</code></td><td data-label="Value"><code>5</code></td><td data-label="Matches when…">value &le; target</td></tr>
<tr><td><code>VALUE_BETWEEN</code></td><td data-label="Value"><code>6</code></td><td data-label="Matches when…">min &le; value &le; max (used by <code>search_by_value_between</code>)</td></tr>
<tr><td><code>NOT_VALUE_BETWEEN</code></td><td data-label="Value"><code>7</code></td><td data-label="Matches when…">value &lt; min or value &gt; max</td></tr>
</table>

### Example

```python
from PyMemoryEditor import OpenProcess, ScanTypesEnum

with OpenProcess(process_name="game.exe") as process:
    for address in process.search_by_value(
        int, 4, 1000, scan_type=ScanTypesEnum.BIGGER_THAN,
    ):
        print(hex(address))
```

---

## `ProcessOperationsEnum` <small>(Windows only)</small>

```{eval-rst}
.. py:class:: ProcessOperationsEnum

   Bitmask of Windows process access rights, passed as the ``permission=``
   argument of ``OpenProcess`` on Windows.
```

Bitmask of [process access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
Defined as `IntFlag` so members can be combined with `|`:

```python
from PyMemoryEditor import ProcessOperationsEnum

mask = (
    ProcessOperationsEnum.PROCESS_VM_READ
    | ProcessOperationsEnum.PROCESS_QUERY_INFORMATION
)
```

<table>
<tr><th>Member</th><th>Hex</th><th>Required for</th></tr>
<tr><td><code>PROCESS_TERMINATE</code></td><td data-label="Hex"><code>0x0001</code></td><td data-label="Required for"><code>TerminateProcess</code></td></tr>
<tr><td><code>PROCESS_CREATE_THREAD</code></td><td data-label="Hex"><code>0x0002</code></td><td data-label="Required for">Creating a thread</td></tr>
<tr><td><code>PROCESS_VM_OPERATION</code></td><td data-label="Hex"><code>0x0008</code></td><td data-label="Required for">Allocating / freeing / changing page protection</td></tr>
<tr><td><code>PROCESS_VM_READ</code></td><td data-label="Hex"><code>0x0010</code></td><td data-label="Required for"><code>ReadProcessMemory</code></td></tr>
<tr><td><code>PROCESS_VM_WRITE</code></td><td data-label="Hex"><code>0x0020</code></td><td data-label="Required for"><code>WriteProcessMemory</code></td></tr>
<tr><td><code>PROCESS_DUP_HANDLE</code></td><td data-label="Hex"><code>0x0040</code></td><td data-label="Required for">Duplicating a handle</td></tr>
<tr><td><code>PROCESS_CREATE_PROCESS</code></td><td data-label="Hex"><code>0x0080</code></td><td data-label="Required for">Creating a process</td></tr>
<tr><td><code>PROCESS_SET_QUOTA</code></td><td data-label="Hex"><code>0x0100</code></td><td data-label="Required for">Setting memory limits</td></tr>
<tr><td><code>PROCESS_SET_INFORMATION</code></td><td data-label="Hex"><code>0x0200</code></td><td data-label="Required for">Setting priority class, etc.</td></tr>
<tr><td><code>PROCESS_QUERY_INFORMATION</code></td><td data-label="Hex"><code>0x0400</code></td><td data-label="Required for"><code>VirtualQueryEx</code>, token info</td></tr>
<tr><td><code>PROCESS_SUSPEND_RESUME</code></td><td data-label="Hex"><code>0x0800</code></td><td data-label="Required for">Suspend/resume the process</td></tr>
<tr><td><code>PROCESS_QUERY_LIMITED_INFORMATION</code></td><td data-label="Hex"><code>0x1000</code></td><td data-label="Required for">Limited info queries</td></tr>
<tr><td><code>PROCESS_SET_LIMITED_INFORMATION</code></td><td data-label="Hex"><code>0x2000</code></td><td data-label="Required for">Limited info set</td></tr>
<tr><td><code>PROCESS_ALL_ACCESS</code></td><td data-label="Hex"><code>0x1FFFFF</code></td><td data-label="Required for">Everything</td></tr>
</table>

### Default permission

The default mask used by `OpenProcess` on Windows is:

```python
PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
```

This is enough for both read and write operations plus region enumeration
(`VirtualQueryEx` needs `PROCESS_QUERY_INFORMATION`).

---

## `MemoryProtectionsEnum` <small>(Windows only)</small>

```{eval-rst}
.. py:class:: MemoryProtectionsEnum

   The Win32 ``PAGE_*`` page-protection constants.
```

The Win32 `PAGE_*` constants. Used as the `permission=` argument of
`allocate_memory` and surfaced in `region["struct"].Protect`.

```python
from PyMemoryEditor.win32.enums.memory_protections import MemoryProtectionsEnum
```

<table>
<tr><th>Member</th><th>Hex</th><th>Meaning</th></tr>
<tr><td><code>PAGE_NOACCESS</code></td><td data-label="Hex"><code>0x01</code></td><td data-label="Meaning">Disables all access.</td></tr>
<tr><td><code>PAGE_READONLY</code></td><td data-label="Hex"><code>0x02</code></td><td data-label="Meaning">Read-only.</td></tr>
<tr><td><code>PAGE_READWRITE</code></td><td data-label="Hex"><code>0x04</code></td><td data-label="Meaning">Read + write.</td></tr>
<tr><td><code>PAGE_WRITECOPY</code></td><td data-label="Hex"><code>0x08</code></td><td data-label="Meaning">Copy-on-write.</td></tr>
<tr><td><code>PAGE_EXECUTE</code></td><td data-label="Hex"><code>0x10</code></td><td data-label="Meaning">Execute-only.</td></tr>
<tr><td><code>PAGE_EXECUTE_READ</code></td><td data-label="Hex"><code>0x20</code></td><td data-label="Meaning">Read + execute.</td></tr>
<tr><td><code>PAGE_EXECUTE_READWRITE</code></td><td data-label="Hex"><code>0x40</code></td><td data-label="Meaning">Read + write + execute. <em>(allocate_memory default)</em></td></tr>
<tr><td><code>PAGE_EXECUTE_WRITECOPY</code></td><td data-label="Hex"><code>0x80</code></td><td data-label="Meaning">Read + execute + copy-on-write.</td></tr>
<tr><td><code>PAGE_GUARD</code></td><td data-label="Hex"><code>0x100</code></td><td data-label="Meaning">Pages become guard pages.</td></tr>
<tr><td><code>PAGE_NOCACHE</code></td><td data-label="Hex"><code>0x200</code></td><td data-label="Meaning">Non-cachable.</td></tr>
<tr><td><code>PAGE_WRITECOMBINE</code></td><td data-label="Hex"><code>0x400</code></td><td data-label="Meaning">Write-combined.</td></tr>
</table>

### Convenience composites

<table>
<tr><th>Member</th><th>Includes</th></tr>
<tr><td><code>PAGE_READABLE</code></td><td>Every PAGE_* that allows reads.</td></tr>
<tr><td><code>PAGE_READWRITEABLE</code></td><td>Every PAGE_* that allows writes.</td></tr>
</table>
