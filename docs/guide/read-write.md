# Reading and writing memory

`read_process_memory` and `write_process_memory` are the two building blocks of
PyMemoryEditor. Once you know an address, you read or write it like any other
Python variable.

## Supported types

PyMemoryEditor supports the **five primitive Python types** typically found in
process memory:

<table>
<tr><th>Type</th><th>Default size</th><th>Notes</th></tr>
<tr><td><code>int</code></td><td><b>4 bytes</b></td><td>Signed integer. Override to 1/2/8 for other widths.</td></tr>
<tr><td><code>float</code></td><td><b>8 bytes</b></td><td><code>double</code> by default; pass 4 for <code>float32</code>.</td></tr>
<tr><td><code>bool</code></td><td><b>1 byte</b></td><td>C <code>bool</code>.</td></tr>
<tr><td><code>str</code></td><td>— (required)</td><td>UTF-8 decoded with <code>errors="replace"</code>.</td></tr>
<tr><td><code>bytes</code></td><td>— (required)</td><td>Raw, no decoding.</td></tr>
</table>

For numeric types, you can pass `bufflength=None` (or just omit it) to use the
default. For `str` and `bytes`, you **must** pass the size.

## Reading a value

```python
from PyMemoryEditor import OpenProcess

with OpenProcess(process_name="notepad.exe") as process:
    address = 0x0005000C

    # Integers — 4 bytes by default
    score = process.read_process_memory(address, int)

    # 1-byte integer
    flag = process.read_process_memory(address, int, 1)

    # 8-byte float (double)
    speed = process.read_process_memory(address, float)

    # 32 bytes interpreted as a UTF-8 string
    name = process.read_process_memory(address, str, 32)

    # Raw bytes (no decoding)
    raw = process.read_process_memory(address, bytes, 16)
```

### Method signature

```{eval-rst}
.. py:method:: read_process_memory(address, pytype, bufflength=None)
   :no-index:

   :param int address: target memory address.
   :param Type pytype: one of ``bool``, ``int``, ``float``, ``str``, ``bytes``.
   :param int bufflength: value size in bytes. Optional for numeric types;
      required for ``str`` / ``bytes``.
   :return: the decoded value.
```

```{admonition} String decoding
:class: tip

When `pytype=str` the raw bytes are decoded with `errors="replace"` — invalid
UTF-8 becomes the replacement character `U+FFFD` instead of raising.
If you need the bytes verbatim, pass `pytype=bytes`.
```

## Writing a value

```python
with OpenProcess(process_name="notepad.exe") as process:
    address = 0x0005000C

    # Write an int (None = default size of 4 bytes)
    process.write_process_memory(address, int, None, 9999)

    # Write a 2-byte int explicitly
    process.write_process_memory(address, int, 2, 42)

    # Write a string
    process.write_process_memory(address, str, 32, "Hello!")

    # Write raw bytes
    process.write_process_memory(address, bytes, 4, b"\xDE\xAD\xBE\xEF")
```

### Method signature

```{eval-rst}
.. py:method:: write_process_memory(address, pytype, bufflength, value)
   :no-index:

   :param int address: target memory address.
   :param Type pytype: one of ``bool``, ``int``, ``float``, ``str``, ``bytes``.
   :param int bufflength: value size in bytes (``None`` for numeric types to use
      the default).
   :param value: the value to write.
   :return: the written value.
```

## Common errors

- **`OSError`** — the address may have been freed between scan and write, or
  the page might not be writable. Wrap one-off writes in `try/except OSError`.
- **`PermissionError`** — the handle was opened without write access (Windows
  read-only handle). See [Opening a process](opening-process.md#permissions-windows-only).
- **`ValueError`** — `bufflength` was omitted for a `str` or `bytes` write.

## Reading many addresses efficiently

When you have a **list of addresses** to read, do **not** loop over
`read_process_memory` — each call performs one syscall.

Use `search_by_addresses` instead, which reads each memory page only once and
extracts every requested address from it:

```python
addresses = [0x10000, 0x10010, 0x10020, ...]

for address, value in process.search_by_addresses(int, 4, addresses):
    print(f"0x{address:X} -> {value}")
```

On long address lists this is orders of magnitude faster.

```{seealso}
- [Searching memory](searching.md) — find addresses by value.
- [Pointers](pointers.md) — follow multi-level pointer chains.
```
