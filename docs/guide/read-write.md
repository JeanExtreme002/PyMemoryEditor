# Reading and writing memory

`read_process_memory` and `write_process_memory` are the two building blocks of
PyMemoryEditor. Once you know an address, you read or write it like any other
Python variable.

## Supported types

PyMemoryEditor supports the **five primitive Python types** typically found in
process memory:

<table>
<tr><th>Type</th><th>Default size</th><th>Notes</th></tr>
<tr><td><code>int</code></td><td data-label="Default size"><b>4 bytes</b></td><td data-label="Notes">Signed integer. Override to 1/2/8 for other widths.</td></tr>
<tr><td><code>float</code></td><td data-label="Default size"><b>8 bytes</b></td><td data-label="Notes"><code>double</code> by default; pass 4 for <code>float32</code>.</td></tr>
<tr><td><code>bool</code></td><td data-label="Default size"><b>1 byte</b></td><td data-label="Notes">C <code>bool</code>.</td></tr>
<tr><td><code>str</code></td><td data-label="Default size">— (required)</td><td data-label="Notes">UTF-8 decoded with <code>errors="replace"</code>.</td></tr>
<tr><td><code>bytes</code></td><td data-label="Default size">— (required)</td><td data-label="Notes">Raw, no decoding.</td></tr>
</table>

For numeric types, you can pass `bufflength=None` (or just omit it) to use the
default. For `str` and `bytes`, the size is **required when reading** (the
library needs to know how many bytes to pull back) but **optional when
writing** — a write simply stores the value you gave it.

```{tip}
Prefer the **typed shortcuts** below (`read_int`, `write_float`, `read_string`…)
if you don't want to think about sizes at all — the width is baked into the
method name.
```

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

    # Write a string — the size is optional; None just stores your text as-is
    process.write_process_memory(address, str, None, "Hello!")

    # Write raw bytes
    process.write_process_memory(address, bytes, 4, b"\xDE\xAD\xBE\xEF")
```

```{admonition} Writing text? Count characters, not bytes.
:class: tip

For `str` / `bytes` writes, `bufflength` is just a **minimum** width — your
value is always written in full. So `write_process_memory(addr, str, 3, "olá")`
writes all of `"olá"` even though the `á` takes 2 bytes (4 bytes total): you can
think in characters and never worry about UTF-8 byte math. Pass a *larger*
size to clear a fixed-size field (the extra space is zero-filled).
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

## Typed shortcuts

Don't want to remember that an *Int32* is 4 bytes or that *unsigned* needs
special handling? Use the **typed shortcuts**. Each one is a `read_*` /
`write_*` pair with the size and signedness baked into the name:

```python
with OpenProcess(process_name="game.exe") as process:
    hp    = process.read_int(0x7FF40010)     # signed, 4 bytes
    gold  = process.read_uint(0x7FF40014)    # unsigned, 4 bytes
    speed = process.read_float(0x7FF40018)   # 32-bit float

    process.write_int(0x7FF40010, hp + 100)  # heal up
    process.write_bool(0x7FF4001C, True)     # toggle a flag
```

No `bufflength`, no `pytype` — just the address (and the value, when writing).
Here's the full set; every `read_*` has a matching `write_*`:

<table>
<tr><th>Shortcut</th><th>Reads / writes</th><th>Bytes</th></tr>
<tr><td><code>read_char</code> / <code>read_uchar</code></td><td data-label="Reads / writes">8-bit integer — signed / unsigned</td><td data-label="Bytes"><b>1</b></td></tr>
<tr><td><code>read_short</code> / <code>read_ushort</code></td><td data-label="Reads / writes">16-bit integer — signed / unsigned</td><td data-label="Bytes"><b>2</b></td></tr>
<tr><td><code>read_int</code> / <code>read_uint</code></td><td data-label="Reads / writes">32-bit integer — signed / unsigned</td><td data-label="Bytes"><b>4</b></td></tr>
<tr><td><code>read_long</code> / <code>read_ulong</code></td><td data-label="Reads / writes">32-bit integer — signed / unsigned</td><td data-label="Bytes"><b>4</b></td></tr>
<tr><td><code>read_longlong</code> / <code>read_ulonglong</code></td><td data-label="Reads / writes">64-bit integer — signed / unsigned</td><td data-label="Bytes"><b>8</b></td></tr>
<tr><td><code>read_float</code></td><td data-label="Reads / writes">32-bit floating point</td><td data-label="Bytes"><b>4</b></td></tr>
<tr><td><code>read_double</code></td><td data-label="Reads / writes">64-bit floating point</td><td data-label="Bytes"><b>8</b></td></tr>
<tr><td><code>read_bool</code></td><td data-label="Reads / writes">boolean</td><td data-label="Bytes"><b>1</b></td></tr>
<tr><td><code>read_string</code> / <code>read_bytes</code></td><td data-label="Reads / writes">text / raw bytes</td><td data-label="Bytes">you choose</td></tr>
</table>

```{note}
Widths are **fixed and the same on every OS** — `long` is always 4 bytes here,
`longlong` always 8 — so your code reads the same number of bytes on Windows,
Linux and macOS.
```

## Working with text

`read_string` and `write_string` are the friendly way to handle text — no byte
counting, no manual decoding:

```python
with OpenProcess(process_name="game.exe") as process:
    # Write your text — UTF-8 encoding (accents, emoji…) is handled for you.
    process.write_string(0x7FF40020, "Pedro")

    # Read it back: read up to 32 bytes, stop at the first NUL terminator.
    name = process.read_string(0x7FF40020, 32)   # -> "Pedro"
```

`read_string` reads up to the size you pass and returns everything **before the
first `\0`**, so a generous size like `32` gives you the real string without the
trailing padding. `write_string` writes exactly your text — pass
`null_terminator=True` if you're overwriting a longer value and want a clean
cut-off:

```python
process.write_string(0x7FF40020, "Ann", null_terminator=True)
# read_string now stops right after "Ann", even if "Pedro" was there before.
```

```{seealso}
Need the raw bytes with zero interpretation? Use `read_bytes(address, length)`
and `write_bytes(address, data)`.
```

## Common errors

- **`OSError`** — the address may have been freed between scan and write, or
  the page might not be writable. Wrap one-off writes in `try/except OSError`.
- **`PermissionError`** — the handle was opened without write access (Windows
  read-only handle). See [Opening a process](opening-process.md#permissions-windows-only).
- **`ValueError`** — `bufflength` was omitted for a `str` or `bytes` **read**
  (a write doesn't need it — it sizes itself to your value).

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
