# Pattern scan (AOB / regex)

A **pattern scan** locates *data by its shape* rather than its value — the
technique Cheat Engine, IDA and Ghidra use to find code or data that moves
between builds. PyMemoryEditor accepts three input forms, all powered by the
same `search_by_pattern` method.

## When to use it

<table>
<tr><th width="40%">You want…</th><th>Use this</th></tr>
<tr><td>Find every email address in memory</td><td>Regex pattern</td></tr>
<tr><td>Locate a function whose absolute address changes between builds</td><td>IDA-style byte signature with wildcards</td></tr>
<tr><td>Recognize a custom struct header</td><td>Regex or IDA-style pattern</td></tr>
</table>

## Three pattern formats

### 1. IDA-style byte signature

The format used by almost every public AOB recipe online — space-separated
hex bytes with `?` or `??` as one-byte wildcards:

```python
for address in process.search_by_pattern("48 8B ? ? 00 00 89 ?"):
    print(f"Match at 0x{address:X}")
```

- Each token is **one byte**.
- Whitespace between tokens is free-form.
- `?` and `??` both mean *"any byte"*.

The number of matched bytes is inferred from the token count — you don't have
to pass `byte_length=`.

### 2. Raw bytes regex

Pass a `bytes` object — it's compiled with `re.DOTALL` so `.` matches any byte
(including `\n`, which is what you want when scanning binary memory):

```python
# Every email address in memory
email = rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"

for address in process.search_by_pattern(email, byte_length=128):
    raw = process.read_process_memory(address, bytes, 128)
    print(address, raw.split(b"\x00", 1)[0].decode("ascii", "replace"))
```

```{admonition} byte_length is required for regex
:class: warning

A regex doesn't have a fixed match width, so the scanner can't infer one.
Pass `byte_length=` set to the **maximum** number of bytes one match can
consume. The scanner uses it to compute chunk-overlap so matches that span a
chunk boundary aren't missed.
```

### 3. Pre-compiled `re.Pattern[bytes]`

If you reuse the same pattern many times:

```python
import re

pattern = re.compile(rb"PLAYER_\d+", re.DOTALL)

for address in process.search_by_pattern(pattern, byte_length=32):
    print(hex(address))
```

Same rule: `byte_length=` is required.

## Method signature

```{eval-rst}
.. py:method:: search_by_pattern(pattern, *, byte_length=0, progress_information=False, memory_regions=None)
   :no-index:

   :param pattern: an IDA-style hex string, a raw bytes regex, or a compiled
      ``re.Pattern[bytes]``.
   :param int byte_length: required for regex / compiled patterns — the maximum
      number of bytes one match can consume. Ignored for IDA-style strings.
   :param bool progress_information: when ``True``, yields ``(address, info)``
      tuples (same shape as :py:meth:`search_by_value`).
   :param memory_regions: optional snapshot from
      :py:meth:`snapshot_memory_regions` to skip region enumeration on iterative
      workflows.
   :returns: a generator of addresses (or ``(address, info)`` tuples).
```

## Examples in the wild

### Locating a function after a patch

```python
# Cheat Engine signature for a known function body.
pattern = "48 89 5C 24 ? 57 48 83 EC 20 48 8B D9 48 8B FA"

for address in process.search_by_pattern(pattern):
    print(f"Function at 0x{address:X}")
```

Because the byte signature stays stable across recompilations (only the
addresses change), this finds the same function in every build.

### Harvesting data from memory

```python
import re

# Match an IPv4 address as ASCII.
ipv4 = re.compile(rb"(?<![\d.])(\d{1,3}\.){3}\d{1,3}(?!\d)")

for address in process.search_by_pattern(ipv4, byte_length=64):
    raw = process.read_process_memory(address, bytes, 64)
    print(address, raw.split(b"\x00", 1)[0].decode("ascii", "replace"))
```

### Combining with the refine workflow

Pattern scans take a `memory_regions=` snapshot just like value scans:

```python
regions = process.snapshot_memory_regions()

for address in process.search_by_pattern(pattern, memory_regions=regions):
    ...
```

## Compiling patterns yourself

The pattern compiler is available as a standalone helper, useful for testing
without a live process:

```python
from PyMemoryEditor.util.pattern import compile_pattern

regex, byte_length = compile_pattern("48 8B ? 00 00")
print(regex.pattern, byte_length)
# b'\\x48\\x8B.\\x00\\x00' 5
```

See [Utilities API](../api/utilities.md) for the full reference.
