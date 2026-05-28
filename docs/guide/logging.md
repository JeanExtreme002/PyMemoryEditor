# Logging and diagnostics

PyMemoryEditor uses the standard `logging` module to emit informational
messages from inside its scans. By default, the library is **silent** — a
`NullHandler` is attached so nothing is printed unless you opt in.

## Turning logging on

To see what the library is doing internally, attach a handler to the
`PyMemoryEditor` logger:

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("PyMemoryEditor").setLevel(logging.DEBUG)
```

You'll start seeing messages like:

```
DEBUG    PyMemoryEditor: skipping region 0x7FFD0000–0x7FFD2000 (read failed)
WARNING  PyMemoryEditor: partial read at 0x14010F4F4 (got 6 of 8 bytes)
```

## Log levels

<table>
<tr><th>Level</th><th>When it fires</th></tr>
<tr><td><code>DEBUG</code></td><td>Transient skips (pages vanished mid-scan, unreadable chunks).</td></tr>
<tr><td><code>WARNING</code></td><td>Surprising-but-recovered conditions (partial reads, <code>mach_vm_protect</code> restore failure on macOS).</td></tr>
</table>

## Routing logs

You can route the logger anywhere you like — to a file, to a Qt widget, to a
remote log collector:

```python
import logging

logger = logging.getLogger("PyMemoryEditor")
handler = logging.FileHandler("memscan.log")
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)
```

## The bundled GUI app

The GUI app exposes the same log stream in its **Log Console**:

<table>
<tr><td><b>Menu</b></td><td>Tools → Log Console</td></tr>
</table>

Toggling DEBUG verbosity in the console reveals the same messages the library
sends to the Python logger.

## macOS write-side-effect warning

On macOS, writing to a read-only page transparently elevates the page
protection, performs the write, and tries to restore the original
protection. If the restore step fails, the library emits a `ResourceWarning`
and the target page is left more permissive than it started.

```python
import warnings

# Treat the warning as an error so you don't miss it.
warnings.filterwarnings("error", category=ResourceWarning)
```

See [Platform Notes → macOS](project:#macos) for the details.

```{seealso}
- [Troubleshooting](../troubleshooting.md) — common errors and how to fix them.
```
