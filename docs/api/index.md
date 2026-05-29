# API Reference

Every public class, method and helper PyMemoryEditor exposes. For
task-oriented walkthroughs, see the [User Guide](../guide/index.md).

## At a glance

<table class="glance-grid">
<tr><th>Symbol</th><th>What it is</th></tr>
<tr><td><a href="openprocess.html"><code>OpenProcess</code></a></td><td>The unified entry point — read, write, scan, allocate.</td></tr>
<tr><td><a href="enums.html">Enums</a></td><td><code>ScanTypesEnum</code>, <code>ProcessOperationsEnum</code>, <code>MemoryProtectionsEnum</code>.</td></tr>
<tr><td><a href="memory-region.html"><code>MemoryRegion</code></a></td><td>One region of the target's address space.</td></tr>
<tr><td><a href="remote-pointer.html"><code>RemotePointer</code></a></td><td>A live, re-resolving handle to a typed value.</td></tr>
<tr><td><a href="pointer-path.html"><code>PointerPath</code></a></td><td>A discovered static pointer path from a reverse scan.</td></tr>
<tr><td><a href="module-info.html"><code>ModuleInfo</code></a></td><td>A loaded executable or shared library.</td></tr>
<tr><td><a href="thread-info.html"><code>ThreadInfo</code></a></td><td>A thread running inside the target.</td></tr>
<tr><td><a href="errors.html">Errors</a></td><td>The exception hierarchy.</td></tr>
<tr><td><a href="utilities.html">Utilities</a></td><td>Low-level helpers under <code>PyMemoryEditor.util</code>.</td></tr>
</table>

```{toctree}
:maxdepth: 1

openprocess
enums
memory-region
remote-pointer
pointer-path
module-info
thread-info
errors
utilities
```
