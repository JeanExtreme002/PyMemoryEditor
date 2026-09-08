# The MCP Server (AI assistants)

PyMemoryEditor ships a **Model Context Protocol server**, so an AI assistant
can drive the memory-editing loop itself: enumerate processes, attach to one,
scan for a value, narrow the matches as the value changes, then read or write
the address it converged on.

It is the Cheat Engine workflow — the tedious part of which is a search
problem with a human in the loop, which is exactly what an assistant is good
at.

> *"Find the health value in my game. It's 100 right now."*
>
> The assistant scans, asks you to take damage, refines, and hands you the
> address.

```{admonition} No flags needed — but you are asked before anything happens
:class: important

Consent is enforced where it can actually be given, not by hiding features:
attaching to a process you have not pre-approved asks **you** for permission
([Choosing your targets](#choosing-your-targets)), and your client confirms
**every single write** before it runs. `--read-only` drops the write tool
entirely if you want that guarantee below this process.

Read [Safety](#safety) before pointing it at anything you care about: the
server runs with your privileges and it is **not a sandbox**.
```

## Install

```bash
pip install "PyMemoryEditor[mcp]"
```

The `mcp` extra pulls in the official MCP SDK. The core library stays
dependency-free, and the tool layer itself imports nothing from the SDK.

## Register it with a client

### Claude Code

```bash
claude mcp add pymemoryeditor -- pymemoryeditor-mcp
```

You do not name a target here. The server asks you before it attaches to
anything, so one registration covers whatever you end up working on.

### Any client that reads `mcpServers` JSON

Claude Desktop, editors, and most other MCP hosts:

```json
{
  "mcpServers": {
    "pymemoryeditor": {
      "command": "pymemoryeditor-mcp",
      "args": []
    }
  }
}
```

```{admonition} The console script may not be on PATH
:class: tip

MCP clients launch the server from their own environment, which often is not
the virtualenv you installed into. If the client reports "command not found",
point it at the interpreter instead — the module entry point is equivalent:

    {"command": "/path/to/venv/bin/python", "args": ["-m", "PyMemoryEditor.mcp"]}
```

## Run it by hand

Handy for checking your flags before wiring up a client. The server speaks the
protocol over stdin/stdout, so it will simply sit there waiting — that is
correct behaviour.

```bash
pymemoryeditor-mcp                            # asks to attach; writes allowed
pymemoryeditor-mcp --read-only                # can never modify a target
pymemoryeditor-mcp --allow-process game.exe   # never asks for game.exe
pymemoryeditor-mcp --allow-any-process        # never asks at all (scripts/CI)
```

## Flags

<table>
<tr><th width="34%">Flag</th><th>What it does</th></tr>
<tr>
  <td><code>--read-only</code></td>
  <td>Removes the <code>write_value</code> tool, so the server can read and scan but never modify a target. On Windows the process handle is also opened without write rights, so the <i>kernel</i> enforces it rather than this process promising to. Writing is otherwise <b>on by default</b> — each write is confirmed by your client.</td>
</tr>
<tr>
  <td><code>--allow-process NAME</code></td>
  <td><b>Pre-approves</b> processes whose name contains <code>NAME</code>, case-insensitively, so attaching to them never prompts. Repeatable. Omitting it does <i>not</i> open the server up — unlisted targets ask you instead.</td>
</tr>
<tr>
  <td><code>--allow-any-process</code></td>
  <td>Never ask: open any target the denylist permits. For scripted or non-interactive runs where nobody is there to answer. Interactively, prefer the default.</td>
</tr>
<tr>
  <td><code>--allow-system-processes</code></td>
  <td>Lifts the built-in denylist of OS and credential processes (<code>lsass.exe</code>, <code>launchd</code>, <code>systemd</code>, …). Rarely what you want.</td>
</tr>
<tr>
  <td><code>--scan-batch-bytes BYTES</code></td>
  <td>Target memory covered between deadline checks during a scan (default 64 MiB). Smaller means a scan gives up closer to its time budget, at the cost of more per-batch overhead.</td>
</tr>
<tr>
  <td><code>--max-scan-results N</code></td>
  <td>Addresses one scan may keep. Default 50 000.</td>
</tr>
<tr>
  <td><code>--max-scan-seconds S</code></td>
  <td>Wall-clock budget for one scan. Default 30.</td>
</tr>
<tr>
  <td><code>--transport</code></td>
  <td><code>stdio</code> (default), <code>sse</code> or <code>streamable-http</code>. The HTTP transports expose this machine's memory to whoever can reach the port — see <a href="#safety">Safety</a>.</td>
</tr>
</table>

## The tools

<table>
<tr><th width="30%">Tool</th><th>What it does</th></tr>
<tr><td><code>server_info</code></td><td>Capabilities, limits, policy and open sessions. The assistant should call this first.</td></tr>
<tr><td><code>list_processes</code></td><td>Running processes the server is allowed to open.</td></tr>
<tr><td><code>open_process</code></td><td>Attach by pid or name → a <code>session_id</code>.</td></tr>
<tr><td><code>close_process</code></td><td>Detach and drop that session's scan results.</td></tr>
<tr><td><code>process_info</code></td><td>Bitness, address-space summary, modules and threads.</td></tr>
<tr><td><code>list_memory_regions</code></td><td>Page through the memory map, filtered by permission or backing file.</td></tr>
<tr><td><code>scan_value</code></td><td>First scan — eight comparison modes, five value types → a <code>scan_id</code>.</td></tr>
<tr><td><code>scan_pattern</code></td><td>AOB scan with <code>?</code> wildcards → a <code>scan_id</code>.</td></tr>
<tr><td><code>refine_scan</code></td><td>Next scan — narrow an existing result set. The step that makes it work.</td></tr>
<tr><td><code>list_scan_results</code></td><td>Page through a result set, reading each address's live value.</td></tr>
<tr><td><code>read_value</code></td><td>Read one typed value from an address.</td></tr>
<tr><td><code>write_value</code></td><td>Write one value. Your client confirms every call; absent under <code>--read-only</code>.</td></tr>
<tr><td><code>resolve_pointer_chain</code></td><td>Replay a Cheat Engine pointer recipe to its final address.</td></tr>
<tr><td><code>find_pointer_paths</code></td><td>Reverse pointer scan — turn a found address into a recipe that survives a restart.</td></tr>
</table>

## How a session actually goes

The assistant is instructed to follow the classic loop, because it is the only
reliable way to find an address:

1. `open_process` → a `session_id`.
2. `scan_value` with the value you can see now (health `100`). Expect
   *thousands* of matches — that count is a starting set, not progress.
3. You change the value in the target; the assistant calls `refine_scan` with
   the new value. Repeat two to four times.
4. `list_scan_results` reads the survivors' live values. The one that tracks
   what you report is the address.
5. `find_pointer_paths` on that address makes it reusable across restarts.

```{admonition} Scan results never leave the server
:class: note

A first scan for a common integer legitimately matches tens of thousands of
addresses. Returning them would burn the client's whole context on hex digits,
so a scan returns a **handle** (`scan_id`), a match count and a few spread-out
samples. Refining happens server-side; the addresses themselves are only paged
out at the end, when a handful remain.
```

## Choosing your targets

You do not have to decide up front which process the assistant may touch. The
server has three modes, and the default is the useful one:

<table>
<tr><th width="26%">Mode</th><th>When</th><th>Behaviour</th></tr>
<tr>
  <td><b>ask</b> (default)</td>
  <td>No flags</td>
  <td>Attaching to a new process prompts <b>you</b>, naming the process and pid and whether writes are possible. You can approve just this once, or tick <i>remember</i> to stop being asked for it.</td>
</tr>
<tr>
  <td><b>allowlist</b></td>
  <td><code>--allow-process</code></td>
  <td>Named targets attach silently; anything else still prompts.</td>
</tr>
<tr>
  <td><b>any</b></td>
  <td><code>--allow-any-process</code></td>
  <td>Nothing prompts. Use for automation.</td>
</tr>
</table>

So a single registration handles work you did not plan for. Ask for a process
by name and the prompt appears:

```text
Allow PyMemoryEditor to attach to "game.exe" (pid 4821)?

This gives the assistant read access to that process's memory.
Writes are ENABLED on this server, so it can also change values in it.

  [ ] remember   (Approve)  (Decline)
```

The decision is yours in the literal sense: the model can *request* a target,
but only your answer grants one, and a refusal is reported back to it as a
refusal. Approvals you remember last for the life of the server process and are
matched by name, so they survive the target restarting — which is routine when
you are editing a game between runs.

```{admonition} This needs a client that supports elicitation
:class: warning

The prompt is an MCP *elicitation* request. Claude Code supports it (2.1.76 and
later); Claude Desktop currently does not. On a client that cannot ask, there is
nobody to answer, so the attach is **refused** rather than silently allowed —
the error names the two flags that get you moving:
`--allow-process NAME` or `--allow-any-process`.
```

Independently of that, `open_process` and `write_value` are tagged so a client
always asks before running them, even in its most permissive auto-approve mode.
So in Claude Code you see and confirm the tool call itself as well.

## Safety

The server hands a language model the capability a debugger has. Treat it that
way.

**What the defaults give you**

- **No attaching behind your back.** Consent for a target is a runtime
  decision, not a config-file one, so a model that has been confused cannot
  widen its own reach — it can ask, and only you answer. The prompt names the
  process and pid, and says whether writes are possible.
- **No unattended writes.** `open_process` and `write_value` are tagged
  `requiresUserInteraction`, which makes a client prompt on **every** call —
  even in its most permissive auto-approve mode. `write_value` also returns the
  previous value, so a change can be undone.
- **A real read-only mode when you want one.** `--read-only` does not register
  the write tool at all, so the model cannot see it, let alone be talked into
  calling it; on Windows the handle itself carries no write rights.
- **A system-process denylist.** `lsass.exe`, `csrss.exe`, `launchd`,
  `kernel_task`, `systemd`, `sshd` and friends are refused. These hold
  credentials or keep the machine running; attaching to them is not what a
  memory editor is for.
- **Bounded scans.** Every scan stops at a result cap and a wall-clock budget,
  and a result set that stopped early is flagged `partial` so the assistant
  reports it rather than confidently refining a prefix.
- **Handles closed on shutdown.** No debug handle left open on your game.

**What it does not give you**

```{admonition} The server is not a privilege boundary
:class: warning

It runs with exactly the rights of the user who started it. The approval prompt
and `--allow-process` are guard rails that keep an assistant inside the task you
gave it — not a sandbox, and not protection against a determined operator.
Process names are matched by substring, and a name is not an identity: PIDs are
recycled and executables can be renamed.

Two specific things to avoid:

- **Do not expose the HTTP transports** (`--transport sse` /
  `streamable-http`) to a network you do not control. That publishes read —
  and write — access to this machine's process memory to anyone who can reach
  the port.
- **Be deliberate about prompt injection.** The assistant reads bytes out of a
  process it does not control. Text in a game's memory that looks like
  instructions is still just data — but a model that has been convinced
  otherwise can be steered. The prompts are what bound the damage: read the
  process name before approving an attach, and read the address and value
  before approving a write. `--allow-any-process` removes the first of those
  two checks, so pair it with `--read-only` unless you have a reason not to.
```

**Anti-cheat and terms of service.** Attaching to an online game's process is
often against its terms, and anti-cheat systems generally treat memory access
as tampering regardless of intent. That is between you and the game; the
library takes no position, but the consequence is yours.

## Platform notes

Attaching to another process needs privileges the OS does not hand out freely.
This is the same story as the rest of the library — see
[Platform Notes](platform-notes.md) — but it bites harder here, because the
client launches the server and you never see the error:

<table>
<tr><th width="20%">Platform</th><th>What you need</th></tr>
<tr><td>🪟 Windows</td><td>A target at the same integrity level, or run the client elevated.</td></tr>
<tr><td>🐧 Linux</td><td>Matching privileges plus a permissive <code>/proc/sys/kernel/yama/ptrace_scope</code>; often means launching the server with <code>sudo</code>.</td></tr>
<tr><td>🍎 macOS</td><td><code>task_for_pid</code> needs root or the <code>com.apple.security.cs.debugger</code> entitlement, and SIP protects Apple binaries outright.</td></tr>
</table>

Every attach failure the server reports carries the relevant hint, so the
assistant can tell you what to fix.

## Using the tools from Python

The tool layer is a plain class with no MCP dependency, which makes it usable
directly — for scripting, or for testing a workflow before handing it to an
assistant:

```python
from PyMemoryEditor.mcp import MemoryToolset, ServerConfig

# allow_any_process: there is no MCP client here to show an approval prompt,
# and you are the one calling, so consent is implicit. Writes are on by
# default; pass allow_write=False for a read-only toolset.
tools = MemoryToolset(ServerConfig(allow_any_process=True))

session = tools.open_process(name="game.exe")["session_id"]
scan = tools.scan_value(session, "int", "100", bufflength=4)

print(scan["count"], "candidates ->", scan["scan_id"])

# ...after the value changes in the target:
refined = tools.refine_scan(scan["scan_id"], value="87")
print(tools.list_scan_results(refined["scan_id"])["results"])
```
