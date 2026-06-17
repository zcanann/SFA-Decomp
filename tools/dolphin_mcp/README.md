# Dolphin Debugger MCP (SFA-Decomp)

Drive Dolphin's debugger from Claude to automate the function-discovery loop:
**set breakpoint/watchpoint → run game → read r3/LR/PC → resolve to a function → name it.**

It talks to Dolphin's built-in **GDB stub** over the GDB Remote Serial Protocol
(TCP). No Dolphin plugin, no `gdb` binary, no pip installs — pure stdlib Python.

## 1. Enable the stub in Dolphin

In `~/Library/Application Support/Dolphin/Config/Dolphin.ini`:

```ini
[Core]
GDBPort = 2159
```

(`[Interface] DebugModeEnabled = True` is also handy for the GUI debugger.)
Then **restart Dolphin and boot SFA** — the port must be set before boot.

## 2. Smoke-test the stub

```sh
python3 tools/dolphin_mcp/smoketest.py
```

Expect it to connect, halt, and print PC/LR/r3 resolved to symbol names. If it
says "could not connect", the stub isn't listening (check the ini / rebuild /
that the game is booted).

## 3. Register the MCP with Claude Code

```sh
claude mcp add dolphin -- python3 /Users/jackpriceburns/Code/sfa/tools/dolphin_mcp/server.py
```

Optional env: `DOLPHIN_GDB_HOST` (default 127.0.0.1), `DOLPHIN_GDB_PORT` (2159),
`DOLPHIN_GAMEID` (GSAE01).

## Tools

| Tool | Purpose |
|------|---------|
| `connect` / `status` | Connect to the stub / show state + active breakpoints |
| `whereami` | Resolve current PC + LR → `function+offset` and unit |
| `read_registers` | All GPRs + pc/lr/ctr/cr/xer/msr; resolves pc/lr/r3 |
| `read_register` / `write_register` | One register (r0-31, f0-31, pc, lr, ...) |
| `read_memory` / `write_memory` | Memory r/w (hex + big-endian u32 words) |
| `set_breakpoint` | Execution breakpoint at a symbol or address |
| `watch_memory` | Hardware watchpoint (`write` / `read` / `access`) |
| `clear_breakpoint` / `clear_all_breakpoints` | Remove breakpoints/watches |
| `continue` | Resume; blocks until a breakpoint hits or timeout (then force-halts) |
| `resume` | Free-run without blocking (for booting / free play) |
| `wait_stop` | Wait for a breakpoint/watch to fire; never force-halts on timeout |
| `step` | Single-step one instruction |
| `halt` | Break the running emulator |
| `lookup` | Symbol ↔ address resolution (no Dolphin needed) |

Addresses accept hex (`0x801ee668`), decimal, or a **symbol name**.

## Discovery loop example (in plain English to Claude)

> Boot the game, get to the cloudrunner level, then watch the steer field for
> writes and tell me which function writes it.

Two execution models:

- **Free play (recommended for getting in-game):** `resume` to run freely while
  you play; when you've set a breakpoint/watch, `resume` then `wait_stop` to
  catch the hit. `wait_stop` leaves the game running on timeout (call it again),
  so long stretches of play are fine. `halt` to break in manually.
- **Blocking:** `set_breakpoint`/`watch_memory` then `continue` — blocks until
  the hit, or force-halts at `timeout` (use when you expect the hit soon).

On any stop, the report includes `pc`, `lr`, and `r3` already resolved to
`function+offset` — exactly what you need to name the function.

While the game is **running** (after `resume`), register/memory reads are
rejected with a clear error — the stub only answers reads when halted. Call
`wait_stop` or `halt` first.

## How it works

- `rsp.py` — RSP client: packet framing/checksums, `p`/`P` registers, `m`/`M`
  memory, `Z`/`z` breakpoints+watchpoints, `c`/`s` + Ctrl-C halt. Register
  numbering matches Dolphin's `GDBStub.cpp` (GPR 0-31, FPR 32-63, pc 64, msr 65,
  cr 66, lr 67, ctr 68, xer 69, fpscr 70).
- `symbols.py` — loads `config/GSAE01/{symbols.txt,splits.txt}`; bisect lookup
  turns an address into `unit::function+offset`. The build byte-matches retail,
  so symbols.txt addresses are the live RAM addresses.
- `server.py` — MCP stdio transport (newline-delimited JSON-RPC 2.0) + tools.

## Notes / gotchas

- **Config key lives in `[General]`, not `[Core]`** — `MAIN_GDB_PORT` is
  `{System::Main, "General", "GDBPort"}`. A value under `[Core]` is silently
  ignored. Edit `Dolphin.ini` only while Dolphin is **fully quit** (it rewrites
  the file on exit and will clobber a live edit).
- **The stub freezes the CPU at boot** (`__start`) waiting for a client — a
  black screen on boot is expected. Connect, then `continue` to run the game.
- **One client per boot, and the stub tears down on disconnect.** Dolphin's stub
  accepts a single GDB connection for the lifetime of that emulation boot; when
  the client disconnects the port closes. So: **connect once and hold it for the
  whole session.** Any reconnect (new Claude session, or running the one-shot
  `smoketest.py`/`live_proof.py`, which close when done) needs a **game reboot**
  (Stop → Play) to get a fresh stub.
- **Never probe the port with `nc`/`telnet`.** A connect-then-drop consumes the
  stub's single client slot and tears it down. Only connect with the real RSP
  client (the MCP server, which holds the socket).
- The stub halts the **whole emulator** on break (fine for discovery).
- `continue` blocks up to its `timeout` (default 30s) waiting for a hit; trigger
  the in-game action during that window. On timeout it force-halts and says so.
- Watchpoints are hardware-backed and historically rough on some builds — if a
  watch never fires, fall back to an execution `set_breakpoint`.
