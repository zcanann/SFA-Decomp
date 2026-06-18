# Live-Debugging Workflow (Dolphin MCP) for Decomp Naming

A field-tested process for using a live Dolphin session (via the `dolphin` MCP) to
**identify objects, confirm struct-field and function semantics, and name symbols**
in the decomp — driving the game, reading/writing memory, and verifying behavior
in real time. Developed while naming `dll_0158_gunpowderbarrel` (the Krazoa Palace
"unlimited bomb pad") end-to-end; every technique below has a concrete worked example.

> Prime rule unchanged: we still recover plausible C and gate on **match %**, never
> asm. Live debugging tells you *what a symbol means*; the matching playbook
> (`CLAUDE.md` / `docs/matching_archive.md`) still governs *how you write it*.

---

## 0. Setup

1. Boot the game in Dolphin with the GDB stub enabled, load the symbol map.
2. `mcp__dolphin__connect` — reports halt state + symbol/unit counts.
3. The deferred MCP tools must be loaded with `ToolSearch` (`select:mcp__dolphin__…`)
   before first use.

Halt/run primitives:
- `resume` — free-run (non-blocking). Then `wait_stop` (waits for a bp/watch, no
  forced halt on timeout) or `halt` (Ctrl-C break).
- `continue` — resume **and block** until a breakpoint hits or it force-halts on timeout.
- `read_registers` / `read_memory` / `write_memory` / `write_register`.
- `set_breakpoint` / `watch_memory` (mode `write|read|access`) / `clear_breakpoint` /
  `clear_all_breakpoints`.
- `lookup` resolves symbol↔address with **no** Dolphin call (cheap; use freely).

**The game must actually be running** for per-frame code to execute. If `wait_stop`
returns nothing and the PC sits in `SelectThread` / `ZeroOffsetHandler`, the main
loop is paused (in-game pause or Dolphin-side pause) — ask the user to un-pause.

---

## 1. Identify any live object's type (the descriptor chain)

Every `GameObject` carries a DLL descriptor pointer at **`obj+0x68`** (`ObjAnimComponent.dll`,
an `int**`). The object's per-frame **update** function lives at **descriptor_base + 0x08**:

```
ppDesc      = *(obj + 0x68)        # pointer to the descriptor pointer
descBase    = *ppDesc              # the DLL export table base
updateFn    = *(descBase + 0x08)   # the update() callback
lookup(updateFn)  ->  e.g. "gunpowderbarrel_update", unit "…/dll_0158_gunpowderbarrel.c"
```

Worked example: an object at `0x81200f60` → `0x68` → `0x80338d78` → `*` = `0x80322d40`
→ `+8` = `0x801a1d48` → `lookup` = `gunpowderbarrel_update`. That one chain tells you
*exactly* which DLL/source a mystery object belongs to.

> **Myth busted:** in this build the object DLLs are resident at their **fixed**
> symbol addresses (`0x801A…`), not relocated. So `set_breakpoint <dll_symbol>`
> works directly. (Verify by `read_memory` on the symbol — a real PPC prologue
> `9421… / 7c0802a6` confirms the code is there.)

The player has **no** DLL descriptor (`obj+0x68 == 0`) — it's the engine's built-in
object, always index 0 of object group 0.

---

## 2. Enumerate what's loaded

- **Player:** `gObjGroupObjects[gObjGroupOffsets[0]]` (offsets[0] is 0) =
  `*(gObjGroupObjects)`. Look these up in `config/<region>/symbols.txt` if the MCP
  can't resolve a data symbol (e.g. `gObjGroupObjects`, `gObjGroupOffsets`).
- **Grouped (interactive) objects:** `gObjGroupObjects` is a flat pointer array;
  `gObjGroupOffsets[g]..[g+1]` slices group `g`. Dump the array, resolve each via
  §1 — instant census of crates/baskets/enemies/etc.
- **Full object list (linked):** head at `*(lbl_803DCB7C+4)`, next-link offset at
  `*(s16*)(lbl_803DCB7C+2)` (was `0x38`). Walk `obj = *(obj + linkoff)`. Reading
  `[+0x0C..]` per node gets **position + next + descriptor** in one `read_memory`.
- **Label-encoded addresses:** a symbol named `lbl_803DCB7C` *is* its address —
  use `0x803DCB7C` directly when `lookup` can't resolve it.

---

## 3. Find the object you care about

Two reliable angles — use whichever the situation gives you:

**By position.** Read the player position (`obj+0x0C` = X/Y/Z f32), then read each
candidate object's position and pick the nearest. Great for "the thing right in
front of me." Caveat: some objects store *local* vs *world* coords; static map
objects have `pos@0x0C == pos@0x24` (not moving), so trust those.

**By behavior (work back from the player).** The player's per-class state block
(`PlayerState`, at `player+0xB8` → `extra`) holds what it's interacting with. We
found the interacted object at **`PlayerState + 0x7F8`**, read live, and §1-resolved
it to the bomb. Reading the source of the relevant player state fn
(`fn_802A4D34` here) tells you *which field* to read.

> Don't trust names while doing this — they may be wrong/absent. Work from
> **addresses and behavior**. ("staff" turned out to be a guess; `triggerExplosion`
> fires every frame; etc.)

---

## 4. Catch events with breakpoints

DLL callbacks are at fixed addresses, so breakpoint them directly:
- **`<obj>_update`** — fires every frame per live instance (`r3`/`r31` = the object).
- **`<obj>_init`** — fires on spawn. Its **LR** = the spawner (find who creates a thing).
- A function called only on a specific transition (e.g. the un-hide block inside
  `update`) — breakpoint a **specific instruction** to fire exactly once per event.

**Map a source line → a live breakpoint address:** dump asm with
`tools/function_objdump.py <unit> <symbol>`, find the instruction (e.g. the `bl`
to a callee that only runs in the branch you want), then
`live = TU_base + objdump_offset`. Worked example: the barrel respawn un-hide block
called `ObjHits_SyncObjectPositionIfDirty` at objdump offset `0x1300`; with
`gunpowderbarrel_update` live at `0x801a1d48` (objdump `0x1234`), TU base =
`0x801A0B14`, so `bp 0x801A0B14 + 0x1300 = 0x801A1E14` fired exactly on respawn.

**Filtering a noisy watch/break:** when a watchpoint fires on every frame
(e.g. the player's anim-move word, rewritten by `ObjAnim_SetCurrentMove` constantly),
loop `resume`→`wait_stop` and inspect a register/value each hit, auto-continuing
until the one you want. Stationary player ≈ quiet; moving player ≈ noisy — ask the
user to hold still before arming. (Still slow — prefer §3 position/behavior lookup
when a value-filtered watch would take dozens of iterations.)

---

## 5. Confirm meaning by **modifying memory** (the high-value technique)

This is what makes live debugging decisive: change a byte/field/instruction and
watch the game react. Three patterns we used:

| Goal | Action | Result that confirmed it |
|---|---|---|
| Field is a detonation trigger | `write_memory` `detonateTrigger(state+0x16) = 4` on an idle bomb | bomb exploded untouched → `unk16` = arm/detonate state |
| Field is a respawn flag | clear `respawns`(configFlags bit 0x80): `configFlags 0xc0→0x40`, then detonate | bomb blew up and **never came back** → bit 0x80 = respawn-vs-remove |
| Value is a timer in frames | patch the `li r4,60` immediate (`38 80 00 3c → 38 80 02 58`) feeding `s16toFloat(&respawnTimer,…)` | respawn went 1s → 10s → `respawnTimer` is the respawn delay |

Notes:
- **Find the *right* instruction first.** Our first timer patch did nothing — the
  barrel took the `configFlags` code path (`update+0x480`), not the `gen==0` path we
  patched. A **write-watchpoint on the field** (`watch_memory state+0x18 write`)
  caught the actual setter (`s16toFloat` from `update+0x480`) and the value written
  (`0x44160000` = 600.0), proving the patch executed (no JIT staleness).
- **Save states restore *all* of RAM** — including your code patches. Patching an
  engine "remove object" path can delete an object permanently; tell the user to
  reload a save state to recover (cleaner than hand-relinking the object list).
- Always **revert code patches** when done (or rely on a save-state reload).

---

## 6. Name it, then verify by **match %** (not byte-identity)

Cleanup work *should* be allowed to shift non-essential bytes. Gate on the
per-function **fuzzy match %**, which is the project's source of truth:

```bash
rm -f build/<REGION>/src/<unit>.o
ninja build/<REGION>/src/<unit>.o && ninja report.json
python3 - <<'PY'
import json; r=json.load(open('build/GSAE01/report.json'))
for u in r['units']:
  if '<unit-id>' in u['name']:
    for f in u['functions']:
      if f['fuzzy_match_percent']<100: print(f"{f['fuzzy_match_percent']:6.2f}%  {f['name']}")
PY
```

Capture a **per-function baseline** before editing; after editing, no function may
drop below its baseline. Worked example: converting raw `sub[0x16]` byte accesses to
`((GunpowderBarrelState*)sub)->detonateTrigger` held every function at baseline
(unit avg `99.33%`) — a real readability win that strict byte-identity would have
scared us off.

`report.json` labels functions by their **target** symbol names, so your renames
won't change the labels there — matching is by **address**. That's expected.

**Match % is the only gate — byte-identity is never required.** Renames, struct
consolidation, removing duplicate/dead functions, and other source restructuring
are all fair game; just rebuild the unit + `report.json` and confirm no function
dropped below baseline. Don't byte-compare `.text` or chase md5 stability — a
function that was 100% and is still 100% is done, however much the source moved.

---

## 7. Watch out for load-bearing "redundancy"

A reviewer's instinct to "tidy up" often collides with matching reality. Things that
**look** like cruft but are intentional — always verify before changing:

- **`extern` type fudges are load-bearing.** `extern int barrelgener_getLinkId()`
  (empty params) is required because the call passes an `int*` as the handle —
  adding `(int obj)` *breaks compilation*. Same for `u8*`-vs-`int` param types and
  `undefined4*`-vs-`void*` (`*gCarryableInterface` is illegal on `void*`).
- **`extern fn_<addr>` aliasing a locally-defined function** *may* be removable
  (we replaced `fn_801A1230` calls with `gunpowderbarrel_triggerExplosion` and it
  stayed byte-identical) — but **test it**; the TU header may note it keeps helpers
  as out-of-line `bl`s.
- **Identical if/else arms and duplicated calls can be faithful.** Both the
  "both arms store the same const" branch and the "double `ObjGroup_AddObject`" we
  flagged were **real in the retail asm** (two `R_PPC_EMB_SDA21` relocs / two
  adjacent `bl`s). Check `function_objdump.py` before "fixing" — then leave a comment
  so it isn't re-flagged.

---

## 8. Parallelize a file review with a background agent

Spawn a read-only review agent (`Agent`, `model: sonnet`, `run_in_background: true`,
explicit *do-not-edit*) over the file while you keep working live. Ask it for: unused/
redundant externs, stale comments, Ghidra artifacts (`extraout_*`, `in_rN`, `undefined`),
duplicated branches, and clear-from-context `fn_`/`unk`/`lbl_` names. Treat its output
as **leads to verify**, not edits — its "make externs match defs" suggestions were
right for normal C but wrong for matching decomp (§7). You'll get a task-notification
when it finishes.

---

## 9. Commit hygiene

- `ninja` → confirm `EXIT=0` before committing (whole project, since shared-symbol
  renames touch other units).
- Re-run the match-% check; commit only with no regressions.
- On `main`: rebase onto the remote before pushing (other hunters push constantly);
  re-verify `ninja EXIT=0` *after* the rebase merges their work, then push.

---

## Quick reference — the loop that worked

```
connect → resume → (player acts) → halt/wait_stop
  → §1 resolve object type   (obj+0x68 → desc → +8 → lookup)
  → §3 find the object        (position, or PlayerState+0x7F8)
  → read its struct           (map fields against the source)
  → §5 write a field / patch  → observe behavior → field/flag MEANING confirmed
  → §6 rename in .c/.h/symbols.txt → rebuild → match % held? → keep
  → repeat; commit at clean checkpoints
```
