# METHOD: dynamic-RE probe of mwcceppc allocator (x86_64 Ubuntu) — CONFIRMED WORKING 2026-06-23

Reusable procedure for breaking inside the running compiler at guest VAs. Confirmed on
gdb 15.1 / native x86_64. **This is a DISCOVERY tool — use what it shows to write clean,
plausible-2002 C. Never to justify a coercion hack.**

## How to break (confirmed hits)
1. Get the single-unit compile command, drop the `sjiswrap` wrapper for a non-SJIS unit
   (invoke `mwcceppc.exe` directly under `wibo`), e.g.:
   `build/tools/wibo build/compilers/GC/2.0/mwcceppc.exe <flags> -c src/.../unit.c -o /tmp/x.o`
2. wibo (x86_64 ELF at 0x70000000+) maps the 32-bit PE at image base **0x400000**, no ASLR.
   gdb can't set a guest-VA breakpoint before the PE is mapped, so break at wibo's
   mode-switch thunk first:
   ```
   break call_EntryProc      # 0x703ca73c in the checked-in wibo
   run
   break *0x508680           # NOW the guest VAs resolve
   delete 1                  # drop the thunk bp
   ```
3. `commands N / silent / ... / continue / end` blocks count or inspect each pass entry.
   IMPORTANT: `silent` MUST be the first line of a `commands` block.

## Guest VAs (image base 0x400000, from assert_map_GC2.0.txt)
- Coloring.c          0x508680  0x508900  0x508c10 (coalescer)
- ValueNumbering.c    0x509010
- IroCSE.c            0x46a360    IroPropagate.c 0x470060

## Confirmed observable: pass-entry profile
controllight unit (one compile): Coloring@508680=9 @508900=4 coalescer@508c10=4
ValueNumbering@509010=57. (9 ≈ functions in the unit; coalescer 4 = fns with copies to
fold.) Profiling A vs B variants of a stuck fn isolates which pass diverges.

## Open / harder: reading the web→register RANKING
Counting hits is trivial. Reading the *allocation order* (which web gets which saved reg, and
why) needs the Coloring.c arg/struct layout (web list, interference graph) — that is genuine
mwcceppc data-structure RE (the README's "Coloring.c under-covered" frontier), not yet mapped.
Static disasm of 0x508680 + IDA/Ghidra on the anchors is the next step for that.

## BREAKTHROUGH 2026-06-23: reading the web→register RANKING (MILESTONE)
The allocator data structures ARE crackable. Recipe (capstone for i386 disasm since gdb
defaults to 64-bit and desyncs on `mov [disp32],reg`):

### Coloring.c structures (GC/2.0, image base 0x400000)
- `0x508680` = register-allocation main loop: iterates register CLASS 0..4 (`cmpb $5`),
  stores current class to global byte **`0x5ea299`**, per class loads start/end web indices
  from `0x5e9800[class*4]` (start) and `0x5e9b04[class*4]` (end), calls the per-class colorer.
- **`0x5e9858`** = pointer to the WEB ARRAY (array of web pointers). Populated DURING the pass
  (it's 0 at 0x508680 entry — read it inside the per-class walk, not before).
- Per-class apply/walk loop at `0x508864`: `web = webArray[esi]`, `esi` in `[start,end)`.

### Web struct (per node)
- **`+0x04` = IR node ptr** (value identity; 0 for synthetic/precolored temps)
- **`+0x14` (word) = ASSIGNED PPC register** (0,3,4 volatiles; 25..31 saved)
- **`+0x16` (word) = flags** (0x2 normal var, 0x4 precolored/temp, 0x40 loop-region, combos)
- web ARRAY INDEX = creation order (web 32 created before web 33 …)

### Dump recipe (gdb)
`break call_EntryProc; run; delete 1`; counter-break `*0x508680` (function #); break
`*0x50886d` and print `fn / cls=*(char*)0x5ea299 / web[esi] / reg=*(short*)(ebp+0x14) /
flags=*(ushort*)(ebp+0x16) / ir=*(uint*)(ebp+4)`.

### First real read — controllight_update (class 4 = GPR saved-reg webs)
web32→r31, web33→r25, web36→r27, web38→r26, web42→r29, web43→r30 (flags 0x2 = real vars);
web34/37/39/41 = the two-case loop webs (flags 0x42) sharing r26-r28. The first-created
function-scope web (web32 = the `obj` param, referenced at entry) takes **r31** — that IS the
"param-at-top" inversion, captured as ground truth.

### Still needed to make it CLEAN-C-actionable (next layer)
Map web→source variable: follow `+0x04` IR ptr to a name/symbol (if O4 keeps one), or match by
register against the known .o assignment. And read the PRIORITY the colorer assigns by
(creation-order vs spill-cost) from the per-class colorer (0x4fe520). With those, the inversion
becomes directed. METHOD only — not a lever list.

## MODEL (front-and-center for hunterb/hunterc): register = PRIORITY, not a decl knob
A GPR/FPR web's saved-register rank is set by the allocator's PRIORITY ordering (≈ spill cost
= usage × loop depth + live-range), NOT by declaration order (decl-order A/B is structurally
inert, confirmed). This is PLAUSIBLE-C-aligned: a value's register follows how the source
genuinely USES it — so to match the target you recover the original USAGE pattern, never game
a knob. NOTE: register COALESCING (copy-elimination, e.g. iceblast def→r5) is a SEPARATE pass
from this priority ranking — read the coalescer separately when chasing those.

### web→source identification (no name strings at O4)
O4 strips local names, so the web IR node (+0x04) carries no name. Map instead by:
- (a) REGISTER: cross-reference the web's +0x14 reg against the known .o assignment.
- (b) IR HEAP REGION: PARAMS' IR nodes live in a DISTINCT heap region from locals' — in
  controllight, obj(param) ir=0x6c12xxxx while all locals ir=0x6c62xxxx. Lets you pick the
  param web out instantly.

### Verdict gotcha (controllight_update — BANKED fn-context-bound)
"most-used wins" is NECESSARY but NOT SUFFICIENT. Ground truth: obj (param web32) is used
inline every iteration in BOTH case-loops AND is the earliest-created web, yet retail ranks it
r29 (LOW) while bit (web42, used in only one loop) gets r31. Hotter+earlier → lower contradicts
pure usage/creation order. The residual factor is interference-graph structure from the two
near-identical DIRECT/INVERTED loops sharing r25-r28. No plausible usage recovery flips it
(hoisting obj's loop address halved the reg-perm but added a web target lacks). Banked.

## ALLOCATION MODEL (high-level, supported by the dump) + coalescer status
**SOLID (validated by the web→reg dump on controllight AND iceblast):** register assignment is a
PRIORITY-ordered graph coloring — webs colored in priority order (≈ spill cost / usage / live
range), each taking a register not used by an already-colored INTERFERING web; declaration order
is structurally inert. A copy/move is eliminated (coalesced) when its two webs can share one
register — i.e. they do NOT interfere (not simultaneously live); a SURVIVING `mr` means source and
dest interfere at the copy point. This high-level model is supported by the dumped assignments and
the controllight verdict; it gives the right TRIAGE (usage-bound vs interference-bound).

**Plausible-C levers it implies:** priority inversion → recover the usage/lifetime that makes the
target web hotter (bank if interference-bound). Coalesce miss → make the copy SOURCE dead right
after the copy so source/dest stop interfering. Plausible only via a genuine lifetime change.

### COALESCER internals — NOT reliably RE'd yet (earlier claims RETRACTED)
I over-claimed the coalescer's exact functions; correcting honestly:
- `0x508c10` walks the move/copy lists `0x5e9b00`/`0x5e99c4`/`0x5e98f4` and propagates regs for
  flagged moves — that part reads plausibly, but the flag-SETTER is NOT confirmed.
- **RETRACTED:** `0x4fe552`/`0x5e3e68`/`0x5e5c78` as "the colorer + candidate list + interference
  table." Live trace showed `0x4fe552`'s reached path is the web-NUMBERING fast-path (`bp` returns
  sequential web INDICES 32,33,34…, not registers; `ebx+0x14` ≠ the assigned reg), so it is NOT
  the coloring/coalesce decision. The real colorer + interference structures are not yet located.
- **RETRACTED earlier:** `0x508f10` degree-threshold (never executed; conditional/spill path).

### What's TRUSTWORTHY to use now
The DUMP (web→register, +0x14, recipe above) — validated twice. Use it to TRIAGE a stuck
inversion: dump the webs, identify by register/IR-region, and classify usage-bound (recoverable
clean-C) vs interference-bound (bank with proof). The exact coalescer decision read needs a
careful re-trace of which fn actually colors (the search path, when global 0x5e9900==0) — not done.
