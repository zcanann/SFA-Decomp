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

## COALESCER + COMPLETE allocation mechanism (READABLE end-to-end)
The mr-copy / "def coalesced into slot-result reg" class is the COALESCER, distinct from the
priority ranking. Status (capstone i386, controllight unit):
- **CONFIRMED:** `0x508c10` = per-class coalesce APPLY (called per class from the alloc main
  loop at 0x508753). Resets web `+0x14`=index, then walks the move/copy lists
  `0x5e9b00`,`0x5e99c4`,`0x5e98f4`; for each move node ALREADY FLAGGED coalesceable
  (`node+0x24 &2`, class match `node+0x25`), it propagates the surviving register into the
  coalesced web's `+0x04` and sets web flags `0x20`/`0x10`. So the move's coalesce flag is set
  UPSTREAM; 0x508c10 only applies it.
- **DECISION:** set upstream in the colorer `0x4fe520` (called at 0x50871a, before the apply) —
  fully disassembled below.
- **RETRACTED:** `0x508f10` (degree-vs-threshold bucket walk, `web+0x0c` vs `0x5e08a4`) did NOT
  execute on the controllight compile (bp 0x508f2c never hit) — so it's a CONDITIONAL path
  (likely spill bucketing), NOT the main coalesce decision. Earlier claim corrected.

### DECISION FOUND (0x4fe520 disassembled) — coalesce + register pick are ONE step
The colorer's inner fn `0x4fe552` ("color a web that is a move target") makes both:
- `0x5e3e68` = priority-ordered register CANDIDATE list (try-order for the class).
- `0x5e5c78` = interference/availability table, indexed `reg + class*0x20`; non-zero = taken by
  an already-colored interfering web.
- It assigns the FIRST candidate reg whose interference byte is 0 (highest-priority register that
  doesn't clash with already-colored neighbors), then `0x4fe5ef: or byte [moveNode+0x24], 2`
  sets the coalesce flag, `+0x25`=class, `+0x26`=chosen reg. 0x508c10 later applies it.

### COMPLETE allocation model
1. Webs colored in PRIORITY order (≈ spill cost/usage); first-colored wins the first free reg
   (why controllight's early-colored obj param takes r31).
2. Each web gets the first candidate reg not interfering with already-colored webs (0x5e5c78).
3. A copy COALESCES (mr eliminated) iff its two webs can share a reg — i.e. they do NOT interfere
   (not simultaneously live). A SURVIVING mr means source/dest interfere at the copy point.

### Plausible-C levers this unlocks
- Priority inversion: recover the original USAGE/lifetime that makes the target web higher
  priority (not a decl knob). Bank if interference-bound (controllight).
- Coalesce miss (surviving mr, e.g. global-base load): make the copy SOURCE dead right after the
  copy (don't keep the address temp live) → source/dest stop interfering → coalesce. Plausible
  only via a genuine lifetime change; bank otherwise.

### Read it live
- Coalesce/colour decision: break `*0x4fe5ef`; moveNode=`ebx`, chosen reg=`bp`, class=`*(char*)(esp+0x20)`.
- Per-web reg result: the web-list dump loop at `0x50886d` above.
