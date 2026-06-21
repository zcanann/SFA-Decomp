# fn_801B3DE4 (dll_01CA_dimexplosion) — documented partial @ 98.04%

> **✅ SOLVED 2026-06-21 — 100% byte-match. See `fn_801B3DE4_SOLVED.md` and CLAUDE.md recipe #131.**
> The "impossible / open-frontier / requires inline asm" conclusion below was WRONG: two clean-C
> levers close it — a no-op `e14 |= e` to defeat the front-end same-value merge (→ `mr r29,r31`),
> and #112 K-grouping onto the base for the random section. Kept below only as a record of the
> (long, repeatedly-mistaken) negative path. Do not re-attack — it's matched.

Per the prime directive: residual that won't yield → commit the partial, document the
target-vs-ours asm shape, keep on the retry list.

## State
- Unit: `src/main/dll/DIM/dll_01CA_dimexplosion.c`, compiler GC/2.0 (`-O4,p`).
- `fuzzy_match_percent` = **98.0387**. Pragmas: `peephole off`, `opt_propagation off`.

## The single divergence
Saved-register allocation is otherwise correct (`state→r28`, `off→r30`, `e→r31`). The
target keeps a SECOND callee-saved register holding the same value `state+off`, used
only for the `0x14` field, established by a copy right after the `sqrtf` call:

```
target:  add r31,r28,r30        mine:  add r31,r28,r30
         ...                            ...
         bl  sqrtf                      bl  sqrtf
         ...                            ...
         mr  r29, r31     <-- MISSING   (folded)
         stw r0, 0x14(r29)              stw r0, 0x14(r31)
         ...                            ...
         lwz r0, 0x14(r29)              lwz r0, 0x14(r31)   (all 0x14 use r31)
```

`e` and `e14` both equal `state+off`. O4 value-numbering proves them equal and
substitutes `e14→e`, eliminating the copy (no `mr`, and the `0x14` accesses use `r31`).
The target keeps two registers for the same value connected by `mr r29,r31`.

## Root cause (localized via compiler RE tooling)
The fold is in MWCC's value-numbering pass — `ValueNumbering.c`, mapped to `mwcceppc.exe`
@ `0x509010` by `tools/mwcc_assert_map.py`. This matches the existing CLAUDE.md worked
example: "the `mr r29,r31` base copy that O4 value-numbering folds away."

## Source levers tried — ALL fold to one register (byte-identical or no `mr`)
1. `e14 = e` (copy)                              8. `register int e14`
2. embedded-assign in store addr (#116)          9. phi via `if(b==0xff) e14=e` (#94)
3. post-`sqrtf` sequencing of `e14=e` (#94)      10. phi via `b ? e : state+off`
4. `char* e14` retype (#77)                      11. `optimization_level 0/1/2/3` (#95/#108)
5. `(int)(long)e` VN-split (#114)                12. `opt_common_subs off`
6. fresh memory re-deref `*(obj+0xb8)+off` (#130)13. un-naming / inline `(state+off)` (#107)
7. `e14 = state + idx*0x30`                       + decl-order/hoist brute battery
None produced `mr r29,r31`. Confirmed by objdump grep on the rebuilt `.o` each time.

## Dynamic instrumentation — NOW OPERATIONAL (x86_64 Ubuntu, 2026-06-20)
The Mac block is gone. On native x86_64 Linux, wibo maps the PE at image base 0x400000 and
runs the guest in compatibility mode; a software breakpoint at a guest VA (`0x509010`) hits
and gdb reads regs normally. Setup (no sudo): `docs/mwcc_re/gdb_setup.sh` (fetches gdb +
libs as .debs into /tmp). Break at wibo's `call_EntryProc` first (maps the PE), then set the
guest-VA breakpoint. Standalone repro TU: `docs/mwcc_re/fn_801B3DE4_mini.c` (raw-offset
field accesses; reproduces the FOLD but not the whole-TU coloring).

Pass-entry profile for ONE compile of fn_801B3DE4 (from the mini TU under gdb):
`ValueNumbering` (0x509010) **96x**, `IroPropagate` 9x, `IroCSE` 2x, `Coloring` 1–2x each.

## REFINED DIAGNOSIS (supersedes the "VN folds unconditionally" framing above)
The handover blamed value-numbering, but the target emits `mr r29,r31` — a **copy of r31**,
not an `add r28,r30` recompute — so VN/codegen DID prove e14==e. The real shape is:
- The two `state + off` computations (e at line 186, e14 at line 194) sit in the SAME entry
  basic block, separated only by stores and the sqrtf call (calls don't split BBs, and
  state+off is pure arithmetic a call can't kill). **LOCAL CSE merges them unconditionally.**
- Proven robust: the fold to a single register survives `optimization_level 0/1/2/3/4` AND
  `peephole off` AND `opt_propagation off` AND `opt_common_subs off` (the latter only
  disables *global* CSE; local in-BB CSE still folds — verified: with all three off, one
  `add r28,r29,r5` feeds every field incl. 0x14). O1 gives `_savegpr_26` (6th saved reg) but
  STILL no separate e14 / no `mr` — the CLAUDE.md worked-example claim that "O1 yields the
  `mr r29,r31`" is INACCURATE (checked in both mini and in-tree).
- The target's copy is materialized AFTER sqrtf, i.e. the original computed the 0x14 base
  inline in the store statement. Reproducing that position (T1: inline `(state+off)` at each
  0x14 use; T2: `int life = (int)(K*sqrtf(spd)); e14 = state+off;` after the call) folds
  identically — position-independent, as expected for a pure expr in one BB.
- Best theory for the target's surviving copy: in the retail compile CSE turned the 2nd
  state+off into a COPY (not a substitution) that reached the **conservative coalescer**
  (Coloring.c 0x508c10), which refused to merge r29 into r31 under that TU's register
  pressure. In our builds CSE *substitutes* (eliminates e14 before coalescing), so no copy
  ever reaches the coalescer. Why CSE copies-vs-substitutes here is the open question for the
  next dynamic session (break in IroCSE 0x46a360 / VN 0x509010 and watch state+off's 2nd
  occurrence).

## Source levers tried (this session, on top of the 13 above) — all fold or regress
`e14=e` (97.32, VN-merges to one web, allocator scrambles to r28); `(int)((long)state+off)`
and `state+(int)(long)off` (97.32, splits the web but parks e14 in r28, no copy, worse);
`(int)((long)(state+off))` / `(int)((char*)state+off)` (fold/regress); inline-T1, post-call-T2
(98.04 unchanged); address-taken `&e14` (93.85, spills). The #36/#77 whole-TU coloring
coupling is the real wall: any VN-split that separates e14 rescrambles the function's 5-reg
coloring instead of cleanly ADDING a 6th (r29) + copy.

## Verdict / retry list
Banked at 98.04% (single missing `mr r29,r31`). No clean-C lever at any opt level / pragma
combination reproduces it; inline asm forbidden. The fold is local-CSE-driven and robust; the
target's copy is a coalescer artifact of the full-TU register pressure, not source-reachable
without perturbing the documented #36/#77 coloring coupling. Dynamic RE is now operational —
the precise next attempt is to instrument IroCSE/VN and find why CSE inserts a copy (not a
substitution) for the 2nd state+off, then engineer a source construct that triggers the
copy-insertion path while leaving the other 5 saved-reg webs intact.

## DEEP RE — CONCLUSIVE ROOT CAUSE (2026-06-20, x86_64 session 2)
After exhausting source levers, the deep allocator RE settled the mechanism definitively.
The earlier "local CSE" framing was incomplete — the true root cause:

**The divergence is a register-allocator outcome: the target holds `state+off` in TWO
overlapping saved regs (r31 AND r29 are both live and equal in the falloff), joined by a
`mr` copy that SURVIVES coalescing. Our compiler never produces two overlapping same-value
ranges — it always keeps one register.** Evidence (all via the gdb/patched-compiler harness):

- **It is NOT a CSE pass.** Binary-patched the compiler to ret-disable IroCSE (0x46a360),
  IroPropagate (0x470060), IroRangeProp (0x49ea50), AddPropagation (0x56ba20), ValueNumbering
  (0x509010), and NOP'd the VN operand-substitution at 0x509098. The single-register fold
  SURVIVES ALL of them → the two `state+off` are merged by the FRONT-END value-numberer
  before any optimizer runs. Cannot create two source webs.
- **Same-value copies always coalesce.** `e14 = e` + register pressure (N=0..8 extra live
  GPRs) → the copy is ALWAYS coalesced away (any-saved-mr=0). MWCC correctly merges a copy
  whose src/dst hold the same value regardless of degree (no true interference). So the
  target's surviving same-value copy contradicts our compiler's coalescer on every input.
- **Opaque base doesn't help.** `e14 = identBase(state+off)` (call result, VN-opaque) still
  folds 0x14 into r31 — no overlap. The corpus splits that DO survive (HuPrcChildCreate's
  r29/r30) come from a CALL-RESULT pointer flowing through INLINED calls, or a LOOP-diverging
  walk (explosion_render `p=state; p+=0x30`). fn_801B3DE4 is a straight-line COMPUTED base —
  the one shape that yields the overlap, and it appears in ZERO of ~1750 functions across
  SFA/MP4/pikmin2/prime/tww/mkdd/melee.
- **Not a compiler version.** All of GC 1.2.5,1.2.5n,1.3,1.3.2,1.3.2r,2.0,2.0p1,2.5,2.6,2.7
  fold (none split). NOTE: siblings in this very unit (explosion_update etc.) are 100% with
  GC/2.0, so the compiler is correct and the match IS reachable in principle — we just can't
  find the source shape, and the front-end merge blocks constructing it.

**Verdict:** genuine #108 open-frontier residual. Banked at 98.04%. The only remaining lever
would be external knowledge of the original source structure (macro expansion? a specific
helper signature?) that happened to defeat the front-end's same-value merge. RE harness,
patched-compiler diagnostics, and the 7-game corpus scanner are preserved under /tmp + this dir.

## PHI BREAKTHROUGH + the closed obstacle (session 2 cont.)
Found the ONE construct that defeats the front-end same-value merge and produces a surviving
`mr` copy + a separate single-reg web for 0x14 (the target's exact shape):
  `e14 = state + off; if (b == 0xab) { e14 = 0; }`  → emits `mr r27,r31`, 0x14 via r27.
This PROVES the structure is reproducible. BUT every realization needs a phi (two reaching
defs is the only way the front-end won't merge two equal webs), and the phi's branch +
alternate-value are irremovable overhead the target lacks:
- Foldable-false conditions (`if(0)`, `if(1==2)`, sizeof) are eliminated BEFORE phi creation → no split.
- Non-foldable conditions keep the branch (cmpwi+b+li), netting 182–184 instrs / 91–96% (worse
  than the 178-instr/98.04% baseline). opt_dead_code/opt_dead_assignments don't remove it.
- Tying the 2nd def to an existing branch + a live value (`if(rand)…{ e14=obj; }`) reaches 180
  instrs but 96.8% — because it puts a WRONG value (obj) on one path; the target uses state+off
  on ALL paths.
**Closed obstacle:** the target's branch-free `mr` between two *known-equal single-def* webs is a
contradiction for our compiler — a register copy means the value is known equal, and known-equal
is exactly why the front-end/coalescer merges it. Only a phi (genuinely-maybe-different) escapes
the merge, and a phi costs a branch the target doesn't have. So 100% is not expressible in clean C
with our mwcceppc build; it requires either the original's (unknown) source shape that happened to
land a phi-web with zero net overhead, or a front-end/coalescer nuance in Rare's exact build.
