# SFA-Decomp Matching Playbook — FULL ARCHIVE

> Complete, unabridged playbook: every recipe with its full negative-maps, CRACKED/SUPERSEDED
> history, campaign/task notes, and open-puzzle analyses. `CLAUDE.md` is a lean lever-index
> distilled from this file — consult THIS file when a one-liner there isn't enough. Recipe
> numbers match between the two. This archive is the source of truth.

---

# SFA-Decomp Matching Playbook (MWCC 1.2.5n, EN v1.0)

Short field-tested reference for getting MWCC-compiled C to match the target
binary. Read in 60 seconds, apply in the order they appear; the later sections
are more invasive.

## Prime directive: recover plausible C, never asm

The goal of this project is plausible original source. **Inline `asm { }` is
forbidden — no exceptions.** A function at 80-99% fuzzy from clean C is more
valuable than a 100% byte match achieved by `asm`. Previously-sanctioned asm
recipes (material-mask `li`/`lis;ori` + `and`, GQR/MSR/HID0 ops, `rlwimi` bit
inserts, `register`-decl-order forcing) are all REVOKED — the repo owner is
actively reverting them ("Replace X flag asm with C" commits).

If a residual won't yield to the C one-liners and source-form tweaks below,
**commit the partial, document exactly what you tried, and treat it as an OPEN
problem.** There is always a C recipe for the divergence; we just don't know it
yet — every function is attemptable and nothing here is permanently impossible
(the cap-crack campaign proved dozens of former "caps" winnable: the s64
tar-pit, #61c pairs, #86 fold, the GVN class, the #121 field). New C techniques
land in this playbook as they're discovered, and a documented partial is the
exact seed the next technique grows from. Don't reach for asm to fill the gap —
the gap is the point, and the gap is recoverable.

Heuristic (these are checkpoints to record progress, never stop signs — re-attack
every partial when a new recipe lands):
- Residual is a single instruction / register-allocation choice? → commit the
  partial with the divergence documented, then keep it on the retry list.
- Function ≥80% fuzzy on clean C? → set the partial aside and circle back as
  techniques accumulate.
- Looks like "MWCC can't pick this from any C"? → **commit the partial** and
  flag the function so it gets revisited with the next playbook recipe (this
  exact framing is how the cracked caps got cracked). Never asm.

**FRESH-EYES PROTOCOL for set-aside residuals: re-attack WITHOUT reading the previous
attempt's negative map.** A documented "probed inert ×N" list anchors the next
attacker onto the same axes; FOUR set-aside residuals fell in ONE day to
attackers told only the score and "the playbook may be wrong" (SB_Galleon_func0E
95.9→100 — the "unproducible at O4" verdict was a wrong axis; SB_ShipGun_update
99.42→100 — every spelling battery missed that the LOOP-ELEMENT VARIABLE
IDENTITY was the lever; fn_801EE668 99.87→100 — the "#83 open allocator
threshold" was a clamp-arithmetic SPELLING, found via the in-repo oracle;
cfprisonguard's "retail-anomaly, permanently unmatchable" census verdict — a
dropped argument). Negative maps stay valuable
for the SAME axis (don't re-run them); the protocol is for finding the axis
nobody tried: derive the hypothesis from the target asm as if the function were
new, and only afterwards check the set-aside notes for overlap.

## Pragma states: what they are and where they come from (read before #1)

**Our per-fn `#pragma peephole/scheduling` wrappers are a MATCHING
INSTRUMENT, not a claim about the original source.** Retail game code almost
certainly did not carry per-function pragma forests; what we are reproducing
with them is per-function OPTIMIZER STATE whose original mechanism was
something else. Empirical findings (asm-bug investigation, byte-verified
probes on the bundled compilers):

- **The MWCC asm-function bug is REAL but version-bound**: on GC/1.2.5 and
  1.2.5n, an `asm void fn(void) {...}` definition DISABLES THE PEEPHOLE PASS
  for every subsequent function in the TU (scheduling unaffected;
  `#pragma peephole on` re-enables — same internal flag). FIXED in GC/1.3+.
  So in a 1.2.5-family unit, a mixed peephole map can mean the ORIGINAL had
  an asm function at the ON→OFF boundary — check that reading before adding
  per-fn wrappers in 1.2.5n units (MSL/audio lanes).
- **The main game lib is GC/2.0, which is IMMUNE** (probed: asm fn with
  nofralloc, with fralloc+body, and statement-level `asm {}` blocks — no
  effect). The bug therefore canNOT explain mixed peephole in the main lib.
- **Version tell — the PROLOGUE CONVENTION**: 1.2.5-family emits
  `mflr r0; stw r0,4(r1); stwu r1,...` (LR stored above the frame, stwu
  last); 1.3+/2.0 emits `stwu; mflr; stw r0,frame+4(r1)`. One glance at any
  fn's prologue identifies the compiler family. SFA main-lib targets are
  uniformly stwu-first = 2.0-class (also confirmed by codegen: shrine1CE's
  tail fns mismatch 1.2.5n under every off-arrangement, 8/24 fns).
- **What the original mechanism for main-lib state mixes most plausibly
  was**: per-FILE makefile flags for the uniform-state files (a file-global
  `-opt nopeephole`/schedule choice — most of our 178 uniform-state pragma
  files should become unit cflags, not pragmas), and for the genuinely
  mixed files an UNKNOWN mechanism — candidates: finer original TU splits
  than we model (our "file" = several original files each with uniform
  flags), original-source pragmas (possible but unusual), or an undiscovered
  GC/2.0 state trigger. The macro-pattern in our maps is ON-region→OFF-tail
  with holes; many holes are INERT wrappers (the #173 sweep found ~60), so
  the true mixes may be cleaner than our source suggests.
- **Cleanup gate**: any pragma simplification must be byte-verified
  (`md5sum` the .o before/after). The off/reset pairs are NOT always dead
  weight even inside a global-off — an un-reset `on` earlier in the file
  makes the gaps BETWEEN pairs ON (shrine1CE: deleting the "redundant"
  pairs changed the .o).

## High-impact one-liners (try first when a function is already 80-95%)

1. **`#pragma peephole off` + `#pragma scheduling off`** around the function
   (matched-with `#pragma peephole reset` + `#pragma scheduling reset` after).
   This alone routinely takes 80-95% fuzzy functions to 100% by disabling the
   peephole pass that fuses `extsb + cmpwi → extsb.`, `rlwinm + cmpwi →
   rlwinm.`, and similar dot-form merges. Single most useful change on this
   project. See `b7eda753` (dll_198 — 3 functions to 100%). The wrapper
   reproduces the optimizer STATE; see "Pragma states" above for what the
   original mechanism likely was — the pragma is our reconstruction tool,
   not an assertion the original carried it.
   **Caveat — peephole-off suppresses jump tables.** `peephole off` also turns a
   `switch` MWCC would lower to a jump table into a compare-chain. If a function
   is *all-switch with no bit-ops*, keep it OUTSIDE the peephole-off region so
   the jump table survives; if it mixes a switch with bit-ops you can't have
   both from this lever, so pick whichever the target uses and set the other aside as
   an open residual (revisit when a finer-grained pragma/recipe lands).
   **BUT peephole-off does NOT always kill the table — DENSE switches can keep
   both.** For a sufficiently dense switch (e.g. 30 contiguous cases) `#pragma
   peephole off` KEPT the jump table (verify: still two `bctr`) AND unfused the
   bit-test compares (`rlwinm`+`cmplwi` vs the merged `rlwinm.`), netting more
   than peephole-on. So don't *assume* the table dies — test peephole-off on a
   dense jump-table fn and check for `bctr`; you may get the table + the unfused
   compares together. (november10, fn_802B1E5C 30-case → +2%.)
   **Inside a file/region that is GLOBALLY `peephole off`, locally re-enable it
   for one jump-table function** by wrapping just that function in `#pragma
   peephole on` … `#pragma peephole reset` (the `reset` restores the surrounding
   global-off). MWCC then regenerates the jump table for that fn while the rest
   of the file stays peephole-off — combine with #13 case-order. Took
   `dvdCheckError` to 99.2% inside a global-peephole-off unit (placeholder_800066E0).
   **Pragma regions are per-REGION, not per-function — SPLIT a multi-fn region
   to capture asymmetric wins.** When one `peephole on` region wraps 2+ fns and
   whole-pair removal regresses a sibling (the gate-revert), move the `on` to
   wrap ONLY the fn that needs it and leave the other at the outer state:
   object.c fn_8002B758 67.46→78.69 with sibling fn_8002B860 held at 100.
   **Sweep finding (task #173, all 477 `peephole on` sites A/B'd): ~60 wrappers
   were INERT** (byte-identical .o with or without — the site sits in default
   peephole-ON context, the wrapper was defensive dead weight) and were removed;
   only 4 sites were genuinely load-bearing (waterfallControl
   tumbleweed_updateRollingMotion, lightmap drawFn_8005cf8c, mm.c mmFreeTick,
   shrine1CE dll_19B_update — kept). Before ADDING a `peephole on` wrapper,
   check the file's effective pragma state — in a default-ON file it does
   nothing. ⚠️ "Load-bearing" ≠ "original": shrine1CE dll_19B_update's wrap
   (and dimmagicbridge's) was a COMPENSATING INSTRUMENT — its real job was
   fusing the extsh on an `s16 += int`; replacing it with a width-correct
   compound `(s16)` addend cast let the wrap drop AND restored the #68
   deref-via-copy + the dense jump table under peephole-off (both units →
   100.0, near-100 sweep). Re-audit any "kept" wrap for a width-cast
   replacement before calling it load-bearing.
   **Treat the two pragmas independently — `scheduling off` ALONE is often the
   win.** For vtable-dispatch / call-heavy / FP-heavy functions, `scheduling
   off` by itself takes 40-70% → 95-100% (it stops MWCC reordering loads/stores
   and FP ops around calls), while `peephole off` can *hurt* them (jump-table
   suppression, clamp/compare fusion changes). Default to `scheduling off` only,
   and add `peephole off` *only* to kill a specific `extsb.`/`rlwinm.` dot-merge
   residual. Many object-DLL units lean scheduling-off; but the on/off choice is
   PER-FUNCTION, not per-unit — A/B test both each time. On placeholder_80220608:
   scheduling-off always; `peephole off` WINS on the arwing bit-test/flag handlers
   (target has UNFUSED `rlwinm+cmpwi` bit-tests + a redundant `clrlwi r0,r0,24`
   after byte-flag `|=`/`&=` that peephole-ON wrongly fuses/drops — fn_8022C30C
   91.2→98.3%, fn_8022CDEC 89.9→97%), but `peephole off` LOSES on the
   cror-float-compare-heavy handlers (arwarwing_update). Same unit, opposite
   answer — so measure both per function (corrects the earlier over-broad
   "80220608 = scheduling-off-only" claim).
   **`#pragma ... reset` POPS a stack — it does NOT reset-to-default.** `on`/`off`
   push; `reset` restores the *surrounding* state. So nested regions matter: a
   function between an outer `off` and an inner `... reset` is still `off`. When
   reproducing per-function pragma regions (esp. splitting/restructuring an
   interleaved file), model the pragma state as a STACK and emit the *effective*
   on/off for each function — tracking only the last-seen label silently compiles
   functions with the wrong setting (regressed 7 fns during the 80211C24 split
   until modeled as a stack).

2. **Replace `& 0xff7f`-style literal with `& ~0x80`** for single-bit clears.
   The bit-NOT form often produces `rlwinm` directly where the explicit
   inverted-literal form produces `andi.`. See `782a09a8`, `91f5f4ab`.
   **Inverse cap — CRACKED by recipe #74.** When target MATERIALIZES the mask
   (`li rX,-K; and` / `lis;or`) where every 32-bit C spelling gives
   `rlwinm`/`oris`, write the constant with an `LL` suffix
   (`x &= ~0x80LL;` / `x |= 0x800000LL;`) — MWCC then materializes exactly
   target's form. The old "leave as documented partial" guidance is obsolete;
   retry all previously-capped materialized-mask partials.

3. **`*(void **)ptr != NULL` instead of `*(int *)ptr != 0`**. The pointer form
   emits `cmplwi` (unsigned); the int form emits `cmpwi` (signed). Target
   almost always uses `cmplwi` for pointer-typed compares. See `a42bb90b`.
   **U-SUFFIX LITERALS are the width lever the `(u32)` cast can't be: `x == 0u`
   / `(x >> 6 & 1) == 0u` forces `cmplwi` on u8/bit-extract compares** where
   the `(u32)`-cast form is inert (probe-verified t3/t19/t20 + trickyGrowl's
   two banked width sites -> fixed). The suffix rides the COMPARE's type
   instead of the operand's, so nothing folds it away. Use before reaching
   for #58 width locals.
   **MWCC DROPS a `(u32)` cast on a `!= 0` compare — so `(u32)x != 0` still
   emits `cmpwi`; use `(void *)x != NULL` to force `cmplwi`.** For an `int`
   field/local holding a handle/pointer that target null-tests unsigned, the
   `(u32)`-cast form is INERT (the front-end folds `(u32)x != 0` back to
   `x != 0` and uses x's signed type); the pointer-cast `(void *)x != NULL`
   is the form that lands `cmplwi`. (miner-4: fn_801C5CE4 light null-test.)
   CAVEAT — when the int field is ALSO read with int arithmetic nearby
   (`inner->heldObj`), MWCC CSE-merges the loads and the int read's signedness
   wins the compare; the only fix is a struct-field pointer retype (header
   change, gold-gated) — body-local u32/volatile launders are inert/worse
   (fn_802A49C8, banked #108-CSE-open: void* retype build-fails on int-
   arithmetic use sites).

4. **`if (v > K) v = K; return v;` instead of `if (v <= K) return v; return K;`**.
   The former produces target's `blelr` clamp pattern; the inverse form emits
   `bgt + mr + blr`, adding an instruction. See `77438a6f`.

5. **Swap local declaration order to control stack offsets.** When you take
   addresses of multiple `int` locals and pass them to a single function
   (e.g. `ObjList_GetObjects(&objectIndex, &objectCount)`), MWCC assigns stack
   offsets in declaration order. If target has `&first` at sp+8 and `&second`
   at sp+0xc but yours is the opposite, swap the declarations. See `91f5f4ab`.
   **DECL position vs INIT position are INDEPENDENT levers -- a local's
   register HOME follows its DECLARATION position (#16 coloring) while its
   init INSTRUCTION is emitted at the INIT statement's position.** When the
   coloring is right but a `li`/`srawi`/`mr` init sits at the wrong slot in
   the stream (or vice versa), split `int half = size >> 1;` into `int half;`
   (at the coloring-correct decl slot) + `half = size >> 1;` (at the
   emission-correct statement slot) and place each independently. Two
   confirmed: fn_8004AAD4 (srawi placement, byte-exact) and fn_8004B218
   (param cast-copy `mr` emission order: n's DECL first for the r31 home,
   q's INIT first for the mr order; byte-exact 65/65).
   **Note — address-taken locals can color in REVERSE declaration order.** In
   some functions MWCC assigns address-taken stack locals offsets in *reverse*
   declaration order (declare the lowest-offset local LAST). If the plain
   declaration-order swap above doesn't land the offsets, flip it. Proven on
   drgenerator/drlasercannon/hightop_hitDetect (placeholder_80211C24).

6. **Lift a repeated constant load to a local before multiple stores** to force
   CSE. `f32 fz = lbl_xxx; *p1 = fz; *p2 = fz; *p3 = fz;` instead of three
   direct stores — MWCC will reload the constant each time without the lift.
   See `75660758` (ecsh_cup_init 67% → 100%).
   **Inverse caveat — lift ONLY when the live range is call-free.** If the
   lifted local's uses straddle a `bl` (call), MWCC must keep it in a
   *callee-saved* FP reg (f31…) across the call, which adds a save/restore and
   grows the stack frame — making the match *worse* than just reloading the
   global inline (where the load stays in volatile `f0`). So lift for a tight
   call-free store-burst; inline the global when any use crosses a call.
   (placeholder_80295318: fn_80295674, repeated `0.0`.)
   **Counterpoint — when TARGET ITSELF keeps the value in a callee-saved FP reg
   across a call, DO hoist (above the call) to reproduce that f31 save.** If
   target loads a float threshold into f31 BEFORE a `bl` so it survives the call
   (frame grows to hold the f31 save/restore — that's target's real shape), hoist
   `f32 thr = *(f32*)(state+off);` ABOVE the call. The inverse caveat says don't
   lift across calls because it adds an f31 save — but when target HAS that save,
   the lift is the MATCH. Read the target frame/save-mask to decide. (zulu19,
   arwsquadron_update 85.8→88.7%.)

7. **`u8` not `char` for byte arrays you load and assign without arithmetic**.
   `char buf[N]; buf[0] = arr[i];` emits a spurious `extsb`; `u8 buf[N];`
   doesn't. See `6863ffe7` and the related dll_36 commits.

8. **Wrap dead-stored stack locals in a `struct` when only the buffer head is
   passed to a callee.** Pattern: function builds `auStack_28[6]; u16 mode;
   f32 a,b,c,d;` on the stack, fills the f32 slots from globals, then passes
   `auStack_28` (just the head) to a virtual call — MWCC sees the per-field
   writes as dead (the call only "sees" a 6-byte buffer) and eliminates every
   `stfs`. Wrapping them as one struct with a `pad[6]` then passing
   `&stk.pad` keeps the stores alive because MWCC treats the whole struct as
   live through the address-taken `pad` member. Took
   `SB_Galleon_hitDetect` from 63% → 93.8% (commit `8b37ec0c`). Combine with
   `#pragma scheduling off` to align the `lfs`/`stfs` order.

9. **Declare `objRenderFn` (and similar dispatchers) with the full 6-arg
   signature** `void (*)(int *obj, int a, int b, int c, int d, f32 e)` via a
   function-pointer cast at the call site **when there's an intermediate call
   between entry and the dispatch**. Without the full signature MWCC sees only
   `r3` as live across the intermediate call and re-spills/reloads `r4..r7,f1`,
   which scrambles register allocation around the dispatch. With the full
   sig, MWCC preserves `r3..r7,f1` across the intermediate call and the
   dispatch lands on target's exact instruction sequence. Simple render fns
   *without* intermediates don't need this — args pass through naturally.
   Picked up several 100% matches in TREX_trex and DIMcannon batches.
   **Corollary — a callee may take MORE params than its BODY uses; declare the
   trailing DEAD params so the caller sets up the registers.** If the call site
   loads `r3..rN` but the callee's body only reads `r3..rM` (M<N), the caller
   won't match unless the callee signature has all N params (the extra ones are
   dead in the body but the caller still materializes them). Read the call's
   r-register span off the target asm and declare the trailing `int`/`f32` params
   even though unused. (hotel6 — heapSpawnSlot/changeHeapSlot actually take 7
   params, the 7th `tag` dead in-body; adding it fixed mmAllocFromRegion's caller
   setup with no regression to the callees.)

10. **`(u32)` cast on a u8/u16 before int→f32 conversion** forces the unsigned
    path. The signed int→f32 path emits `xoris + lfd + fsubs` against a
    compiler-internal `@xxx` magic constant; the unsigned path uses the
    project's named `lbl_xxx` f64 magic (matching target). When converting an
    unsigned byte/halfword to float, write `(f32)(u32)obj->u8field` rather
    than `(f32)obj->u8field`. Picked up MoonSeedBush_init in DIMlavaball.
    **THE @magic-vs-named-lbl cap is usually fixable — this is the #1 residual
    on the autos units, don't just leave it.** When an int→f32 conversion emits
    an anonymous compiler `@NNNN` magic where target references a named
    `lbl_803Exxxx` f64 magic, add an EXPLICIT cast matching the conversion's
    signedness and try both: `(f32)(int)x` (signed/`xoris` path) vs
    `(f32)(u32)x` (unsigned path). The explicit cast frequently flips MWCC from
    its anonymous local magic to the project's named magic. A bare
    `(f32)someIntReturningCall()` (e.g. `randomGetRange`) tends to emit the
    anonymous form — wrapping it `(f32)(int)randomGetRange(...)` forces the named
    path. `#pragma peephole off` can independently flip this choice too. Proven:
    drakorhoverpad render 95→100% and initMain 98.5→100% (placeholder_80211C24).
    **Caveat — on some units this is float-pool-ORDERING-bound, not cast-bound.**
    On large multi-handler units (placeholder_80295318, 80220608) the named f64
    magic is emitted only for the EARLIEST functions in the TU's float pool;
    later functions cap at the anonymous `@NNN` regardless of the cast (confirmed
    by two hunters — the `(f32)(int)` variant tested and reverted, sometimes
    *worse*). If the explicit cast doesn't flip it on a late-pool function, the
    deficit (~85-96%) is float-pool ORDERING — an open problem awaiting a
    pool-reordering lever; bank the partial and revisit when one lands.
    **The `@NNN`-vs-named-`lbl` LABEL is largely a MEASUREMENT ARTIFACT — NOT
    fixable via symbols.txt.** ⚠️ **CONFIRMED & CLOSED by recipe #70** (task
    #145): the @NNN reloc itself is score-neutral (proven by 100.0% fns
    carrying @NNN refs); any deficit is real codegen divergence elsewhere.
    ⚠️ **PARTIALLY SUPERSEDED — see recipe #60**:
    a later byte-diff audit of 14 partials at 99.9-99.99% found ZERO of them
    were actually pool-name-only cosmetic; all had real codegen byte differences
    after reloc-masking. The measurement-artifact case below still applies
    when the bytes ARE identical — but at <100% scores, always run
    `tools/cosmetic_audit.py` first to confirm before assuming cosmetic. The
    rest of the paragraph documents the cases where the bytes truly do match
    (e.g. shared pool symbols at the same address). objdiff content-matches the literal-pool entry by
    the actual DATA BYTES at the resolved address; both your `.o` and target hold
    the same bias `0x4330000000000000`, so objdiff already scores it MATCHED even
    though `function_objdump.py --diff` always prints the raw local name `@NNN`.
    Measured proof: retyping `lbl_803E7158` (the int→double bias, mistyped in
    symbols.txt as a 3-byte `string`) to an 8-byte `double` produced ZERO
    project-wide delta (fuzzy 46.066067 → 46.066067 to the digit; build green).
    So the `@NNN` print is cosmetic when the bytes match — retyping symbols or
    chasing the label is the wrong axis. The real open problem is the
    float-pool-ORDERING cases above (the entry lands at a *different address*
    than the shared pool symbol, so the bytes can't content-match) — these are
    not symbols.txt-fixable and want a pool-ordering technique that hasn't
    landed yet. (zulu14, task #9: the symbols.txt-retype experiment is a
    settled negative — that specific approach is exhausted, so spend new effort
    on the pool-ordering axis instead of re-running it.)
    **#10 ADDENDUM — the `CONCAT44(0x43300000, ...)` / `__cvt_ull_dbl` de-Ghidra
    tell is a MAJOR field (94 source files).** A CUR-only `__cvt_ull_dbl` in
    `callset_audit.py` (or a `CONCAT44(0x43300000,` in the source) is a raw
    Ghidra-imported int->double conversion the decompiler wrote as the explicit
    magic-bias idiom: `(float)((double)CONCAT44(0x43300000, (int)x ^ 0x80000000)
    - DOUBLE_bias)`. The `CONCAT44` builds a u64, so `(double)(u64)` routes
    through the `__cvt_ull_dbl` runtime helper where TARGET does a plain inline
    int->float. FIX: rewrite the whole blob as a direct cast — `(float)(int)x`
    (signed; the `^ 0x80000000` marks signed) or `(float)(u32)x` if no XOR
    (unsigned). MWCC then lowers it to the standard xoris/stw/lfd/fsubs/frsp
    conversion with NO helper call, and it CASCADES: the dead `local_NN =
    0x43300000;` / `uStack_NN = x ^ 0x80000000;` bias-build locals drop, the
    frame shrinks, and downstream coloring often realigns. Took kaldaChomFn_8016821c
    81.9->100 and firstPersonExit 83.1->91.75 (campfire/camTalk). Companion
    de-Ghidra fixes that ride along in the same import-damaged fns: `char`->`u8`
    on an `Obj_IsLoadingLocked()`-style byte compare (clrlwi vs extsb), retype
    `*(undefined4 *)` position-field copies to `*(f32 *)` (lfs/stfs vs lwz/stw),
    `0x8000` not `-0x8000` for a `(short)(K - angle)` constant (matches target's
    `lis;addi` materialization), and `int` not `short` for a value assigned from
    an `s16`-returning callee that's used raw (drops a redundant extsh). DETECTOR:
    `grep -rln "CONCAT44(0x43300000" src/` (94 files) — but only the ones in
    PARTIAL fns that produce the helper are guaranteed wins; a CONCAT44 that
    already compiles to target's exact stw/lfd/fsubs is cosmetic, leave it.
    SIBLING (uncharacterized): `__cvt_fp2unsigned` is the float->UNSIGNED
    direction (`(u32)(floatExpr)`); target often uses signed `(s32)`/fctiwz —
    A/B `(s32)` vs `(u32)` per site, but beware it can be entangled with a
    #108 rotation (partfx_update: __cvt_fp2unsigned x9 in a parked rotation fn).

11. **`extern int fn(...)` for callees whose return is treated as `int`** —
    even if conceptually the return is a byte. Declaring `extern u8 fn(...)`
    triggers a spurious `clrlwi r3, r3, 24` after every call to zero-extend
    the result, which target omits. Check the asm — if there's no `clrlwi`
    after the call, the project treats the return as `int`. Picked up
    `MMP_levelcontrol_init` in DIMlavaball via `extern int getSaveGameLoadStatus`.
    **VTABLE-MEMBER width is the same bug at INTERFACE scale, and one header
    retype is the wave's single biggest find — but A/B PER-FN, then block-cast
    the lone regressor.** A shared interface vtable slot declared `u8
    (*fn)(...)` makes EVERY caller that tests the result emit the spurious
    `clrlwi r0,r3,24` after the `bctrl`; target uses plain `cmpwi r3,0`.
    Retyping the slot to `int` return drops it across all callers at once:
    `MapEventInterface.isTimedEventActive` u8->int gave +4108 matched_code, 18
    fns improved, 6 to 100% in one line (e3b6dff99). METHOD (gold standard for
    any shared-header return-width flip): (1) snapshot per-fn fuzzy, retype,
    full report rebuild, diff per-fn; (2) keep ONLY if net-positive with no
    real regressions; (3) the one collateral regressor here (hagabon_update, an
    already-capped #108 coloring fn whose int-width result web perturbed its
    coloring net-negative) was ISOLATED with a block-scope fn-ptr cast back to
    the old width — `((u8 (*)(int))(*iface)->fn)(args)` — recipe #57/#35, ->
    zero regressions. CRITICAL NEGATIVE: most u8 vtable returns are CORRECT
    (target keeps the clrlwi) — A/B'd rom_curve walker fns (u8->int net -1936,
    29 regressions) and MapEvent getAnimEvent/getPlayerNo (net -5144); only the
    one typo flipped positive. NEVER bulk-retype u8 vtable slots; A/B each. The
    clrlwi-after-bctrl on a tested result is the per-fn TELL that points back to
    the slot.

12. **Model a single-bit flag as a C bitfield to get `rlwimi` from CLEAN C.**
    (The older asm `rlwimi` workaround has been revoked under the no-asm
    Prime Directive; bitfields are now the only path to this instruction.)
    When target sets a flag with `li r3,1; rlwimi rX,r3,sh,mb,me` but your
    `field |= 0x20` emits `ori`/`andi`, declare the flag as a bitfield member
    (`u8 x:1;` or `unsigned int x:1;`) at the bit position the `rlwimi` operands
    imply, and assign `s->x = 1;`. MWCC then emits `li; rlwimi` matching target —
    no asm. Read the bit position off the target `rlwimi rX,rS,sh,mb,me`
    (`mb==me` ⇒ a single bit). Confirmed by three hunters. See `a3a86c446`
    (gunpowderbarrel set/clear → 100%), `34ee540c0` (cfprisonguard_init → 100%).

13. **Reorder C `case` labels to match target block-address order.** For a
    `switch` MWCC lowers to a compare-chain (not a jump table), it emits the
    case *bodies* in **source order**. If the dispatch matches but the case
    blocks are laid out differently, reorder the `case` labels in the source to
    the target's block order (read the block addresses off the `.s`). Clean C,
    no asm. See `61dd19936` (DIMcannon `fn_801AF6DC` → 100%).
    **Jump-table switches also match — read the table and order cases by block
    address.** When MWCC lowers the switch to a *jump table* (dense cases), read
    the table (`jumptable_xxx`) from the unit's data `.s`
    (`build/GSAE01/asm/..._data.s`) to recover each case→block-offset mapping,
    then write the `case` labels in **target block-address order** and let cases
    that fall to default just omit — MWCC regenerates the same table. Residual is
    usually only the anonymous `@jumptable` vs the named symbol (a ~2-instr reloc
    diff), leave that. Took drakorhoverpad_handlePathPointEvent (22-case) to 86%.

    **Case-set COMPLETENESS shifts the binary-search pivot.** For a
    compare-chain switch lowered to a binary tree, the PIVOT value is the
    median of the case SET — a case the import dropped (because its body
    equals default, e.g. an explicit `case 0: break;`) changes the pivot.
    When target's first cmpwi tests a different value than yours, count
    target's compare values to recover the full original case set and add
    the missing `case K: break;` (drakormissile_update: adding
    `case DRAKORMISSILE_STATE_IDLE: break;` moved the pivot 3→2 and
    aligned the whole tree; 96.08→99.18). CAVEAT: MWCC eliminates an
    empty case whose position lets it merge with default at the EDGE of
    the value range (worldobj_render's 0x61e re-canonicalized both
    directions) — works only when the case value sits INSIDE the range.
    CONTIGUOUS-RUN EXTENSION (fn_801DFA28): a `bge`-over-`b` at a switch
    range check = contiguous case RUNS (`case K: case K+1:` sharing a body,
    + default) — the range-check lowering emits the island naturally.
    TREE-BUILDER FACTS (dll_179, 160-variant brute-force sweep): empty-case
    blocks fully unify (block splits inert); SINGLE value holes absorb into
    runs (`cmpwi K-1; beq/bge`); 2+ value gaps keep exact bounds; run
    leaves emit `cmpwi hi+1; bge` + a dead `cmpwi lo; b`. A tree shape no
    case-set reproduces can mean the import FABRICATED or DROPPED case
    values — brute-force the case-set space before banking (dll_179's
    "vestigial run [0x87-0x8D]" never existed in v1.0; true set recovered,
    CFCrate_SeqFn → 100).
    ⚠️ OVERTURNED SAME-DAY (CFBaby maverick): the dead-`cmpwi K+1`-no-beq
    island is PEEPHOLE-STATE-BOUND — switch lowering EMITS it for empty
    cases whose block == default, and the PEEPHOLE pass is what deletes
    the dead compare and retargets the bge (verified bidirectionally).
    Fix: the empty-case pair (`case 3: break; case 4: break;` → cmpwi
    last+1) + a local `#pragma peephole off/reset` wrap (InfoPoint_SeqFn
    → 100). RETRY every banked "empty-case island unreachable" partial
    under peephole OFF. (The same-day "always edge-eliminated" verdict was
    an artifact of probing under peephole ON — a model case for
    re-attacking fresh banks.)

14. **`int` parameter (not `u32`) for `(arg & bit)` flag tests → `cmpwi`.** A
    `u32` param makes a masked-flag compare emit `cmplwi`; an `int` param emits
    `cmpwi`. Use `int` when the caller passes a signed/int flag word. Mirror of
    #3 (which is for the pointer case). See `1ebdcf015` (loadModelsBin → 100%).

15. **`*(s8 *)(p + off)` instead of `(s8)p[off]` to land the byte in the
    target/arg register.** The cast-pointer-deref form loads straight into the
    destination/arg register; `(s8)p[off]` routes through a scratch first,
    leaving an extra `mr` or wrong-reg residual. See `b42e26e71`
    (cfpowerbase_update → 100%).

16. **Clean-C local declaration order controls volatile-register coloring.**
    Beyond the stack-offset trick (#5): when a partial's only residual is a
    register-number permutation (logic identical — e.g. target uses r6/r4 where
    you emit r4/r6), reorder the *local declarations*. MWCC colors volatiles
    roughly in declaration order, so declaring the loop pointer last, or
    swapping two `int` locals, often flips the allocation to match. Try this
    first when chasing a saved-reg-coloring residual. See `fa209c270`
    (fn_8019C3A0 → 100%).
    **Some SAVED-reg coloring resists decl-order in both directions — this is an
    OPEN coloring problem, not a dead end (recipes #107/#108/#115 later cracked
    several of these).** On some units there's a *systematic* saved-reg
    permutation: target assigns the LOWER reg# (r27/r29) to the longer-lived /
    earlier variable (the obj/setup base), MWCC does the reverse, and it cascades
    through every instruction referencing that var. Declaration-order reorder
    (both directions) didn't flip it on the fns observed. Pending a fresh lever
    this can sit at ~74-90% on such units — but the partial banks real fuzzy%,
    so commit it, record the permutation, and re-attack with the class-pooled
    allocator model (#108), un-/re-naming (#107), and callee-decl widths (#115)
    as your next moves.
    **Before banking a coloring residual, try making the base a REAL PARAM
    instead of `void*` + a local copy.** If the function is `f(void *p){ Obj *o =
    (Obj*)p; ... }` and the saved-reg coloring is off, change the signature to the
    concrete pointer type `f(u8 *o)` (or `Obj *o`) — taking the base as a typed
    PARAM (no local copy) often flips MWCC's r29/r30/r31 assignment to match
    target. (hotel7, Obj_BuildWorldTransformMatrix → 100%.) This is a real fix,
    not a cap — try it first.
    **Local TYPE controls frame size: `f32 m[16]` (64B) vs `Mtx m` (48B).** When
    target reserves a full 64-byte 4x4 stack slot but your `Mtx`/`MtxP` local only
    reserves 48B (shifting the frame + every sp-offset), declare the matrix local
    as `f32 m[16]` to match the 64B reservation. (hotel7, the
    Obj_TransformLocal*ByWorldMatrix pair 99.6→100%.)
    **Base-pointer hoist for saved-register coloring.** When target keeps a
    repeatedly-used base address in a *saved* register (r29-r31) across the whole
    function — e.g. it references one global table at many offsets — declare that
    base as the FIRST local (`char *base = (char *)lbl_xxxx;`) and use `base + off`
    everywhere, instead of re-deriving the address per access. MWCC then parks it
    in a callee-saved reg matching target's coloring. Took fn_8029FA24 90.7% →
    96.8% in one move (placeholder_80295318).
    **Single-base struct-overlay for a CLUSTER of globals.**
    DETECTION TELL: target computing a "different" global's address with
    NO-RELOC arithmetic off an already-resolved base — e.g.
    `addis r3,r30,1; addi r29,r3,-30692` with no R_PPC lines — means that
    address is base_symbol + constant in the source (renderObjects:
    gVisibleObjectSortKeys = lbl_8037E0C0 + 0x8818; one hoisted qbase +
    derived keys pointer fixed savegpr and the lis/addi count). When target addresses
    several "separate" globals off ONE base reg at fixed offsets (e.g.
    `gMmDeferredFreeStack` = base+0x80, `gMmRegionTable` = base+0x3F00, all off
    r31=`gMmStoreArray`), declare ONE struct that overlays the whole block and cast
    the base global to it (`MmGlobal *g = (MmGlobal *)gMmStoreArray;`), then use
    `g->field`. Every access then folds to `r31+const` off the single base,
    matching target — instead of each global emitting its own `lis;addi`. The
    cluster-of-globals generalization of the base-pointer hoist. (hotel5, mm
    block on placeholder_8001746C — required for mmFreeTick/mmAllocFromRegion.)

17. **Fold multiple early-return guards into ONE big `||` (with embedded
    assignments) for convergent-predicate functions.** When target computes a
    multi-condition predicate — several globals/fields checked, sometimes with
    an assignment threaded in — and your early-return chain (`if(a) return;
    if(b) return; ...`) sits at a partial, merge the guards into a single
    `if (a || (x = f()) == 0 || b) return ...;`. MWCC's branch fusion for the
    merged form matches target's convergent compare/branch layout, where
    separate early-returns each emit their own branch island. Took two
    EmissionController predicates 82% → 95%. Clean C, no asm. (Pairs with #14
    `int`-param `cmpwi` and #3 `*(void**)` `cmplwi` for the individual compares.)

    **Inverse-direction note: an embedded assignment in the merged guard
    also DEFEATS the adjacent-value RANGE-FOLD** — and a target
    `bne next; b end` (INVERTED-polarity branch-over-branch) on an `== K`
    guard = a merged `||` guard whose LAST term falls through into the
    then-block (`if (a == 0 || (v = load) == K) return;` — earlier terms
    branch-thread, the last doesn't; cfccrate_render → 100, CF sweep).
    `c == 72 || c == 71`
    folds to `(c-71) <= 1`; writing the first term as
    `(c = *(u8 *)(p+off)) == 72 || c == 71` keeps the separate beq tests
    AND places the lbz at target's position (fn_802A98FC 95.13→100).

18. **Model base+displacement indexed loads as a STRUCT member-array, not
    `*(T*)(base + idx*N + disp)`.** When target indexes a table with
    `add base,idx; lha disp(base)` (the index added to the base *before* the
    displaced load), the pointer-arithmetic form `*(T*)(base+idx*N+disp)` emits
    the indexed-load form (`lhax`/`lfsx`) and won't match. Declare a struct whose
    layout mirrors the table element (e.g. `typedef struct { ...; s16 f; } Elem;`)
    and index `tbl[idx].f` — MWCC then emits `add; lha disp`. Single-level
    indexing matches 100% (fn_8029D250); double-level (`element*stride + idx*4`)
    only partials — leave those partial. Clean C, no asm.
    **End-pointer form for the LAST element: `T *top = &arr[n]; top[-1].f`
    gives `add base; lwz -disp(base)` where `arr[n-1].f` emits indexed `lwzx`.**
    When target walks to the end of a table and accesses the final entry with a
    negative displacement off a computed end-pointer, write the end-pointer +
    `top[-1]` form rather than the `arr[n-1]` index. Took mmFreeDeferred
    94.8→99.45% (hotel4, 8001746C). Clean C, no asm.

19. **objdiff cascade-misalign trap: a low fuzzy% with a high instruction-diff%
    means ONE dropped instruction early in the body, not a wrong function.**
    When a newly-added function scores ~11% fuzzy but its instruction diff reads
    ~94% similar, MWCC dropped/const-folded a single instruction near the top
    (commonly a literal `int x = 1;` that target keeps live in a saved reg),
    which shifts every later instruction by one and makes objdiff only score the
    prologue. Don't rewrite the body — make that one value non-foldable so the
    instruction count realigns: assign it from an adjacent call's return (e.g.
    `x = Camera_GetCurrentViewSlot();`) instead of a literal. Took fn_802AA2B0
    11.6% → 97.3%. Clean C, no asm.

**(s16)timeDelta DIRECT subtrahend — cracks the 'converted-float subtrahend'
cap (the #53/#20 documented residual).** `field -= (int)timeDelta;` on an s16
field emits fctiwz + subf + EXTSH + sth; `field -= (s16)timeDelta;` truncates
the float straight to s16 (same fctiwz, no (int) node) and the compound folds
the extension — exactly target's shape. tesla -> 100, fxemit_update +0.5,
light x3, anim x3 in one sweep; A/B per site. ⚠️ CORRECTED (near-100 sweep):
the old "shrine1CE's site reverted - its target keeps the extension" was a
WRONG attribution — the extension only looked kept because the fn carried a
`#pragma peephole on` wrap; under the correct OFF state the `(s16)`
subtrahend IS the fix (shrine1CE → 100 by dropping the wrap + this cast).

20. **Compound-assign a narrow lvalue (`*(s16*)p += K`) instead of the expanded
    read-modify-write (`*(s16*)p = *(s16*)p + K`).** The expanded form reloads
    the value and re-sign-extends it, emitting a redundant `extsh` (or `extsb`
    for `s8`); the compound form folds load+add+store and drops the extra
    extension. Took fn_802B7B0C 96.5% → 100%. Clean C, no asm. (Same family as
    the caller-side extsb/extsh table below.)
    **u8 LOOP-COUNTER edition: `i++` vs `i = i + 1` on a `u8 i` counter pick
    the MASK position.** `i = i + 1` masks at the def (`addi r0,rX,1; clrlwi
    rX,r0,24`); `i++` keeps the home raw and defers the mask to the use
    (`addi rX,rX,1` ... `clrlwi rN,rX,24` at the compare) — target's usual
    shape for `for (u8 i = 0; i < framesThisStep; i++)` spawn loops. Two
    SB-lane confirmations (SB_ShipHead_render, SB_Galleon_hitDetect →
    byte-exact).

21. **Invert `if(c){A}else{B}` → `if(!c){B}else{A}` to flip MWCC's then/else
    block layout.** When the dispatch matches but the then- and else-blocks are
    laid out in the *opposite* order from target (e.g. target emits `beq else;
    <A>; b end; else: <B>`, you emit `bne A; <B>; b end; A: <A>`), invert the
    condition and swap the branches in C. MWCC always lays the *then*-block
    first, so flipping the C source flips the asm. Plain peer to #13 (case-order
    for compare-chain switches) but for if/else. Took fn_802BA1D4 91% → 100%.
    Clean C, no asm.
    **Dispatch FORM: `if/else-if` chain vs `switch` controls linear-bne vs
    binary-search.** When target dispatches an integer/enum with a LINEAR `bne`
    chain (cmp; bne; cmp; bne; …), write an `if (x==0){} else if (x==1){} …`
    chain — a `switch` makes MWCC emit a BINARY-SEARCH tree (or jump table)
    instead and won't match. (Inverse of #13, which is for when target DOES use a
    jump table/compare-chain switch.) Pair with the base-pointer hoist (#16). Took
    vortex_init 86→97.8% (zulu20, 80220608). Read the target's branch shape and
    pick the C form that produces it.
    **CLONED-CALL-PER-ARM addendum: when target shows `li rA,K1; <full call
    setup + bctrl>; b end; li rA,K2; <full call setup + bctrl>` — the SAME
    call duplicated in both arms with only one constant arg differing — the
    C is the literal if/else with the call WRITTEN IN BOTH ARMS.** The
    shared-call spellings (`f(x, cond ? 1 : 0)` ternary arg, or an int-temp
    `v = cond ? 1 : 0; f(x, v);`) emit a per-arm li JOIN feeding ONE call
    instead — different shape, ~5 instrs off per site. Read target's bctrl
    count inside the diamond to pick. (OptionsScreen_run 73.5→99.4 leg,
    commit fea39e9e3.)

22. **Wrap the whole body in `if (cond) { ... } return 0;` instead of
    `if (!cond) return 0; <body>`.** An early mid-function `return` of a constant
    emits an extra `li r3,0; b <epilogue>` island that target doesn't have when
    it instead falls through a single guarded block to one common return. When
    the function is "guard, then do everything, then `return 0`", express it as
    the positive `if (cond) { <body> }` wrapping the work and a single trailing
    `return 0;`. Took fn_802B74C4 73% → 100% (combined with a local decl-order
    swap). Clean C, no asm.

23. **`!!x` for MWCC's double-`cntlzw` `x != 0` materialization; plain `!= 0`
    gives `neg; or; srwi`.** When target materializes a boolean "is non-zero"
    with the `cntlzw rX,rY; ...; cntlzw`/`srwi rX,rX,5` (count-leading-zeros)
    idiom and your `x != 0` (or `(int)(x != 0)`) emits the `neg; orc/or; srwi`
    form instead, write `!!x` (double logical-NOT) to get the `cntlzw` form.
    Mirror: `!x` gives the `== 0` `cntlzw` form. Match whichever the target
    uses. Clean C, no asm — supersedes leaving these as a "cntlzw-idiom cap."
    **Related — `break` (fall to common return) instead of `case`-body
    `return 0` drops a spurious `cntlzw` boolean.** When a switch case ends with
    an explicit `return 0;` and target instead uses an `li`-branch to a shared
    epilogue, write `break;` and let the function fall to one trailing return.
    MWCC then emits the explicit `li r3,0; b` form rather than synthesizing the
    `cntlzw` non-zero idiom. (zulu13, 80220608 *_free family.)

**#23 addendum — the `li rD,1; cntlzw r0,x; rlwnm rD,rD,r0,31,31` idiom is
MWCC's materialization of `x <= 0` (signed).** Mechanism: cntlzw(x) is 32 for
x==0 and 0 for x<0; rotating 1 by either lands bit31 set, any other count
clears it. When a tiny predicate fn shows this tail and the import wrote
`== 0`, the original was `<= 0` — a real behavioral difference, not a codegen
cap (fn_801B6D40 76.4->100, DIM2snowball; paired with peephole-off to keep the
(s8)-cast extsb before the stb).

24. **Declare single-precision math/helper callees as `f32 fn(f32)`, NOT
    `double fn(double)`.** A `double` signature makes MWCC promote args and
    round results through `fmul`+`frsp` (double-precision multiply then
    round-to-single) where target uses a single `fmuls`. Declaring the extern
    with `f32` params/return matches target's single-precision form. Applies to
    trig/interp helpers (e.g. `extern f32 fn_80293E80(f32);` for sin/cos).
    Pairs with #10 ((u32) for int→f32). Took drcreator_update to 99.7%. Clean C,
    no asm. (Related: declare a varargs callee `extern void fn(char *, ...);` to
    reproduce target's `crclr 4*cr1+eq` varargs marker; widen a callee's return
    `void`→`int` when target keeps its result live even if your caller ignores
    it.)
    **`#pragma fp_contract off` IS available per-function** (used in several real
    DLLs) — wrap a function in it when target does a SEPARATE `fmul`+`fadd` where
    MWCC fuses to `fmadds`. (Corrects an earlier "no fp_contract control"
    assumption that flagged some matrix/vector fns as untouchable.) CAVEAT:
    it only controls the fmadds FUSION — it does NOT fix eval-order /
    FP-register-allocation divergences. A function whose divergence is
    FP-reg/eval-order, not fusion, will still cap with fp_contract off, so
    try it on a true fmadds-vs-fmul+fadd mismatch but don't expect it to fix
    coloring.

25. **An FP comparison feeding a BRANCH is NOT a cap — write the plain
    operator.** `if (a >= b)` / `while (a < b)` / `a <= b ? x : y` on floats
    reproduces target's `fcmpo` + `cror` (the `cror eq,gt,eq`→`>=`,
    `eq,lt,eq`→`<=` combine) directly from the `>=`/`<=`/`<`/`>` operator — do
    NOT leave these partial. The harder case is when target *materializes* the
    boolean into a GPR (`int x = a >= b;` / `return a >= b;`), which clean C
    emits via `mfcr`/`rlwinm` and matches less often. So keep float compares
    inside `if`/`while`/`?:` conditions; the stored/returned-boolean form is the
    one that needs the materialization recipes below. (Corrects the over-broad
    "FP-compare → mfcr/cror" verdict that earlier handoffs propagated.)
    **Counter-caveat — the reverse divergence.** On some
    targets a clamp uses a SIMPLE `bge`/`ble` (single branch) where clean-C
    `v>=lo`/`v<=hi` *over-produces* the `cror eq,gt,eq; bne` combine. So
    #25 cuts both ways: when target has the cror combine, write the operator;
    when target has a plain `bge`/`ble` and your `>=`/`<=` emits the cror, the
    cleanest path is **recipe #91** (do NOT just expand the if-chain — a
    logically-correct if-rewrite was confirmed to score *lower*). ⚠️ **CRACKED
    by recipe #91** — the strict-compare nested ternary
    (`*p = (v < lo) ? lo : ((v > hi) ? hi : v);`) reproduces the cror-free
    `bge`/`ble` clamp; reach for #91 on these.
    **A MATERIALIZED float-bool (stored to a GPR) is reproducible — two
    confirmed recipes, pick by the FORM target uses:** (a) **mfcr/srwi form** —
    target does `fcmpo … ; mfcr; rlwinm/srwi` to land 0/1 in a reg: reproduce with
    a `goto`+ternary `cond ? (fcmpo-expr) : 0` and put the inactive/fall-through
    block FIRST (recipe #21 layout). (zulu18, arwbombcoll 90.9→98.3%.) (b)
    **li-branch form** — target does `li r0,0; fcmpo; bge; fcmpo; ble; li r0,1;
    cmpwi r0,0; beq`: reproduce by ASSIGNING the `&&` to an int temp THEN testing
    it — `int v = (d < A && d > B); if (v){…}`. Writing `if (d<A && d>B)` directly
    short-circuits with NO materialization (loses the `li r0,0/1`); the int-temp
    assignment forces it. (zulu19, arwsquadron_update — all 5 instances,
    83.4→85.8%.) If NEITHER form lands, bank the partial and keep it on the
    materialized-float-bool retry list.

26. **"Floor-first" clamp restructure forces a FRESH callee-saved FP reg (frame
    size + coloring fix).** When a clamp `x = computed; if (x < floor) x = floor;`
    makes MWCC *reuse* an earlier value's FP reg (e.g. f31) — shrinking the frame
    and cascading every stack offset off-by — rewrite it to load the floor FIRST:
    `x = floor; tmp = computed; if (x < tmp) x = tmp;`. Loading the constant floor
    before the computed value forces MWCC to allocate a fresh FP reg (f29), fixing
    the frame size and the coloring. Took fn_802B1E5C 78.4→80.6%. Clean C, no asm.
    (november10. Mirror of the GPR decl-order tricks #5/#16, for FP.)

27. **Lead an accumulation subterm with the UNARY-NEGATED operand to get
    `fneg`+`fadds` instead of `fsubs`.** When target computes `a = k*v1 - v0` as
    `fneg`+`fadds` (because it *reuses* the `k*v1` product elsewhere and can't
    consume it in an `fsubs`), writing `k*v1 - values[0]` emits `fsubs` and won't
    match. Write `-values[0] + k*v1` (lead with the negated term) → MWCC emits
    `fneg` on `values[0]` then `fadds`, preserving the reusable product. Fixed the
    whole cubic-spline family (curveFn_80010ce4 76→90.4%, mathFn_80010c64
    86.6→93.9%, mathFn_80010ee0 90.7→94.9%). Clean C, no asm. (mike6, 800066E0.)

28. **A `li r0,<bit>; li rX,1; slw r0,rX,r0; and` (RUNTIME shift) over apparently
    CONSTANT bit positions 0,1,2… = an UNROLLED `for` loop — write the loop, not
    the manual unroll.** When target tests `flags & (1<<bit)` for a run of fixed
    bit positions via a runtime `slw` (not a folded `andi`/`clrlwi`), the original
    source was a small `for(bit=0;bit<N;bit++)` that MWCC unrolled: the unroller
    keeps `1<<bit` as `slw` (doesn't re-fold per copy) WHILE folding the
    induction-derived offset (`bit*STRIDE`) to per-iteration constants. Writing the
    manual unroll in C instead folds `1<<0`→`clrlwi`/`andi` and mismatches. So
    write `for(bit=0;bit<N;bit++){ if(flags&(1<<bit)){ p[bit*STRIDE+off]=…; } }`.
    Took 3 sky-setter fns 75→100%. (november12, 80080E58.)
    **GUARD — only when the per-iteration body is ~≤4 simple instructions.** MWCC
    only re-unrolls trip-small loops with TINY bodies. If target shows the
    unrolled `slw` form but the body is larger (nested-if + bitfield/FP work),
    MWCC keeps a REAL loop from your for-loop (won't unroll) AND manual-unroll
    folds `1<<const`→`clrlwi` (losing the slw machinery, ~18 instr short) — so
    such fns sit at ~66-70% on this lever; commit the for-loop partial and keep
    it open (the count-down crack below and the unroll pragmas #98/#113 are the
    next moves to try).
    **Unroll-FACTOR mismatch is a separate OPEN problem.** Even with
    the right loop form, MWCC sometimes picks a DIFFERENT unroll factor than target
    for a fixed-trip loop (target unrolls a 16-trip init to ctr=4 / x4, a 12-trip
    to x3; MWCC unrolls your identical-body source MORE — x8 / x4). Field-reorder
    and constant-lift didn't flip it on the fns tried. When the only residual is
    "target unrolls x4, mine x8" on an init/clear loop, try the count-down form
    below and the `opt_unroll_*` / `ppc_unroll_*` pragmas (#98/#113); if those
    don't bite yet, bank the partial as an open unroll-factor case.
    **PARTIAL CRACK — the COUNT-DOWN loop form `for (i = N; i != 0; i--)` flips
    both the unroll FACTOR and the unroll STYLE.** When target shows the x4
    walker-bump unroll (store constants hoisted above mtctr, `addi ptr,ptr,stride`
    after EACH body copy) and your count-up `for (i = 0; i < N; i++) { ...; p++; }`
    over-unrolls x8 with FOLDED displacements (one `addi ptr,+8*stride` at block
    end), rewrite the header as `for (i = N; i != 0; i--)` (body unchanged, i
    unused) — MWCC then emits ctr=N/4, x4 copies, per-copy bumps, byte-exact
    (audio musicInitMidiWad 16-trip channel-init -> 100%-matched loop, fn
    69.0->93.7). The same form fixes RUNTIME-count clear loops: target's
    `srwi ctr,count,3` + `andi. rem,count,7` two-phase unroll comes from the
    count-down form, while count-up emits the newer compare-8-first shape
    (streamsLoadedCallback 78.1->97.1). Try the count-down spelling BEFORE
    banking an unroll-factor partial.
    **LOOK-ALIKE that is NOT an unrolled loop: `li K; slwi K2; stwx` per
    copy over constant indices 0,1,2..N = a MULTI-DEF POST-INCREMENT
    INDEX (`arr[idx++] = 0;` written N times).** Per-def const-prop emits
    a fresh `li K` into the index home while the per-use subscript shift
    stays runtime (reaching-defs are not folded through a multi-def web);
    a real loop -- any spelling, incl. (i << 2), conversion sandwiches,
    SR/loop-invariant pragmas -- FOLDS to displacement stores instead.
    Tells: `arr[idx] = 0; idx = K;` SEPARATE statements fold (single
    reaching def per use); only the embedded `idx++` keeps the li-per-def
    shape; a per-statement #80-laundered base `((int *)(int)sym)[idx++]`
    additionally anchors target's zero-then-base materialization order.
    (objlib ObjHits_InitWorkBuffers 79.61->96.80; probe battery pH/pO.)

29. **Callee parameter POSITION controls caller's L2R arg-emission order.** MWCC
    evaluates call args left-to-right; the *positions* of the float vs. int
    params in the callee signature decide which loads/conversions the caller
    emits first. Read the caller's asm — if target sets up `r3; f1; f2; r4`
    where your output sets `r3; r4; f1; f2`, the callee's float params are at
    arg-slots 2-3, not last. Reorder the extern signature to match the target
    eval order; one signature fix can lift every call site of that callee at
    once. (delta-28 `pauseMenuDrawElement(tex, f32, f32, s16 x, u8, s32, s32)`
    lifted wispBaddie 3 fns; charlie-28 weaponE6
    `objAnimFn_8013a3f0(obj, animId, f32, flags)`; charlie-28 firepipe
    `fn_80098B18(obj, f32 scale, type, ...)`.) **Mirror of #9 + #24** for the
    arg-eval-order direction rather than the live-range or single-precision
    direction.

30. **Alias variable `T *base32 = (T *)base;` flips `lwzx`/`lhzx` →
    `add; lwz/lha disp`.** When you walk a `u8 *` base but want word/halfword
    access at fixed displacements, an inline `*(s32*)(base + i*N + disp)` emits
    the indexed-load form (`lwzx`); declaring a separate typed alias
    `s32 *base32 = (s32*)base;` and indexing `base32[i*N/4 + disp/4]` emits
    `add base; lwz disp` matching target. The aliased base lets MWCC compute
    the array address once and use `disp` for the field offset, instead of
    folding the whole `+i*N+disp` into an indexed-load. Took mazewell
    `gmmazewell_update` 75.9 → 98.8%. (charlie-28 task #122.) Generalization of
    #18 for raw-pointer bases.

31. **Whole-struct assignment for paired `lwz`/`stw` blob copies.** When target
    copies several adjacent fields with paired `lwz`/`stw` (not `lmw`/`stmw`,
    not `memcpy`), expressing the copy as field-by-field stmts (`d->a=s->a;
    d->b=s->b; ...`) emits the right loads but in the wrong order, while
    `*dst = *src` (whole-struct assignment) emits the exact paired
    `lwz/stw` sequence in target's order. Use whole-struct assignment when
    every field is being copied. (charlie-28 cfforcefield —
    `radii[4]+axisTable[12]` inside results struct.)

32. **`fr = conv; fr = lbl + fr;` 3-statement form for `fadds` operand order.**
    When target emits `fadds f1, lbl_load, conv_result` (loaded const second
    operand, conversion first) and your `fr = lbl + (f32)i` emits
    `fadds f1, conv, lbl`, split the expression: `fr = (f32)i; fr = lbl + fr;`
    forces MWCC to materialize the conversion into the same reg first and then
    use it as the *second* `fadds` operand. (charlie-28.) Generalization of #27
    for `fadds`-not-`fsubs` cases.

33. **`if (cond) { ... } else return 0;` mid-function — keep the constant
    return in the ELSE arm, not after the body.** When target lays a
    `cmpwi; bne body; li r3,0; b epilogue` shape, the corresponding C is
    `if (cond) { <body> } else return 0;` — placing the `return 0` after the
    body emits an extra `li r3,0; b` island. Sibling of #22 (positive-wrap)
    for cases that have an explicit non-zero return path. (charlie-28.)

34. **Address-taken FP outparam decl-order: first-declared gets the HIGHEST
    stack offset.** Mirror of #5/#16 for float outparams. When passing
    `&fA, &fB, &fC, &fD` to a callee that fills them, MWCC assigns offsets
    based on declaration order — declare the float that lands at the HIGHEST
    offset FIRST. Took `CameraModeClimb_update` to 99.7% via
    `cc, d0, d4, d8` declaration order (cc gets sp+0x14, d8 gets sp+0x8).
    Also: snd3d `s3dCalcEmitter` outparam order
    `(&distance, &pan, &azimuth, &pitch, &frontBack)` with `pan` at lowest
    slot passed LAST. (CAM/dll_62, snd3d, task #120.)

35. **Typedef'd vtable function-pointer fixes Ghidra's `code**` double-deref
    shape.** Ghidra often imports vtable dispatch as `(*(code**)((*obj)+0x34))(...)`
    which compiles to extra loads. Declare a proper `typedef R (*VtblFn)(...)` and
    use `((VtblFn*)*obj)[0x34/4](obj, ...)` (or a typed struct overlay on the
    vtable). MWCC then emits the clean `lwz r12, off(r4); mtctr; bctrl`
    target uses. (CAM/dll_62.) Bonus: fixes the f64 argument-position
    misidentification (`code**` form often loses the float arg types).

36. **`(int)`/`(uint)` casts at call sites INFLATE the cast param's
    saved-reg priority — drop the casts to flip allocator coloring.** Discovered
    on duster `fn_8015625C`/`fn_8015652C`: dropping redundant `(int)`/`(uint)`
    casts at the call sites of a frequently-passed param flipped MWCC's saved-reg
    assignment from `r31/r30` → `r30/r31` to match target. The casts apparently
    raise the cost-model weight enough to win the higher saved reg. When a
    function's only residual is a 1-bit saved-reg permutation and a param is
    passed many times with casts, try dropping the casts. Pair with decl-order
    #16. (dc221d25d task #121.)
    **BURST RULE — #36 scales to WHOLE-QUAD rotations, but only when ALL the
    no-op casts drop AT ONCE (the #74 burst lesson applied to casts).**
    cfguardian cfguardian_updateMain (nee waterSpellStone1Fn) had been BANKED as a "fn-text-bound #108
    rotation" ("#36 cast drops tried — inert") with all four saved webs
    exactly reversed (T obj=r28/def=r29/player=r30/sub=r31, ours the mirror).
    The real cause: 19 Ghidra-noise `(int)obj` casts on an ALREADY-`int`
    param (textual no-ops, but each is an IR cast node) pinning obj at r31;
    dropping all 19 sank obj to target's r28 in one move, and the remaining
    trio then followed plain decl order (descending from the next-free reg —
    reorder decls to land it). A PARTIAL drop shows nothing, which is how the
    earlier "inert" verdict happened. DIAGNOSTIC that found it: per-use-class
    deletion probes — replace each class of obj uses (`(int)obj` args,
    `(int*)obj` args, derefs, bare args) with a constant in a probe and watch
    the prologue coloring; the class whose deletion sinks the web is the
    inflator (94.50→99.31, commits 6a3047575/42eeee68a). Resolves the #82
    GUARDIAN COUNTER-RESULT open lead — no pairwise census needed.

37. **`(u16)` on the WHOLE OR-expression for single-`clrlwi` combine.** When
    OR-ing several byte/halfword values and storing as halfword, writing
    `*p = (u16)(a | b | c)` emits ONE `clrlwi` at the store; per-operand casts
    (`(u16)a | (u16)b | (u16)c`) emit per-operand `clrlwi`s. The single outer
    cast lets MWCC OR full-width and mask once. (newshadows.)

38. **`(x & N) ? 1 : 0` ternary for branchy bool materialization;
    `(x & N) != 0` emits `neg/or/srwi`.** When target materializes a flag-bit
    test into 0 or 1 with a branch-and-set sequence (`andi.; beq; li 1; b; li 0`)
    rather than the `cntlzw`/`neg` arithmetic idiom, the C is the ternary
    `(x & N) ? 1 : 0`. The bare `(x & N) != 0` (or `!!(x & N)`) takes MWCC's
    arithmetic path. Companion to #23: pick the form by reading target's shape.
    (MMP_moonrock lightning.)

39. **Bitfield struct for byte flags at specific offsets generalizes #12 beyond
    single bits.** When `state[0x25]` holds packed bit flags AND target uses
    `rlwimi`/`rlwinm` to read/write individual bits, declare a struct overlay
    with bitfield members at the right byte offset and write `s->flagX = 1;` —
    MWCC emits the matching `rlwimi`. The bitfield approach scales to multiple
    independent bits at the same byte, where #12 only covered single fields.
    (MMP_moonrock lightning — `LightningFlags` / `LightningMode` structs.)

40. **Embedded-assignment in `if()` condition avoids `stw`+`lwz` reload.** When
    a function calls a helper, stores the result, then immediately tests it,
    the natural C `h = helper(); if (h != 0) { use(h); }` emits
    `bl; stw; lwz; cmpwi`. Writing `if ((h = helper()) != 0) { use(h); }`
    keeps the result live in the return-value reg and skips the spill —
    matching target's `bl; cmpwi; beq` shape. (snd3d s3dHandle.)

41. **`(s32)` cast on `fctiwz` return — `f32 stopped` returned via
    `(s32)` conversion.** When target returns an integer that's the
    truncated form of a computed float (e.g. a return code from a physics
    step), `return (s32)floatExpr;` emits `fctiwz; stfd; lwz; blr` — matching
    target's `fctiwz`+`stfd`+`lwz` epilogue. A bare `int stopped = (int)f;
    return stopped;` adds an extra temp. (IMicicle `exploded_stepDebrisPhysics`.)

42. **Ternary `(cond) ? K1 : K2` into a typed lvalue reproduces per-arm
    `li K1; b; li K2; extsX` join.** When target has two `li`s feeding a
    sign/zero-extending store (or test), writing the ternary directly into the
    typed lvalue `s8 t = cond ? 2 : 1;` emits `li`/`b`/`li`/`extsb` matching
    target. Pulling the ternary out into separate `if/else` blocks fragments
    the join. (MMP_moonrock `fn_80198DE8` `s8 triggerState`.)

43. **Comma-init `for (i=0, p=base; ...; ...)` emits `li 0; mr p,base`
    matching target's two-prologue-instruction init.** When target's loop
    prologue is `li r3,0; mr r4,r5; b ...`, a single-init `for (i=0; ...)` with
    `p = base` as a separate stmt swaps the order. The comma form anchors both
    inits at the loop head. (mazewell `gmmazewell_update`.)

44. **`*(u16*)&lbl` pointer-read for `lhz` when a u16 global is passed as a
    u16 param.** Naïvely passing a `s16 lbl;` global as a `u16` callee param
    emits `lha; clrlwi` (sign-extend then mask). Writing `*(u16*)&lbl` emits
    a single `lhz` matching target. The cast tells MWCC to read the bytes
    unsigned-zero-extended. (delta-28 wispBaddie `pauseMenuDrawElement` call
    sites for `lbl_803DD750`/`752`.)

45. **Loop-invariant single-deref into a local saved-reg for FP constants
    target keeps across calls (mirror of #6 inverse caveat).** When target keeps
    an FP constant in `f29`/`f30`/`f31` ACROSS calls inside a loop (visible as
    a `psq_l f31, off(sp)` save-mask + reload after each `bl`), declare the FP
    constants as locals BEFORE the loop in REVERSE order — first-declared gets
    `f31`, second `f30`, third `f29`. The decl order controls which constant
    lands in which callee-saved reg. (snd3d `s3dHandle` — `zeroDist`,
    `ageStep`, `ageLimit` declared first/second/third.) Counter-caveat to #6's
    "don't lift across calls" — when target itself has the f31 save in its
    frame, the lift IS the match.

46. **Ghidra-import wrong-offset bug class: re-derive struct field offsets from
    target asm, not from the imported skeleton.** A surprisingly common stuck-
    partial cause: the Ghidra C has the right *operations* but the wrong *byte
    offsets* into the state struct, because the v1.1 layout shifted vs v1.0.
    Read the actual offsets off the target's `lwz`/`lhz`/`lbz` displacements.
    Pattern caught: firepipe `FirePipeMapData` `s16 cycleTime` at `0x1A`,
    import had wrong offsets `0x20/0x22` for timer/flags; mazewell control
    flow had non-fallthrough ifs where target's switch falls through. Treat
    "stuck mid-partial 60-95%" as offset-bug suspicion before allocator-cap
    suspicion. Related to the "import logic-bug class" already documented in
    the drift-handling section.

47. **Inverse-direction sda21 recipe: when the SIZED-array form FAILS for a
    `.data` symbol >8B, use scalar extern + `(&sym)[i]` indexing.** The
    existing recipe (give an array-typed `.sdata` extern a KNOWN SIZE to get
    `@sda21`) only works up to ~8B objects — that's the sdata threshold MWCC
    uses. For larger pooled-data arrays, the sized-array form mis-emits FAR
    `lis;addi`. Use the scalar form `extern T sym;` then `(&sym)[i]` to index
    — MWCC then folds to `@sda21`. Took newshadows `renderShadows` `FinishQueue_803DED64`
    to match. Inverse: when target USES the far `lis/addi` for a large
    `.data` array and your scalar extern mis-emits `@sda21`, declare it
    incomplete `extern u8 lbl[];` (no size) to force the far form. (duster.)

48. **"WCTileIface vtbl struct" form is an OPEN dispatch-hoist problem — `lwz
    r12, off(iface); mtctr; bctrl` hoists to statement front on every spelling
    tried.** When target
    evaluates a dispatch's args L2R but the 3-load iface chain
    (`lha r3; addi r4; addi r5; lwz r6 x3; lwz r12, off(r6)`) sits at the
    LAST-ARG position in target while MWCC's output puts it at the *first-arg*
    position — no clean-C form found so far defeats the hoist. Probed
    broadly: GC 1.2.5-2.7, sched on/off, -O2/3/4, lang c/c++,
    struct-member / raw-cast / local / inline-helper / volatile forms — all
    no-flip. ~6 reordered instrs × N call sites is the residual. Commit the
    partial and keep it on the retry list; the same shape recurs on wcpushblock
    and other iface-dispatch fns, so a lever that cracks one cracks the family —
    a high-value target for the next dispatch-ordering technique. (wctile,
    task #120.)

49. **Switch with case-FALLTHROUGH (case 0→1→2 with no re-tests) reproduces
    target's compare-chain dispatch when cases run sequentially.** When target
    dispatches an enum/int with `cmpwi 0; bne L1; <body 0+1+2>; b end;
    L1: cmpwi 1; ...` (one body shared by multiple values via fallthrough),
    write the switch with empty fallthrough cases:
    `case 0: case 1: case 2: { <body>; break; }`. Each-case-its-own-body
    emits per-case re-tests and an extra branch island. Took curvefish_update
    +4.2pts. (alpha-34 task #123.) Related to #13/#21 but for *sequential
    fallthrough*, not block reorder or condition flip.

50. **Nested `vcall(vcall(...))` keeps r3 live across calls — MWCC fetches the
    inner result via r4 instead of clobbering r3.** When target shows
    `bl outer; bl inner` where both calls take a chained result and target
    keeps the first call's return in r3 to feed the second's vtable lookup,
    write the inner call as an embedded argument: `outer(vcall(x), y)`. The
    bare `int r = inner(x); outer(r, y);` spills `r` to stack and reloads via
    `lwz` — mismatch. The embedded form keeps the chain in regs. (alpha-34.)

51. **Chained `x = y = z = K;` assignment CSEs ONE constant load across multiple
    stores.** When target emits `li r3, K; stw r3, off1(p); stw r3, off2(p);
    stw r3, off3(p)` (single materialization, three stores), write a single
    chained assignment instead of three independent stores. The chained form
    forces MWCC to share the materialized constant in one reg; separate
    statements may reload the constant per store. Sibling of #6 (lift for CSE)
    for assign-stores rather than reads. (alpha-34.)

52. **Ternary `(a >= b) ? b : a` clamp gives `mr+clrlwi` store shape vs.
    `if/else`.** When clamping to a max with an unsigned-narrow target store
    (the store is a `stb`/`sth` after the choice), the ternary lands the
    "winner" in the same reg both arms use, emitting `mr; clrlwi; stb`
    matching target. An `if (a >= b) v = b; else v = a;` form fragments the
    join into two basic blocks. Companion to #4 for the case that ends in a
    narrow store, not a return. (alpha-34 curvefish.)

53. **`(s16)` cast on a compound `-=` SUBTRAHEND drops the spurious `extsh`.**
    Similar to #20 (compound `+= K`), but specifically for subtraction: when
    target emits `lha; subf; sth` without the `extsh` re-sign-extend that
    `*p -= v` produces, write `*p -= (s16)v;` (cast the subtrahend, not the
    lvalue or the result). The narrow cast tells MWCC the subtrahend is
    already sign-correct width, skipping the redundant extension. (alpha-34
    duster_update.)

54. **Two locals = SAME base pointer when target holds the pointer in two
    DIFFERENT saved regs.** When target dereferences the same base
    (`*(obj+0x4c)`) via TWO different saved regs (e.g. both r28 and r30 hold
    the same loaded pointer at different points in the function), declare
    TWO locals that both alias the base. The duplicated decl forces MWCC to
    allocate the pointer to two saved regs rather than CSE-ing it to one —
    matching target's reg coloring. Use ONLY when the target visibly holds
    the same value in two saved regs; otherwise this regresses. (alpha-34.)

55. **Mixed-hoist pattern: target HOISTS a global to a saved reg at prologue
    AND RE-DERIVES it fresh inside specific loops.** When a function's
    prologue loads `lis;addi` for a global into a saved reg (r31), but a
    specific inner loop has its own `lis;addi` for the SAME global re-derived
    per-iteration, write a mid-fn re-read of the global: declare a
    block-local pointer inside the loop scope that re-reads the address,
    while a top-of-fn local holds the hoisted version for the rest of the
    body. MWCC then matches both placements. The "always hoist" advice in #6
    and "never hoist" in the existing Don't-hoist section are extremes;
    this is the middle case when target actually splits the strategy.
    (echo-25 dfsh_shrine_update findings.)

56. **Duplicate-def reloc-stealing: a same-TU duplicate def of an external
    function makes `bl callee` resolve to the LOCAL copy, stealing the
    reloc.** When a placeholder/recovered TU carries a duplicate definition
    of a function that's *also* defined in another (already-graduated) TU,
    the linker resolves `bl callee` in the placeholder's `.o` to the LOCAL
    copy — not the canonical extern. The function still runs (same bytes),
    BUT the reloc target name differs from target's binary, which shows up
    as a per-fn fuzzy% gap that no source-form tweak can close. **The fix
    is to DELETE the duplicate def** — once the local copy is gone, MWCC
    has to emit an external reloc, and the link resolves to the canonical
    sibling, matching target. Took `snowPrintSnowCloud` 87.65 → 89.24%
    (newclouds, task #126) by dropping the local `getAmbientColor` def
    that was stealing the reloc to sky.c's canonical copy.
    **GUARD — only drop dups of NON-INLINED externals.** For genuine
    `extern inline` helpers (e.g. `sqrtf__inline`), the dup IS load-bearing
    (it's how inlining works at link time); dropping it loses the inline
    expansion and grows the placeholder's code with a now-unresolved `bl`.
    Test which class the dup is in: if target's call site shows a `bl` to
    the canonical name (external resolve) → drop the dup. If target inlines
    the body at the call site → keep the dup. This **resolves the wave-
    lesson "−48 byte cross-inline tail TU cap"** documented in the
    "Graduating a placeholder" section — that cap was actually duplicate-
    def reloc-stealing, not pool migration, and is FIXABLE for the
    non-inlined case. The CLAUDE.md wave-lessons section should be read
    with this update in mind.

57. **Block-scope `extern` overrides reconcile decl-namespace conflicts when
    merging multi-file TUs.** When graduating a multi-placeholder DLL into one
    merged TU, the source `.c` files often disagree on the type of a shared
    extern (one file declared `extern int GameBit_Get(...)`, the next
    `extern u8 GameBit_Get(...)`, etc.) — and the per-file form is **required**
    for byte-exact codegen at the corresponding call sites. Putting both forms
    in the merged TU's global decl scope is a redeclaration conflict; picking
    one globally regresses the other's call sites (different return-width
    triggers `cmpwi` vs `cmplwi`, `clrlwi` insertions, sign-vs-zero extends —
    see recipe #11 and the caller-side-width table). **Solution: BLOCK-SCOPE
    `extern` declarations inside the specific function bodies that need the
    non-global variant.** MWCC accepts this (legal C89 — local extern
    redeclarations override outer scope for that block only), and the byte
    output is identical to the per-file form. REFINEMENTS (resplit
    pipeline, probe-verified): the redecl tolerance is TYPE-PAIR dependent
    — incompatible POINTER-RETURN fn redecls are accepted under a visible
    file-scope decl; OBJECT decls and void-vs-int returns are REJECTED;
    per-block externs with NO file-scope decl are always legal. And MWCC
    errors even on IDENTICAL typedef/struct-tag redefinitions — merged TUs
    must dedupe them (its `identifier ... redeclared` diagnostic can WRAP
    onto the next line; error parsers must tolerate). Took the 4-placeholder
    DIMSnowHorn1 + dim2prisonmammoth merge byte-exact: 4 specific fns needed
    block-scope overrides (`fn_802BB4B4`: `u32 getButtonsHeld/JustPressed`
    no-clrlwi; `fn_802BB998`: `u16 audioPickSoundEffect` chain; `func15`:
    ghidra-order Matrix_TransformPoint L2R arg eval; init: GameBit_Get
    int-return cmpwi), all clean C, all byte-verified. Pair with #14 (`int`
    param → cmpwi) and the caller-side-width table for picking which variant
    each call site needs. (delta-29 task #133.)

58. **`u16 num = field` keeps the unsigned width for `cmplwi`; `long num =
    field` widens to signed and emits `cmpwi`.** When target shows `cmplwi`
    on a value that was loaded from a `u16` struct field (e.g. `lhz r5, off
    (r4); cmplwi r5, 0`) and your code uses a wider local (`long num =
    T.uint16Field; if (num != 0) ...`), the implicit widen to `long`
    flips the compare to signed. **Fix: type the local to match the field
    width.** `u16 num = T.uint16Field;` preserves the unsigned width and
    emits `cmplwi`, while keeping the local for CSE so subsequent uses of
    `num` (e.g. as a `sndBSearch`-style `int` count param) still reuse the
    loaded register. Caller-side-width-control mirror of recipe #14 (`int`
    param for `cmpwi`) and recipe #3 (`*(void**)` for `cmplwi` on pointers).
    **The cleaner "MP4-style" inline (`if (T.field != 0) { ... f(T.field) }`
    with no local) LOSES the CSE** — MWCC re-derives the field address and
    issues an extra `addi`+`lhz` pair for the second use, regressing fuzzy.
    Keep the local; just type it correctly. Took dataGetMacro 98.38→100% in
    one line. (Found via MP4 musyx synthdata.c reference + objdiff
    instruction-level inspection.)
    **Struct-FIELD width is the same lever, but A/B project-wide before
    flipping a shared typedef — mixed-width fields need per-site LAUNDERS,
    not typedef flips.** (task #169, hit-state naming recovery.) When a
    naming sweep replaces raw casts with `obj->field` access, the field's
    declared type sets the width at EVERY site at once: `int lastHitObject`
    → `u32` restored recipe-#3 `cmplwi` pointer compares across 5 fns
    (+1556); `u8 contactFlags` → `s8` restored `lbz+extsb+cmpwi` value
    compares across 4 fns (+1888). BUT `s8 hitVolumeId` → `u8` was NET
    NEGATIVE (−104): the player.c store wanted no extension while two
    objlib 100%s NEED the s8 extsb. When sites disagree, keep the
    majority-correct type and launder the minority site through a cast
    pointer: store `*(u8 *)&s->field = v;` (kills the extsb), bit-test
    `(*(u16 *)&s->field & 8)` (lhz not lha), load `m = *(u8 *)&s->arr[i];`
    into an s8 local (extsb lands at the ASSIGN, recipe #15 family). The
    launder keeps the field NAME visible — naming intent preserved.
    Audit method for any rename sweep: per touched file, build the
    pre-sweep file state and per-fn-diff report.json (full rebuild first —
    stale .o files fake regressions, e.g. fn_801DFA28's phantom −1.6).

59. **Defeat MWCC's commutative-FP-reassociation by lifting the LEADING term
    to its own statement BEFORE the dot/sum expression.** When target's
    fmuls+fmadds chain follows your written source order (e.g. C says
    `a[1]*n[1] + a[0]*n[0] + a[2]*n[2]` and target multiplies `a[1]*n[1]`
    first) but your output reorders to canonical index order (`a[0]*n[0]`
    first), MWCC is reassociating commutatively. **`#pragma scheduling off`
    does NOT fix this** — it's reassociation, not scheduling.
    Fix: `f32 yy = a[1] * n[1]; f32 dot = yy + a[0] * n[0] + a[2] * n[2];`
    — pulling the leading term into a statement before the dot expression
    pins it as the first fmuls and the dot chain becomes
    fmuls(yy) → fmadds(+a[0]*n[0]) → fmadds(+a[2]*n[2]) matching target.
    Took Vec3_ReflectAgainstNormal 98.43→100%. **Sibling of #27** (lead
    with unary-negated operand for fneg+fadds) — both are statement-level
    expression-restructure to control MWCC's commutative reordering.

60. **"99.99% cosmetic" partials can hide REAL behavioral bugs masked by
    `--diff`'s reloc-tolerance — always byte-compare before declaring a
    pool-name artifact.** When a function scores 99.99% (1-2 bytes off) and
    `function_objdump.py --diff` shows zero divergence (because the diff
    tool tolerates reloc-target address differences from the symbol living
    at different file offsets in target vs current `.o`), the residual may
    NOT be a `@NNN`-vs-`lbl_xxx` pool-name artifact — it may be a single
    literal-operand byte difference that encodes a behavioral bug. Recover
    by raw byte-diff of the function bytes pulled from both `.o` files
    (objdump `-t` for the symbol address, `.text` section file-offset, read
    `sym_size` bytes from each), find the differing byte, map it back to
    its instruction's offset (offset/4), and inspect what immediate it
    encodes. Took `objAudioFn_8006edcc` 99.99→100% via byte-diff: the
    differing byte was `li r0, 8` (target) vs `li r0, 4` (current) at
    offset 0x50 — a loop-count immediate. The C had `for (bit=0; bit<16;
    bit++) { (mask >> bit) & 1 ... }` against a 32-bit `int mask` —
    target's unrolled-4x ctr=8 implies 32 iterations, while the C bound
    of 16 produced ctr=4 / 16 iterations. **The C had a wrong bound** —
    the bit-scan should walk the full int (32 bits), not 16. Fix:
    `for (bit = 0; bit < 32; bit++)`. **Lesson: when --diff shows
    everything-identical but the score is <100%, run the byte-diff before
    accepting the pool-name-artifact explanation.** Some Ghidra imports
    silently capped loop bounds to the data width the decompiler inferred
    (here u16 vs the int param), and the unroll-factor disguises the count
    mismatch as a single immediate byte. The script for a byte-diff:
    ```
    objdump -t <file>.o | grep <sym>   # get sym addr + size
    objdump -h <file>.o | grep .text   # get .text file offset
    # read sym_size bytes from (.text offset + sym addr) in each, diff
    ```
    (Found via report.json 99.99% screening + raw byte compare. The
    `--diff` mask-tolerance was masking a genuine codegen difference,
    not a cosmetic artifact.)
    **Empirical observation (audit of 14 fns at 99.9-99.99%, ≤500B):
    ALL 14 had real byte differences after reloc-mask, ZERO were purely
    pool-name-artifact cosmetic.** Recipe #10's "@NNN-vs-named-lbl is a
    measurement artifact" applies far less often than initial impressions
    suggested — when objdiff scores <100%, the bytes ARE different.
    Tool: `tools/cosmetic_audit.py [--min-pct N] [--unit-filter X]` walks
    every fn, reloc-masks the byte diff, and reports the actual differing
    instructions with side-by-side disasm. Use as a screening pass before
    grinding any individual 99.9% partial. Categories observed in the
    99.5-99.99% tier: constant-immediate bugs (loop bounds, decrements),
    operand-order divergences (recipe #59 fmuls/fsubs), frame-size
    differences (arg-passing area for callees with many args),
    register-coloring residuals (recipe #16), branch-displacement
    layout (recipe #21). Knowing which *category* a partial is in lets you
    pick the right recipe to attack it with (and prioritize the categories
    that have landed cracks over the ones still open).

61. **Distinct pointer locals (not `p += K`) to keep target's `addi rX,rX,K`
    base-bump.** MWCC forward-substitutes a `buf += K;` reassignment into every
    later use as cumulative offsets off the ORIGINAL base (`addi r0,r3,K1+K2`,
    base reg never updated). When target actually BUMPS the base register
    (`addi r3,r3,K; stw r3; addi r0,r3,K2`), introduce a NEW pointer local per
    region (`char *p2 = buf + K; ... char *p3 = p2 + K2;`) instead of
    compound-assigning the same variable. With the old pointer dead, the
    allocator coalesces each new local onto the same reg and emits the exact
    `addi r3,r3,K` bump chain. Took waterfx_initialise 99.52→100%.
    **Companion (param relocation):** when target tests/uses a value in r4
    (the COPY) but your code emits the test on r3 (the original param) — e.g.
    `mr r4,r3; clrlwi r0,r4` vs yours `clrlwi r0,r3` — drop the separate local
    (`int bitValue = value;`) and REASSIGN THE PARAM (`if (...) value = 0;`)
    so the variable itself relocates to r4 and all uses reference it there.
    Took setGameBit2BA 99.67→100%. Both are the same lesson: MWCC's
    copy-propagation picks the SOURCE reg; restructure the variables so the
    intended reg IS the variable's home.

61b. **Saved-reg coloring IS often source-flippable: declare a late-used
    scratch local (`int ret;`/loop counter) FIRST.**
    **TRANSPLANT BATTERY (the #108 rosetta method, 3 wins on previously
    35-lever-resistant fns): probe every banked rotation with the standard
    3-variant battery — (a) late-local-first, (b) FULL-REVERSE-SPLIT
    (decl order reversed AND inits separated from decls: `int flag;
    TimerFlags *f; TimerSetup *setup; TimerState *state; int v;` then
    `state = ...; setup = ...; f = ...;` — the strongest member:
    timer_update 98.36->99.10 after the whole campaign failed),
    (c) full-reverse with inits in place (n_rareware 86.69->87.26,
    fn_800D55BC ret-first +0.24). Hit rate ~3/8 on the banked inventory;
    inert where address-taken locals dominate (#5 pins offsets) or the fn
    is a bare 2-web pair (dead decls DCE). Derived from reading MP4's
    matched THPSimpleDecode (locals literally named after their registers —
    the matched corpus encodes decl-order->coloring patterns per shape;
    see tools/research/README_108.md rounds 6-7).** Three confirmed wins in
    one session: when target colors params/early locals to HIGHER saved regs
    than yours (obj→r31 vs your obj→r29, with the whole body cascading),
    insert/move a plain `int` local that's only used LATE to the TOP of the
    decl list. MWCC then assigns it last-internally and the param/early-local
    coloring shifts up to match (endObjSequence j-first → j=r31;
    explodeplan_updateTriggerCallback ret-first → obj/q/runtime=r31/r30/r29;
    fn_802C0A5C inner-before-q → p2/q=r31/r30). Try this BEFORE declaring a
    recipe #16 coloring cap.
    **VOLATILE-reg edition — a FN-SCOPE decl (assignment left in place) sets
    the vreg NUMBERING even when decl-order swaps among initialized locals
    are inert.** Split the decl from its init and move ONLY the decl to fn
    scope, then battery its POSITION: `int v;` declared before the other
    inits flipped alphaanim dll_115_seqFn's def/v pair (def=r6, v=r4 =
    target → 100); `PartFxItem *q;` declared FIRST (before rank/arr) landed
    all three volatiles of Checkpoint_func0F (rank=r7, arr=r4, q=r6 → 100;
    q-last and q-mid were inert — POSITION is the lever, q-first ≠ q-second).
    Block-scope→fn-scope decl moves are codegen-free apart from the
    numbering, so battery cheaply. Pairs with #107's count-inline-in-
    condition (drop `s32 n` and write `i < lbl_X` to send the bound straight
    to ctr) and index-form `arr[i]` (#160) when the walker also diverges.
    **THIRD-WEB edition — when a swapped SAVED pair's own decl perms are all
    inert, battery the decl position of an UNRELATED short-lived local
    instead.** wmwallcrawler_update's spawnk/tricky pair resisted every
    direct permutation (tricky/idx/n/k, full-reverse), but moving the
    unrelated `u8 sum;` decl AFTER `tricky` flipped the pair r26→r27 =
    target (→ 100). The interfering web's position shifts which saved reg
    the disjoint short webs inherit — a partial escape for #108's
    "same-variable affinity across disjoint loops, not yet
    source-controllable" claim; bisect a full-reverse decl battery to find
    WHICH decl is the lever (here it was sum, not the pair's members).

61c. **Limit of #61b — 2-variable chained-deref pairs (`p = load; q = *(p+off)`)
    do NOT respond to decl-order.** When the ONLY divergence is a 2-reg
    permutation across a load chain (target q=r5/p=r6, yours p=r5/q=r6, every
    use cascading), decl-order flips were tried both ways and failed on 5
    separate fns in one session (getLoadedTexture, saveFileStruct_isCheatActive,
    playerAddHealth, fn_8002CE14, ObjModel_CopyJointTranslation — also the
    `lwz+mr` copy-pair direction in dimlogfire_init/curUiDllDraw). #61b works
    when there are ≥3 independent locals to reorder; the 2-var chain coloring
    is allocator-internal. ⚠️ **SUPERSEDED by recipe #107** — the pair is
    source-flippable by UN-naming the value target keeps in the lower reg
    (index-form for walked pointers, member-expression respelling for
    chained loads); getLoadedTexture/saveFileStruct_isCheatActive/
    playerAddHealth/curUiDllDraw all → 100. **Same-init COPY pairs
    (`p = base; ...` both alive, lwz+mr) flip via the CHAINED init
    `p = base = lbl;`** (#51's pointer cousin; insertPoint → 100, recipe
    #112 session) — try the chain spelling when #107's un-naming read
    doesn't apply.

61d. **The @NNN-vs-named conversion-bias residual: MECHANISM + tested negative.**
    The "named" symbols (lbl_803DFD88, lbl_803E6E80, ... — mistyped `string
    "C0"` in symbols.txt) are the int→f32 conversion biases (0x43300000...)
    living in the SHARED auto_11_803DE500_sdata2 unit; target TUs reference
    them via SDA21 while our TUs emit a private @NNN copy that links at a
    different address (hence the per-reference fuzzy penalty — 77 refs in
    Effect7_func04 alone). TESTED: writing the conversion manually in C
    (`((u32*)&t)[0]=0x43300000; ((u32*)&t)[1]=x^0x80000000; r = t - bias;`
    with `extern f64 lbl_x`) DOES emit the named SDA21 reloc, but produces
    `fsub+frsp` instead of MWCC's internal fused `fsubs` — net WORSE (+1
    instr per site). No C spelling fuses a user-written f64 subtract into
    fsubs. (The premise was that a splits/link-level dedup of our .sdata2 bias
    entries onto the auto_11 symbols would be the fix.)
    ⚠️ **PREMISE SUPERSEDED by recipe #70 (task #145)** — the @NNN reloc is
    score-neutral, so there is no per-reference fuzzy penalty and no
    splits/link-level fix is needed; any remaining deficit is ordinary codegen
    divergence elsewhere, attack it as such. The manual-idiom negative result
    above (fsub+frsp vs fused fsubs) is a settled negative — that specific
    spelling is exhausted, so don't re-run it; the function is still open via
    the ordinary-codegen axis.

62. **`(int)`-cast the store base to defeat address-CSE with a later
    `(u8 *)p + off` call arg — restores the displacement-form store.** When a
    function stores to `*(u8 *)((u8 *)p + off) = K` AND later passes the same
    address `(u8 *)p + off` to a callee, MWCC CSEs the address computation:
    it materializes `addi r4, base, off` EARLY and stores via `stb r0,0(r4)`
    (indexed-zero form, +1 instr vs target's direct `stb r0,off(base)` with
    the `addi` recomputed later at the call). Writing the STORE's base with an
    `(int)` cast — `*(u8 *)((int)p + off) = K;` — makes the two address
    expressions formally distinct, killing the CSE: the store folds to the
    displacement form and the call re-derives its own `addi`, matching target.
    Mirror of #30 (which forces the OPPOSITE direction). Took
    sh_queenearthwalker_processAnimEvents 98.21→100 byte-exact.

63. **Ternary `x = (cond) ? x : -x;` reproduces the `bne then; b end; then:
    fneg` empty-then layout; `if (!(x>=K)) x = -x;` materializes the bool
    (mfcr) instead.** When target shows the odd
    `fcmpo; cror eq,gt,eq; bne L1; b L2; L1: fneg; L2:` shape for a
    conditional negate, the C is the ternary keep-or-negate assignment, NOT
    a negated-condition if-statement. BUT for a conditional RETURN with the
    same cror+bne shape, `if (!(f >= K)) return;` works directly (no mfcr) —
    the materialization only bites in an assignment context. Both instances
    were real Ghidra import condition-INVERSIONS on fn_80151DB8 (the import
    negated/returned on the opposite branch) — whenever target's branch
    sense differs from the import's, suspect inverted logic (drift section)
    before a codegen cap. fn_80151DB8 98.16→100.
    **SINGLE-USE FOLD CAVEAT + the empty-ELSE escape (cfguardian w-site).**
    The #63 ternary only keeps its own-statement shape when its result
    survives as a statement boundary; a SINGLE-USE result gets
    forward-substituted into the consuming expression — the ternary then
    evaluates at its L2R operand slot (e.g. AFTER a conversion that is the
    left operand) and the join goes through a fresh temp with an `fmr` in
    the keep-arm. No spelling rescues the substituted form (probed: #85
    self-reassign chains, fresh result var, intervening named-conversion
    statement, embedded def in the condition, (f64) sandwiches, fn-scope
    decl, opt_propagation/lifetimes/dead_assignments off — MWCC re-folds
    through all of them). The working escape is the empty-then if/else
    `if (x >= K) { } else { x = -x; }` (or its goto twin), which — contra
    this recipe's earlier claim — does NOT mfcr: it emits `fcmpo; cror;
    beq Ldone; fneg x,x` with the IN-PLACE fneg at the statement's true
    position, because the conditional def gives the use two reaching defs
    and substitution is barred. Residual vs target's ternary shape: the
    front end folds `bne;b` to one `beq` (1 instr) — far cheaper than the
    substituted form's transposed conversion blob (+fmr). Score the two
    forms per site; the ternary stays right when the result is stored or
    multi-use (the fn_80151DB8/d-site cases), the empty-else wins when the
    sole consumer is a larger expression.

64. **`int` local + `(u32)` cast in the test for a direct saved-reg `lbz` +
    `cmplwi`.** A `u8 vr = p->byteField; if (vr != 0)` local that lives across
    calls routes through a volatile (`lbz r4; mr r24,r4`); typing it `int vr =
    p->byteField;` makes MWCC load DIRECTLY into the saved reg — but flips the
    compare to signed `cmpwi`. Write the test `if ((u32)vr != 0)` to get
    `cmplwi` back while keeping the direct load. Extends recipe #58 (type
    controls compare width) with the load-homing direction. Remaining
    saved-reg permutations can be PER-BLOCK asymmetric — one block wanted an
    `int hi;` declared before the byte local, the sibling block wanted it
    after; A/B each block independently. Took Sfx_ReadTriggerParams
    99.53→100.

65. **Allocator SKIPS a low volatile around a call → that reg is a HIDDEN
    live ARGUMENT — find the missing param.** When target's scratch/iface-
    chain registers jump over rN (e.g. chain in r5/r6/r8 where yours uses
    r4/r5/r3), rN is being kept live INTO the upcoming call — the call takes
    one more argument than your C passes. Recovers recipe #9's corollary by
    reading the ALLOCATION GAP instead of the call-site span. Four wins in
    one session: dll_19_func0C (vcall takes p7; extsh CSEs into r5),
    mmsh_scales_init (trigger-iface slot-7 takes (state, def) — def parked
    in r4 from entry, zero extra instrs), dimlogfire_render (inner
    objRenderFn takes the full 6-arg p2-p5 pass-through, recipe #9 verbatim),
    findRomCurvePointNearObject (slot-7 vcall takes the previous vcall's
    return — recipe #50's nested-call form: `vcall7(found)` keeps r3
    untouched between the two bctrls). The tell is ALWAYS "why didn't MWCC
    use the obvious next reg?" — answer: because target's source had it
    occupied.

66. **Volatile-pair number swap on two chained loads → give the SECOND
    value an explicit block-local, declared AFTER the first.** When target
    assigns ptrA→r3/valB→r4 but yours emits ptrA→r4/valB→r3 (same loads,
    numbers swapped), introduce a local for the value that's read MULTIPLE
    times inline (`s16 texId = *(s16 *)(state + 0x4a);` /
    `f32 *q = (f32 *)lbl_xxx;`) and use it at every site. The explicit local
    (declared after its partner) re-orders MWCC's vreg creation and lands
    both numbers. Works where pure decl-reorder of EXISTING locals does
    nothing. shadowInit 99.58→100 (texId local, declared LAST — declaring it
    FIRST regressed), CameraModeCloudRunner_init 99.60→100 (q local for the
    global pointer). Sibling of #16, for the volatile-pair case.

67. **Frame-size (stwu/stmw delta) class — diagnose via sp-LAYOUT, not call
    args; four sub-causes, each with its own fix.** (task #144 research.)
    Ground truth first: MWCC GC EABI reserves NO outgoing-arg area for
    register args (a 6-arg-calling fn compiles to frame -8 = linkage only) —
    a frame delta is NEVER about callee arg counts ≤8 GPR words. Frame =
    8B linkage + address-taken locals + FP-CONVERSION SCRATCH high-water +
    saved regs, rounded to 8. Each int↔f32 conversion site consumes one-two
    8B scratch slots (xoris/0x43300000 magic pair in, fctiwz+stfd+lwz out).
    DIAGNOSIS: dump both objects, list every `r1)`-relative access + the
    `_savegpr_NN` reloc, then classify:
    (a) **Inner offsets identical, only the top differs** → phantom temp-slot
        delta from source-form temp COUNT. A re-evaluated member chain adds
        an 8B slot with ZERO code change: seqPlaySong 99.94→100 by writing
        `if (gs[i].gAddr->type == 0) { g = gs[i].gAddr; ... }` (re-evaluate
        in the condition, assign inside) instead of `g = gs[i].gAddr;
        if (g->type == 0)`. The CSE'd final code is identical; only the
        pre-RA slot count grows. Inverse direction: collapse such
        re-evaluations to shrink. (1.2.5n; on 2.0 GPR-temp re-evals were
        slot-neutral — A/B per compiler.)
    (b) **GAP between address-taken local offsets** → a stack struct is
        BIGGER than the fields you write. Read the gap: fn_801E83B0's target
        put f64 scratch at 0x40 but `v` fields ended at 0x18 → the
        lightningCreate endpoint struct is really 0x38 bytes (pad 0x28),
        frame -96→-144 exactly (97.29→97.41, rest is coloring).
    (c) **Conversion-scratch slots at DIFFERENT offsets (slot-stream
        divergence)** → compare the "slot stream" (the ordered sequence of
        `lfd/stfd fN,K(r1)` offsets). Statement GRANULARITY controls slot
        coexistence: a clamp written as ONE ternary statement
        (`g = g < (f32)-p5 ? (f32)-p5 : (g > (f32)p5 ? (f32)p5 : g);`)
        keeps all its conversion temps simultaneously live → distinct
        descending slots + bigger frame; the if/else form frees+reuses one
        slot. CAVEAT: flipping the form can perturb GLOBAL register
        coloring elsewhere in the fn (ObjSeq_func20: ternary matched the
        full slot stream AND frame -128 but cost an extra `mr` upstream,
        insensitive to 6 yawd-form variants — net LOWER fuzzy; reverted).
        If the slot-stream fix regresses elsewhere, keep the higher-scoring
        form and file the frame as cosmetic.
        ⚠️ PARK-CLEAR METHOD (ObjSeq_func20 97.33->100): the "extra mr
        upstream" blocking the ternary is often a NAMED narrow local's web
        — UN-NAME it first (int local + per-use (s16)/(u8) casts, #107/#97:
        the extension temp re-executes per statement and the abs/select
        joins in r0 with no mr), THEN apply the ternary clamp; the slot
        stream + frame land with no upstream cost. Sequence matters: the
        yawd-form variants failed BEFORE the un-naming because the named
        web pinned the coloring. Pair with #85 self-reassign chains to pin
        any conversion the single-use temp form lets MWCC sink.
    (d) **`_savegpr_NN` differs (extra saved reg)** → NOT a frame mystery:
        one extra live range, usually MWCC CSE-ing a repeated address expr
        (`(char*)o2 + 0x18` ×3) into a saved reg where target recomputes.
        Value-numbered CSE — different SPELLINGS of the same value
        (`(char*)(o2+6)`, `(u8*)o2+0x18`) do NOT defeat it. But FIRST diff
        the logic: fn_801CE2BC's "frame residual" hid 3 missing vtable
        double-derefs, two INVERTED float compares, and a missing
        `case 0x13:` fallthrough (97.0→98.15 from bug fixes alone).
    Null results (these spellings are exhausted — reach for something new, not
    these): dead/unused locals and dead conversions drop
    their slots entirely (can't pad a frame with dead code); `(s16)` casts,
    block-vs-function scope, and lo/hi clamp-bound locals are all
    slot-neutral on 2.0. Sensitivity probe: an address-taken `f32 probe[N]`
    passed to any callee moves the frame in 8B quanta — use it to measure
    the demand gap before hunting the source form.
    **(b) is by far the most productive sub-case — sweep findings (7 fns,
    5 to 100%):** the Ghidra import routinely GUESSED address-taken
    out-buffer array sizes, and the frame delta is the tell. Wins:
    wmgeneralscales_SeqFn `u8 buf[20]→[16]` (100%), fn_801B9ECC
    `u16 anim[4]→[2]` (100%), dll_19_func08 `u8 bboxOut[0x80]→[0x54]`
    (matches sibling TRICKY_BBOX_HIT_SCRATCH_SIZE; 100%),
    player_applyVelocityStep `f32 mtx[12]→[16]` (64B matrix slot; 100% with
    #15+#34 on top), fn_8002A5DC `f32 m2[16]→[12]`, worldobj_update
    `f32 vec[4]→[10]`, dll_1FF_update `int stk[3]→[2]`.
    METHOD: (1) in-place SIZE-PROBE the suspect array (edit, `ninja <unit>.o`,
    objdump the stwu) until the frame matches — several sizes can give the
    same frame (alignment), so ALSO align the conversion-scratch base (the
    first `stw r0,K(r1)` of an int↔f32 pair) against target before picking;
    disambiguate ties by sibling-code constants/callee semantics.
    (2) STATEMENT-DELETION PROBES localize which construct owns phantom
    slots when no array is obvious — deleting one statement often drops the
    frame in 16B steps (slot demand is thresholded, not linear).
    Census tool: compare per-fn stwu immediates across all <100% fns by
    objdumping target vs current .o (273 mismatches project-wide at last
    run) — but FULL-REBUILD FIRST; stale .o files produce false candidates.
    Block-local placement traps seen: MWCC 2.0 ignores decl order for
    sibling block locals (rot/vec landed reversed vs target regardless of
    order) — a wrapping struct pins the layout (recipe #8 cousin) but can
    perturb the sth/addi schedule and net-lose; measure before keeping.
    ⚠️ **RESOLVED for the rot/vec case (DIMcannon lavaball1be_init → 100,
    unit → 100.0): placement is in order of FIRST ADDRESS-TAKING (call-arg
    order), probe-proven** — decl order, scope, size, alignment, use order
    all inert; a 3rd address-taken local always stacked in arg order. When
    target's order contradicts the call's arg order, the original was ONE
    WRAPPING STRUCT (vec@+0, rot@+12 = sp+8/sp+20 exactly), padded per
    #67(b) to land the conversion-scratch base (pad[18] → 36B → scratch@48,
    frame -128). The struct's sth/addi schedule perturbation (addi hoisted
    above the last sth, +0 instrs but transposed) is fixed by spelling the
    call arg as RAW POINTER ARITH `(u8 *)&s + 12` instead of `s.rot` — the
    member-decay spelling shares its address node with the rot[0] store and
    hoists; (int)-cast launders are VN'd through; only the structurally
    distinct raw-arith tree lands target's sth-then-addi order.
    GXColor-style by-value struct args each take an 8B caller temp slot —
    same threshold behavior (objFn_8003dc50 capped: target allocates 2
    fewer temps for identical call sites; no source form found).
    **(a)-struct corollary — a STRUCT-typed local reserves its stack slot
    even when fully enregistered; flat scalar locals don't.** When the
    frame is N bytes SHORT and the body computes a vector/aggregate in
    plain f32 locals (`f32 dx, dy, dz;`), the original likely used a
    struct (`SND_FVECTOR d; d.x = ...`) — rewrite as
    `struct { f32 x, y, z; } d;` to claim the 16B slot with ZERO code
    change. Proven: s3dUpdateRoomDistances 99.18→100 (the MP4 musyx
    source literally declares `SND_FVECTOR d; // r1+0x8` while every use
    is enregistered), s3dAllocateRoomStudios +16B/+0.2, dimlogfire_update
    97.94→99.75 (3 flat f32 → struct vec, +16B). Check MP4 musyx for the
    upstream form when the fn is audio. SCOPE NOTE: the corollary applies
    even when the scalars ARE address-taken in one place (dimlogfire's
    &local passed to a callee) — the struct still claims MORE space than
    the bare scalars; but wrapping ALREADY-slotted outparam scalars
    (CameraModeCrawl's &v20..&v8 quad) is frame-NEUTRAL — the extra 16B
    there is the separate conversion-temp threshold class. A/B per fn.
    Threshold caps seen in the census sweep (deletion probes move the
    frame in 16B steps but no single source construct owns it; 4+ forms
    tried each): treasurechest_update, CameraModeCrawl_update, drawHudBox
    (target gives EVERY s16→f32 call-arg conversion a fresh slot — 18
    slots, zero reuse — while current reuses the if-block's 2; scheduling
    pragma toggles and if-form variants all inert), foodbag *_func03
    family (sub-case d: long-lived `base+0x2a8` temp in r0 (volatile) in
    target vs r25 (saved) in current — naming/decl-order/pragma all
    inert; see task #146). ⚠️ **PARTIALLY SUPERSEDED (task #157 meta-audit):**
    treasurechest_update → 100 (was a #67(b) import-guessed array size
    `z[2]→z[1]` + a #62 arg launder), drawHudBox → 100 via recipe #83;
    CameraModeCrawl improved via #83 ternary clamps (97.68→97.79, frame +
    slot stream now exact) but still partial. Retry the others against
    recipes #80-#83 before banking them as open threshold residuals.

68. **`mr rS,r3`-copy forward-prop into early derefs is a PEEPHOLE opt —
    `#pragma peephole off` makes pre-call derefs use the COPY, matching
    target.** The recurring 1-2 instr residual where target derefs the param
    through its saved-reg copy (`mr r30,r3; lwz r31,184(r30)`) but yours
    derefs through r3 directly (`lwz r31,184(r3)`) is NOT a coloring cap and
    NOT fixable by source restructure (param reassign, local copy, (u32)
    casts, typed params, statement moves all tested null on
    earthwalker_hitDetect) — it is the PEEPHOLE pass propagating the copy
    source into subsequent uses. Flip the fn to `#pragma peephole off` (or
    wrap `off`/`reset` if the fn sits in a reset/default region). ONE
    discovery recovered 11 fns to 100% in one pass: earthwalker_hitDetect,
    sc_levelcontrol_init, sc_musictree_handleHitObject, fn_80185868,
    fn_801F654C, drcloudper_setScale, cmbsrc_free, fn_80175428, fn_8023A87C,
    androsshand_init, pointlight_free. Signature to recognize: ndiff 1-3,
    all derefs of 184(rN)/76(rN)-style param fields, target reg = the mr
    copy, yours = r3/r4. CAVEAT: vecmath's vecRotateZXY/setMatrixFromObjectPos
    show the same signature but are ALREADY peephole-off — that variant
    (deref via the copy of a NON-r3 param) is still open (the peephole lever
    doesn't reach it; needs a different copy-prop axis). Supersedes the
    former "param-relocation" triage-table note (since removed from the table).
    **Where #68 does NOT apply — peephole-ON-target units (audio TUs etc.).**
    The recipe assumes the peephole pass is propping the copy and target
    compiled WITHOUT that prop. In a unit whose target compiles peephole-ON
    (no pragmas — audio/), target's compile ALREADY did the propagation, so
    the residual there is genuine scheduler/coloring, NOT copy-prop.
    Diagnostic: check the unit's pragma state FIRST. Applying `peephole off`
    to a peephole-ON-target fn REGRESSES hard (golf-1's audio-cap A/B:
    synthAssignHandle 98.6→81.4, hwChangeStudio 98.2→82.1,
    synthGetNextChannelEvent 98.0→91.8, DoSetPitch unchanged — all reverted).
    The audio ON-target rule holds at the SCHEDULING level too: a sched-off
    wrap on salInitDsp (sal_dsp) regressed 85.7→60.3 — audio TUs compile
    both passes ON; never wrap them (pragma-field batch 5).

69. **`cmpwi` immediate is ASYMMETRIC for mathematically-equivalent int
    compares — match the immediate, not just the predicate.** `if (x <= 0)`
    emits `cmpwi rX,0; bgt-skip`; the equivalent `if (x < 1)` emits
    `cmpwi rX,1; bge-skip`. Same for `>= K` vs `> K-1`. When the residual is
    a single cmpwi-immediate diff (paired with a branch-mnemonic diff), try
    the equivalent inversion (`< K+1` ↔ `<= K`, `>= K` ↔ `> K-1`) — read
    which immediate target uses and write that form. pinponspike_update's
    timer test was `<= 0` (cmpwi 0) where the import wrote `< 1` (cmpwi 1).
    NOTE the gotcha: the inversion is PER-COMPARE — flipping a different
    equivalent compare in the same fn regressed the already-matching one.

*(Numbering note: the FbBuf/cmd-list recipe set that previously sat here as a
duplicate #70-72 — a numbering collision with the task-#145 set below — now
lives as recipes #93-95 at the end of the numbered list.)*

**Recipe #60 addendum — two more single-instruction real-bug signatures:**
- **Missing vtable deref**: target `lwz r12,K(rX); mtctr; bctrl` vs current
  `addi r12,rX,K; mtctr; bctrl` = the C calls the SLOT ADDRESS instead of
  the loaded function pointer (runtime crash). Add the missing `*` level at
  the call expression (sh_beacon_update: `(*(fp*)(*iface + 0x20))` →
  `(**(fp**)(*iface + 0x20))`). Same family as the "Vtable double-deref
  pattern" section — but found via a SINGLE-instruction byte-diff at 99.78%.
- **Wrongly-guarded store**: a single branch-DISPLACEMENT diff at 99.9%+
  (beq jumping past one extra store) = a store/guard the import nested
  inside a condition that target executes unconditionally
  (sc_musictree_render: `obj->0xF8 = 1` belonged AFTER the if-block, the
  import early-returned past it). Suspect behavioral guard bugs before
  layout caps when ONE branch target is off by one store's width.

**Recipe #65 addendum — the allocator-gap finds REAL dropped arguments.**
~half of #65 applications surface genuine Ghidra-dropped call args, not
dead-param signature mismatches: textureFree lost its only argument
(drawTrickyHudOverlay), objRenderFn_8003b8f4 lost the 6-arg p2-p5
pass-through (dimlogfire_render, animatedobj_render), trigger/sfx-handle
ids lost from vcall sites (doorlock_update, sc_totemstrength_update,
saveSelectOpenFile, imspacethruster_update). When the gap reg is LOADED
with a meaningful value in target before the bl, the import dropped a real
argument — restore it, don't just pad the signature.
RETURN-CALL-POSITION tell (CFcrystal spawnFireFly): an arg with no visible
setup before a tail `bl` PLUS an otherwise-inexplicable `mr r4,r3` after an
alloc call = a dropped argument riding the alloc result. METHOD: after 2-3
failed coloring spellings on such an mr, grep SIBLING units for the same
callee (in-tree oracle — DRearthwalk.c showed `loadObjectAtObject(obj,
setup)` 2-arg) instead of continuing the spelling battery.
COMPARE-OPERAND-IN-ARG-REG tell (cfguardian, 2 finds): a value loaded/
copied into r4+ FOR A COMPARE (`mr r4,r3; cmplwi r4,0` after a call, or
`lbz r4,off(rN); cmplw r4,r3`) where your compile uses r3/r0, AND a
seemingly-short-of-args `bl` follows inside the guarded arm with rN
untouched = the compare operand IS that call's next argument. Looks
exactly like a #66/#107 volatile-homing residual and resists every
naming/embed/fn-scope mover (the value is an ARG web, not a named
local) — read the rN liveness into the bl BEFORE spelling batteries.
Recovered `dll_2E_func04(sub, found)` ×2 (head-track target; callee defn
in moveLib proved the 2-arg form) and `GameBit_Set(0x4b, sub->questState)`
(an import comment had even excused the one-arg call as "(sic) matches
retail") — all three real behavioral bugs, 99.31→99.54.

### 99.5%+ tier sweep findings (task #142) — category triage table

Empirical verdicts from sweeping the 99.5-100% tier with cosmetic_audit.py
(12 fns → 100%, ~10 capped after exhaustive source-form A/B):

- **TRACTABLE — spurious narrow-store extension (`extsh`/`clrlwi` before
  `sth`/`stb`).** Simple same-lvalue compound (`x = x ± K`) → write `--`/`+=`
  (recipe #20; modelDoAltRenderInstrs → 100%). Explicit `(s32)` cast around a
  float→s16 conversion store → DROP the cast (fn_80039DF8 → 100%). BUT when
  the subtrahend is a converted float (`h - (int)timeDelta`) or the value
  pairs with a separate compare local, the extension survives every form
  (7 tried) — cap (DFP_Torch_update, shopitem_update).
- **TRACTABLE — stack-address re-derive vs CSE reuse.** Target re-derives
  `addi r0,r1,K` where current reuses a live reg: write the address as a
  formally different expression — `(GfxCmd *)((u8 *)&buf + 0x60)` — to kill
  the CSE (dll_A0/dll_9F_func03 → 100%, +4 sibling partials lifted). Same
  family as recipe #62.
- **TRACTABLE — loop-init `li` order** → recipe #43 comma-init
  (staff_release → 100%). But a compiler-HOISTED invariant constant ordered
  before/after the counter init does NOT respond (Sfx_StopAllObjectSounds —
  cap).
- **TRACTABLE — audio/musyx: A/B the upstream MP4 musyx source verbatim
  FIRST** (inpSetMidiCtrl14 → 100% from MP4 snd_midictrl.c form: else-if
  chain, no `& 0xff`, repeated subexpressions, no locals). COUNTEREXAMPLE:
  mcmdSetADSR — the MP4 single-expression form fixed the frame (+8B temp
  slot) but scored 92% vs the prod-local form's 99.74% because it changed
  conversion INTERLEAVING. ALWAYS verify via report.json, not ndiff: objdiff
  penalizes TRANSPOSED instructions far more than same-position byte diffs —
  a "2-instr swap" can score WORSE than a "3-instr same-slot" diff
  (ObjModel_LoadModelData 99.75→96.6 on a 2-instr transposition "fix").
  BANKING-SCORE RULE (CFBaby): objdiff punishes MISSING-instruction
  misalignment more than extra same-position instructions — when choosing
  between two non-matching spellings for a banked residual, keep the
  LONGER one (InfoPoint: extra-beq form 95.83 vs missing-beq 95.63).
- **TRACTABLE — int compare/`+`-operand swaps respond to recipe #66** (a
  block-local for one operand) where the bare source flip does NOT — MWCC
  canonicalizes `cmplw`/`add` operand order regardless of source order
  (mapTextureOverrideRelease, RollingBarrel_free, objGetTotalDataSize all
  won via the local; the flips alone were no-ops). FP `fcmpo` + branch-sense
  pairs DO respond to the plain source flip (`best < v` → `v > best`,
  frustumPlanes 99.78→100) — flip when the BRANCH differs (ble vs bge),
  add a local when only REGISTERS differ.
- **95-98 tier signatures (highest-yield)**: (a) tiny DENORMAL float
  literals in import code (`1.68156e-42`-style) = a misinterpreted INT store
  — decode the bits, store the int (SB_Propeller_init: int 1200). (b)
  `lha`-vs-`lhz` runs in halfword COPIES = mixed s16/u16 fields; `lha`
  requires s16 on BOTH sides of the assignment — `u16dst[i] = *(s16*)…`
  still normalizes to lhz; write `((s16*)dst)[i] = ((s16*)src)[i]`
  (fn_8018FF48 95.08→100). (c) struct-index form (recipe #18) fixes BOTH
  the indexing shape AND the frame (drops the offset local's slot —
  synthHWMessageHandler frame 40→32); base-is-a-pointer-global variants
  keep an lbzx residual (#30's alias didn't bite there — partial).
- **OPEN — FP volatile reg-number permutation** within a statement window
  (fcmpo operand pairs, lfs/stfs bursts, fdivs/fmuls chains, fctiwz). Decl
  order, temp locals, statement order, compare-direction flips were all inert
  on the fns tried (wctemple_update 8 forms, LanternFireFly_func0B 4 forms,
  arwbombcoll delta-order 6 forms). Signature: N same-opcode instr pairs with
  only FP reg numbers swapped. ~10 fns in the tier (dll_127_init,
  Curve_SampleSegmentPoints, exploded_seedDebrisMotion, scarab fn_8015EA48,
  drawTexture, pi_dolphin fn_8004E0FC, magiccavetop fmr) — recognize by
  signature, then classify by web kind (below) and attack.
  ⚠️ **LARGELY SUPERSEDED by recipe #82** (decomposed — classify by web
  kind FIRST):
  symbol-CSE webs respond to the #81 launder (dll_127_init → 100%), named-local
  pairs to a plain decl-order swap (fn_8015EA48 → 100%); expression-temp
  pairs are the remaining open sub-class. See #82 for the full taxonomy.
  **EXCEPTION (cracked sub-shape): decrement+clamp where the compare CONSUMES
  the fsubs/fmadds RESULT (no reload between store and fcmpo).** Write
  `f32 t = global - delta; global = t; if (t < lim) global = lim;` — the
  explicit t homes the result in f1 (the minuend's reg) matching target;
  compound `-=` and the expanded re-read both leave it in f0
  (MMP_levelcontrol_update 99.88→100). DISCRIMINATOR: if target RELOADS the
  field before the fcmpo (lfs f1,off(rN) fresh load after the stfs), use the
  #81 launder instead (it cracks exactly this reload case — see below). The
  reload case was the open part on fn_801CEA14, dim2icicle_update,
  cclevcontrol_update, wctemple_update until #81. Read the target asm between
  the stfs and the fcmpo to pick. ⚠️ **CRACKED by recipe #81** (the reload case is
  cracked by the `*(f32 *)&lbl` launder) — the four "still-capped" fns above
  are #81's test set (5 of 6 → 100%). Use the same stfs/fcmpo read to pick
  temp_t vs the #81 launder.
- **`addi r0,rH,lo; mr rX,r0` vs direct `addi rX,rH,lo` — MOSTLY recipe #80
  in disguise** (task #155). When the recipient is a SAVED reg and
  the fn mixes body offset-uses (`base + K`) with a plain `base` call-arg,
  it's the #80 use-binding split — launder the init (`(T *)(int)&lbl`) AND
  the plain arg: mapSetupPlayer → 100, dll_82_func03 → 100 (via #80 sweep).
  The remaining OPEN sub-shape: a VOLATILE loop-pointer init where the SAME fn
  has a textually-identical second loop that matches while the first emits the
  mr (camcontrol_loadTriggeredCamAction, 1 instr) — same-fn divergence proves
  it's internal vreg-numbering state; 8 forms inert (init/indexed-use
  launders, register-keyword drop, separate local, comma-init, peephole-on).
  Classify by recipient reg: saved → apply #80; volatile with a matching
  twin → open vreg-numbering case, bank the 1-instr partial and re-attack when
  a vreg-numbering lever lands. DECREMENT-SPELLING sub-case (fuelcell_render
  → 100): a via-r0 on a `value±K` CALL ARG of a call that REASSIGNS the same
  variable = move the arithmetic onto the variable (`pickCount--; pickCount =
  randomGetRange(0, pickCount);`) — copy-prop then folds the compound update
  into the arg position in-place (#20 applied to call args; named-temp/mask/
  conversion spellings all kept the arithmetic inside the arg = the miss).
- **OPEN — player_SeqFn (98.10) top-pair allocation order (the cache-inline
  fix is a settled negative — try a different axis).** Eliminating the
  (int)inner cast-copy web (savegpr
  19→20, mid-webs align) makes the merged inner web (179 uses) outweigh obj
  (117) and OUR allocator flips them to inner=r31/obj=r30 — INVERTED from
  target (obj=r31, inner=r30 even though target's inner is also heavier).
  Every variant scored 97.5 vs the 98.10 baseline: the baseline's cast-copy
  web is LOAD-BEARING for the dominant coloring. Tested: web unification
  (h/va/obj2→inner), int-retype, callee-retype-decasting, decl order,
  register keyword, (char*)-cast stripping ×149. Also ruled out: the
  inlined-helper hypothesis for the ~9 materialized-mask sites — MWCC's
  INLINER re-folds constant masks to rlwinm (unlike the unroller, #28), so
  `static helper(p, flag){p->f &= ~flag;}` + auto-inline does NOT reproduce
  `li -K; and`. Both player_SeqFn residual families are open allocator/codegen
  problems pending a new recipe. ⚠️ **PARTIALLY SUPERSEDED by recipe #74** — the
  ~9 materialized-mask sites recovered via the LL-suffix spelling (see #74's
  refinement note); the top-pair allocation-order residual above is still open
  (re-attack with the #108 class-pooled allocator model and #115 callee-decl
  widths).
- **OPEN -- GVN small-constant web merging (4 instances: fn_802A0680,
  Tricky_update, worldplanet_update, dll_0B_func04 x4 sites).** Target
  materializes a small constant FRESH at its use (`li r0,0` / `li r0,-1` at
  a store) or CHAINS it (`li rY,K; mr rX,rY`) where our compile MERGES the
  webs the other way: a #74 LL high-word zero, an adjacent store's -1, or
  a chained `k = m;` init gets value-numbered into ONE early li (or the
  chain const-props back to separate li's). Spellings probed so far -- #51
  chains, (s16)/(u8) casts on the stored constant, int-vs-u8 locals --
  are inert; GVN keys on the VALUE, so the lever has to change the VN key
  (recipe #110's per-fn O1 wrap and #114's conversion-node splitter are the
  closest existing tools — try them; the small-constant-store sub-case is
  still open). ~1-2 instrs per site. (Same family from both directions:
  ours-merges-T-fresh AND T-chains-ours-rematerializes.)
  **CONFIRMED fn-GLOBAL, NOT source-bisectable (task #27, player.c #108
  exclusion set).** Two decisive negatives that close the source-respelling
  axis for this class: (1) **same-source-different-outcome** -- the IDENTICAL
  walker-clear loop (`p = lbl_80332ED4; for(i=0;i<7;i++){if(*p)Obj_FreeObject;
  *p=0; p++;}` clearing 7 obj slots, byte-for-byte the same source) byte-MATCHES
  at 100% inside Lightfoot_UpdateProximityInteractionState (196B) yet diverges
  at 94% inside fn_8029C8C8 (256B). Same loop text, opposite outcome -> the
  loop spelling is provably CORRECT and the divergence is purely the
  surrounding fn's #108-dose state. The divergence in the diverging copy is
  exactly this class: target inits the counter `mr r30,r31` (COPIES the 0
  already live in r31 from a `gByte=0`/`*p=NULL` store-web) where ours emits a
  fresh `li r30,0`, COUPLED with the #160 symbol-base via-r0 (`addi r0,r3,lo;
  mr r29,r0` ours vs `addi r29,r3,lo` direct in T). (2) **minimal /tmp probes
  CANNOT reproduce target's good behavior** -- a 28-line probe of that exact
  loop reproduces OURS (li-fresh + via-r0) but no spelling yields target's
  mr-copy/direct-addi, because the trigger is whole-fn web pressure not the
  loop. So probe-bisection (the method that cracked #74/#107/#114) structurally
  cannot find a lever here -- you can only A/B in the real TU, and the real-TU
  axes below are spent. NEW inert levers added to the exhausted list (all
  real-fn or probe verified, do NOT re-run): shared single-zero variable
  anchoring the const across the byte-store + the NULL-store + the counter-init
  (`int z=0; gByte=z; ... for(i=z;...) *p=(void*)z`); `#pragma opt_propagation`,
  `opt_common_subs`, `opt_dead_assignments`, `opt_loop_invariants`,
  `global_optimizer` each on/off (prop-off and global_optimizer-off CHANGE
  codegen but net WORSE -- extra li's, base still via-r0); sized-vs-incomplete
  array decl and the #80 `(int)`-launder on the walker init (both inert on the
  via-r0). The #160 INDEX form DOES remove the via-r0 (SR rebuilds the walker
  direct) and lifts fn_8029C8C8 94.2->98.4, BUT it rotates the i/walker pair
  (SR walker grabs the HIGHER reg, opposite target) and misrepresents the
  source (target compiled the walker form) -- per #160's own guard (convert
  only when target's reg assignment survives) it is NOT a faithful fix here;
  banked. CONCLUSION: this is the #108 fn-global dose class; the next lever
  must change the fn-global construct census / priority-fn inputs without
  changing the instruction stream (the open research direction in the #108
  cross-class-interleave note), reachable only via real-TU A/B, never probes.
- **VN-internal negatives (dll_0B_func04):** distributive
  factoring `(e+c)*48` vs separate `e*48 + c*48` products is
  value-numbering-internal -- statement split and two-locals spellings
  both fold back (split scored WORSE: partial-burst misalignment).
  ⚠️ **CRACKED by recipe #114** — the `(int)(long)` conversion-node sandwich
  blocks the distributive re-association (`e * 48 + (int)(long)(c * 48)` keeps
  separate products); use it on these sites.
  And the #6 const-lift there is LOAD-BEARING: inlining the lifted
  fz430/fz434 f32 locals regressed 92.3->88.9 (T just places the single
  loads lazily; the lift itself is correct) — keep the lift.
- **OPEN — web-split reload coloring** (reloaded pointer gets a fresh saved
  reg where target reuses the original — MoonSeedPlantingSpot_setScale;
  decl-perms and second-local splits regressed on the fns tried) and
  **reverse-order saved pairs** (worldasteroids_init — recipe #16's reverse
  permutation; re-attack via #107/#108/#115).
- **CRACKED — materialized-mask `lis;or` for `|= 0x20000`** (warpDarkIceMines).
  Recipe #2's inverse was the old blocker (const-lift and expanded `x = x | K`
  fold to `oris`); ⚠️ **recipe #74's LL-suffix
  spelling (`x |= 0x20000LL;`) materializes the constant** — warpDarkIceMines
  recovered (see #74's refinement note).

70. **@NNN-vs-named-lbl SDA21 relocs are SCORE-NEUTRAL — the "pool cap" was a
    misattribution; the deficit is always real codegen divergence elsewhere.**
    (Task #145, four decisive experiments.) objdiff content-matches a reloc by
    the DATA BYTES at the resolved target, so a local `.sdata2` copy (`@534`)
    of an int→f32 bias or float constant scores identically to target's shared
    `lbl_803EXXXX`. Proof: zulu14's 803E7158 retype + india-1's 803DFD88 and
    803E6E80 string→double retypes all produced ZERO project delta, and
    dimbossgut2_update + 13 Effect*_func05 fns reached **100.0%** with @NNN
    local-bias refs still in place. Consequences: (a) do NOT chase splits/dtk
    knobs or symbols.txt retypes for @NNN refs; (b) a symbols.txt retype that
    merges a `lbl_X+4` float away ORPHANS src externs referencing it — only
    safe when nothing references the merged symbol (the link survives today
    only because referencing units are NonMatching); (c) when a fn shows many
    @NNN refs and <100%, align the instruction streams (mnemonic-level difflib
    of `function_objdump.py`'s two halves) — the real divergences are ordinary
    recipe-class bugs. Effect7_func04's "77-ref @NNN cap" was actually ~12
    fixable divergences (98.30→99.87).

71. **Literal float constants REMATERIALIZE per use; named `lbl_` externs get
    CSE'd — pick the C form by whether target reloads.** When target reloads
    the same `.sdata2` float at every use (fresh `lfs f0, const` before each
    `fcmpo` clamp) but your named-extern form loads it once into a long-lived
    reg, write the LITERAL (`if (sum > 1.0f)`) — MWCC pools it locally (an
    @NNN reloc, score-neutral per #70) and reloads at each use, matching
    target's shape. Keep the named extern when target DOES keep it live. Took
    13 Effect*_func05 fns to 100% and lifted every Effect*_func04 head
    (modgfx + dim_partfx).
    **fcmpo OPERAND-ORDER corollary (wmsun campaign): a LITERAL comparand
    loads/evaluates FIRST regardless of which side of the compare you write
    it (`prod != 0.0f` emits the 0.0 load first); the EXTERN form follows
    written order.** So pick literal-vs-extern by target's fcmpo operand
    order too, not just by reload shape — and mix per SITE within one fn
    (wmsun fn_801F6EA4: literals at the compares whose const loads lead,
    externs at the value-first compares).

72. **`sum = g + (step = k * timeDelta);` — embedded assignment keeps
    LHS-first eval AND forces the product into a fresh named FP reg.** When
    target computes `fmuls f3,f1,f0` into a FRESH reg with the base global
    loaded first (`lfs f2,g`), the plain `sum = g + k*td;` form CSEs the
    product into a dead reg (`fmuls f1`), and a hoisted
    `step = k*td; sum = g + step;` reorders the loads (product computed before
    g loads). The embedded-assign form is the only spelling that does both:
    g loads first, product lands in f3, reused by the second sum. (Effect
    func05 family — combined with #71 for the 100%s.)

73. **dtk FALSE-RELOCATES in-range constants — a `fn_XXXX+0xNNN` reloc on a
    value stored to a FLAGS field is a constant, not an address.** When target
    shows `lis;addi {fn_8017FFD0+0x130}` stored into a field that elsewhere
    takes flag words (0x200, 0xc0080004, …) and the addend lands mid-function
    (not at any symbol boundary — check the disasm: 0x80180200 was a shared
    epilogue label), the original source stored the literal constant
    (0x80180100) and dtk synthesized a spurious reloc when splitting. Write
    the literal; objdiff resolves target's reloc to the same value and scores
    it matched. The Ghidra `(u32)((u8 *)fn + 0x130)` form costs an extra
    runtime `addi` — never matches. Check first that the addend is NOT a real
    function boundary (then it'd be a genuine callback needing a symbols.txt
    split). (modgfx Effect5/6/7/9_func04.)
    **FULL fix = literal in C + dtk `block_relocations` in config.yml.** The
    literal alone still scores a 2-instr mismatch per site (target .o carries
    the synthesized reloc, our literal has none; MWCC NEVER folds extern+const
    into a code reloc addend — probed 4 forms ×5 compiler versions, and MP4's
    6526 ADDR16_HA relocs have zero addends). Suppress dtk's false relocs:
    ```yaml
    block_relocations:
    - target: 0x80180100
      end: 0x80180218
    ```
    (key is `block_relocations`, NOT `blocked_relocations` — dtk silently
    ignores unknown keys). One range entry killed all 34 false-reloc sites
    across modgfx/dim_partfx/modelfx → Effect7/16/17_func04 to 100%,
    TOTAL +7216 in one config change.

74. **`LL`-suffixed constants in logical ops force MATERIALIZED-constant
    codegen — cracks the whole immediate-vs-materialized isel class
    (including the recipe #2 "inverse cap").** When target materializes a
    logical-op constant where every 32-bit C spelling folds to the immediate
    form, widen the CONSTANT to long long — the op widens to s64 and
    truncates back into the u32 lvalue with byte-identical semantics and no
    other codegen change:
    - `x ^= 2LL;` → `li r0,2; xor` (all 32-bit forms give `xori`)
    - `x |= 0x100100LL;` → `lis;addi;or` (vs `oris;ori`)
    - `x |= 0x800000LL;` → `lis;or` (vs `oris`)
    - `x &= ~0x80LL;` → `li r0,-129; and` (vs `rlwinm`)
    - `x &= ~0x20000LL;` → `lis -2; addi -1; and` (vs `rlwinm`)
    Version-independent (probed all 5 mwcc versions) — it is purely the
    operand TYPE; plausibly the original flag constants were 64-bit
    enums/macros. Swept ~20 sites in modgfx/dim_partfx → contributed to 5
    fns reaching 100%. Retry every "materialized-mask cap" partial
    (warpDarkIceMines `|= 0x20000`, player_SeqFn's ~9 mask sites, arwing
    flag handlers, the ~70%-capped tiny flag fns) with this spelling.
    Probe-batch method (a /tmp probe.c with N spellings × objdump grep)
    found it in minutes — use that pattern for future isel mysteries.
    BURST SEQUENCING: when a macro/burst has several ADJACENT materialized
    masks, convert them ALL before measuring — a partial conversion
    misaligns the burst and the A/B lies (Tricky_update: 1-of-4 masks
    scored 92.05→91.89, all-4 scored →96.13). Same alignment-cascade
    phenomenon as fake giant diff regions, applied to the measurement
    side: objdiff penalizes partial fixes of repeated adjacent patterns
    below baseline even when each fix is individually correct.
    REFINEMENT (foxtrot): the LVALUE must be u32 — an `int` lvalue widens
    SIGNED and emits an extra `srawi rX,rY,31` for the high word
    (fn_80296BBC needed `*(u32 *)(...) &= ~2LL`, recovering the historic
    70%-capped tiny-flag-fn example from the old recipe #2 inverse note to
    100%). player_SeqFn's 9 mask sites + warpDarkIceMines also recovered
    with #74 — the "11 missing instructions" diagnosis was entirely this
    class.
    **SWEEP DIAGNOSTIC — turn #74 from per-fn into a SAFE BULK operation
    (coloring-A, player.c flags360: +1896, 8 fns to 100% in one sweep).**
    A recurring flag WORD (e.g. a state struct's 0x360 field) whose masks
    are MATERIALIZED in target means the ORIGINAL used a consistent 64-bit
    constant for ALL of that field's ops. To prove it safe to bulk-convert:
    map EVERY non-LL mask site (`field |= 0xK` / `&= ~0xK`) to its
    containing fn's fuzzy%. If ~all sites sit in PARTIAL fns and ~NONE in
    100% fns (player.c: 1 of ~100 in a 100% fn), the field is uniformly
    materialized — bulk-convert ALL to the u32-cast LL form (`*(u32 *)
    ((char *)base + off) OP 0xKLL`; the u32 cast avoids the signed srawi an
    `int` lvalue + LL emits, per the foxtrot refinement above). GATE: snapshot
    per-fn fuzzy, convert all-at-once (#74 burst — partial conversion of a
    field misaligns and the A/B lies), rebuild report, diff per-fn. A few
    sites may genuinely use the immediate form (target inconsistent) and
    regress their fn — EXCLUDE those fns' line-ranges and re-apply (player.c:
    4 fns excluded — fn_8029F108/FA24/playerRender/fn_8029BDB4, whose mask
    change perturbs an independent #108 li-0 web). Leave positive-literal
    AND-clears (`&= 0xFFFFFFFD`) for the `~K` subcase. Apply per recurring
    flag word; each is its own bulk sweep.

75. **`union { f32 m[16]; f64 a8; }` 8-ALIGNS a stack array — fixes the
    "+4 stack-offset" frame residual.** When target places an f32 array at
    an 8-aligned sp offset (e.g. 112) but yours lands at off-by-4 (108),
    the original type carried 8-byte alignment. Declare the array inside a
    union with an f64 member (`#define name u.m` keeps the body unchanged)
    — reproduces the alignment hole with zero codegen change. Sibling of
    recipe #16's `f32 m[16]`-vs-`Mtx` frame-size note, for ALIGNMENT rather
    than size. (objWorldToLocalPos 96→100, with #31 whole-struct copy-out.)
    **Related frame lever — frame size tracks the COUNT of homed locals,
    even when codegen is otherwise identical.** A 64-vs-48 stwu delta with a
    byte-identical body = too many distinct locals homed to stack slots.
    Fold single-use block locals into their consuming expression (each
    −4/−8B) until stwu matches; a fresh local ADDS 8. Complements #67's
    probe method — the probe direction here is removing locals, not
    resizing buffers. (synthUpdateVirtualSamples 95.93→100 — also needed:
    test-via-global to unsplit the state web (addi lands straight in r30,
    kills a spurious `addi r3,r3,0`), switch dispatch, struct ent[vid] form
    (#18), OR operand swap (#66).)

76. **`int key = id;` (u16 param widened to an int local) fixes BOTH `cmpw`
    signedness AND a whole-function volatile rotation in one line.** When
    target compares a u16-derived value with SIGNED `cmpw` (yours emits
    `cmplw`) and the volatiles are rotated (r6/r7/r8 ↔ r7/r8/r6), the
    original held the param in an `int` local (one `clrlwi` at the copy).
    Semantically safe (both operands non-negative); the extra web shifts
    every volatile into target's numbering. Inverse direction of #58.
    (Sfx_FindTrigger binary-search 95.98→100.)

77. **Param saved-reg relocation: `void *` params + cast-assigned typed
    locals split the webs when same-type local copies get propagated
    away.** To reproduce a param coloring permutation (T: p1=r30 p2=r28
    p3=r29 vs C: r28/r29/r30), change the signature's pointer params to
    `void *` and copy each into a typed local with an explicit cast —
    local decl order then sets the coloring (first = highest free). A
    same-typed copy (`short *p2 = arg1;`) gets merged back and changes
    nothing; the cast is load-bearing. Pointer args are ABI- and
    caller-codegen-neutral so the header change is conservation-safe.
    Extends #16/babycloudrunner split-decls to params. Also works for
    plain-locals coloring: babycloudrunner_func0B 95.89→100 via void* param
    + split decls in target coloring order with assignments in target
    statement order. (camcontrol_getTargetPosition 95.96→98.42; remaining open
    residual: the PLACEMENT of `mr r31,r6` among the prologue copies is
    allocator-internal — emission order followed neither statement order nor
    cast-ness on the spellings tried; bank the partial and re-attack via #108.
    Same fn: sqrtf store-then-round
    `stfs f1; frsp f5,f1` vs round-then-store is also allocator-internal.)
    **#77 addendum — struct-container conversions (task #178): retyping an
    `int`/`u8 *` state param/local to the family struct pointer is
    byte-neutral on MOST fns but flips saved-reg coloring on high-pressure
    ones, and the FALLBACK is per-fn too.** fn_80174BFC needed the int param
    KEPT + inline `((T *)ext)->field` casts (pointer retype flipped its
    r23→r31 web); swarmbaddie_update was the OPPOSITE (inline casts
    regressed, typed local byte-exact). Order: typed local/param first,
    inline casts second, byte-verify every touched fn. Member access at
    constant offsets is otherwise codegen-identical to the raw cast forms;
    leave stride-walker loops and `base + idx*stride` arithmetic RAW (#18 —
    converting those changes isel). 30+ fns across 11 TUs converted
    byte-exact this way (Pushable/LandedArwing/PaymentKiosk/DbshSymbol/
    SeqPoint/VfpDragHead/Hagabon containers).
    **#77 round-2 addendum (task #180, ~20 containers incl. the engine-wide
    BaddieState):**
    (a) retyping an `int` state local to a pointer flips its null-compare
    `cmpwi`→`cmplwi` — launder with `if (((int)state != 0) ...)`;
    (b) `&state->field` as a call arg breaks the import's `(char*)base+K`
    address-CSE — keep the ORIGINAL arg spelling (`(char *)state + K`);
    the INVERSE bites too: converting matched raw-arith args (`st + K`
    timer args, `(f32*)(obj + 0x18)` vec args) TO `&state->field` /
    `&obj->anim.worldPosX` can CSE the member-address node into a hoisted
    saved-reg web (+1 saved reg, +1 instr) where the raw arith re-derived
    per site — and it is PER-FN (same spellings byte-neutral in init,
    perturbing in update; wmwallcrawler gold pass). VALUE access converts
    safely; ADDRESS-of-member args need a byte-gate per fn.
    DISCRIMINATOR (WM gold sweep): the hazard is SINGLE-LEVEL member
    addresses off a register-resident base (`&((GameObject*)player)->
    anim.worldPosX` for `player + 0x18`); a CHAIN-DERIVED member address
    (`&obj->anim.placement->posX` for `*(int*)&placementData + 0x8`) is
    byte-neutral — the trailing addi exists either way after the pointer
    load. Reliably-safe conversion classes from the same sweep: offset-0
    member respelling (`*(s16*)obj` → `obj->anim.rotX`, 10/10 sites incl.
    compound `+=` inside a hand-tuned 100% fn), accessor-macro
    `*(T*)((u8*)(state)+K)` → typed member access at whole-TU scale
    (firefly), and pointer→pointer PARAM retypes (`int* obj` →
    `GameObject* obj` — no #126 pool-class change; int→pointer is the
    risky direction). Also byte-neutral: widening an import-era NARROWED
    callee decl to the real signature when the added leading args are the
    caller's own pass-through params (`objRenderFn_8003b8f4(f32)` → the
    real `(obj, p2..p5, scale)` — full-arg calls compile to zero moves,
    recipe #9; killed the fn-ptr-cast noise at 6 sites via one wm_shared.h
    decl);
    (c) field signedness/width must mirror the original deref EXACTLY:
    a u8-array decrement (`sub[9] -= 1`) needs a u8 field to keep the
    `clrlwi` (s8 emits `extsb` under peephole-off); an int-deref'd flag
    word needs `s32`, not `u32` (cmpwi vs cmplwi on `(x & K) != 0`);
    (d) a `p = (int)state;` walker-alias cast after a retype is a recipe
    #36 trap (cast inflates the web; savegpr shifts) — and dropping ONLY
    the cast doesn't always recover: high-pressure fns are ALL-OR-NOTHING
    (if the typed local shifts savegpr, no partial conversion of that fn
    survives — revert it to raw and document; DIM2flameburst's whole
    explosion family + scarab's dll_CB_seqFn are reference-only this way).
    EXPECT the family's MAIN update/SeqFn to be the all-or-nothing holdout
    (dll_CB_seqFn, DIMSnowHorn1_update, hightop_update) — convert the rest,
    keep this one in its raw-cast form (the conversion regresses it), and
    treat its coloring as an open #108-family problem rather than forcing the
    container retype;
    (e) variable-indexed member arrays (`s->segmentLit[j]`) CAN convert
    byte-exact — the #86 index-fold concern doesn't automatically bite;
    (f) shared ENGINE records discovered by containerization: BaddieState
    (0x410, include/main/dll/baddie_state.h — obj+0xB8 prefix for
    gBaddieControlInterface/gPlayerInterface actors incl. player.c's
    "inner"; converted in scarab/mediumbasket, adoption pending elsewhere)
    and the gCarryableInterface record (lbl_803DCAC0; mmp_moonrock/
    sandwormBoss/CFBaby/gasvent/groundAnimator) — when a "family" state's
    offsets recur across TUs, check for an interface vtable taking the
    state pointer before defining a private struct.
    **#77 CROSS-CLASS INTERLEAVE — a real (small) dent in the #108 frontier
    (coloring-A, fn_8029560C → 100).** When target keeps a PARAM in the
    HIGHER saved reg ABOVE a single-def copy local (e.g. target state(param)
    =r31, *state(deref copy)=r30; ours inverts), lift the param into the
    copy pool: change the signature's pointer param to `void *` and copy it
    into a typed cast-local (`int *state = (int *)statep;`). Both the cast-
    copy and the deref value are then single-def copies in the TOP block, and
    DECL ORDER within the copy pool sets r31/r30. ORDERING RULE observed: this
    fn colored FIRST-CREATED → r31 (declare `state` cast-copy BEFORE the
    deref value `v` to land state in r31) — opposite of #108's E1 "last-
    created → r31", so the within-copy-pool direction is PER-FN; A/B both decl
    orders. ABI-neutral (pointer param, regs assign by class). One data point
    on the #108 within-class/cross-class ordering frontier.

78. **Triple-multiply REGROUP: `A * lbl * conv` → `A * (lbl * conv)` —
    Ghidra always left-flattens; target groups the constant-by-conversion
    product.** When target computes `fmuls f1,f0(lbl),f1(conv)` FIRST and
    then `fmuls f0,A,f1`, the left-assoc import form `A * lbl * conv`
    evaluates `(A*lbl)*conv` and mismatches at EVERY such site. Add explicit
    parens to group the const×conversion subterm. Scales catastrophically:
    147 sites in Effect20_func04 alone (+5pp in one sed), 13 more in modgfx.
    Diagnostic grep: `\* lbl_\w+ \* \(f32\)\(s32\)randomGetRange`. Sibling
    of #59 (statement-level reorder for fadds chains) for multiply chains.
    (dim_partfx/modgfx Effect family, task #147.)

79. **Import-dropped/mangled SWITCH CASES: reconstruct via jump-table
    decode — the canonical fix for big `delete` regions in a stream
    alignment.** When a mnemonic-level difflib alignment (recipe #70
    method) shows target-side delete regions of 20+ instructions, the
    Ghidra import dropped (or gutted) whole case bodies. Procedure, proven
    on Effect3_func04 90.8→99.75 and Effect2_func04 93.5→98.0:
    1. Find the fn's `jumptable_8xxxxxxx` in the auto_07 data asm
       (`build/GSAE01/asm/auto_07_*.s`); the dispatch's `subi rX, rY, BASE`
       gives the case-value base; table index i ⇒ case BASE+i, entry ⇒
       fn-relative block offset.
    2. Map the missing block offsets to case values; insert/repair the
       cases at the position matching target block order (#13).
    3. Transcribe bodies from target asm. Watch for the import-corruption
       signatures: (a) real float-compare conditions (`lbl == *(f32*)
       (param_3+4)` fcmpu) replaced by `param_3 != 0`; (b) `FILL` macro
       calls + param_3 field reads silently dropped; (c) global TABLE reads
       (`(s16)lbl_8031xxxx[i]`, lwz+extsh+sth) corrupted into
       param-relative garbage (`*(int*)((char*)param_1 - 0x980)`); (d)
       dropped `f44`/`f48` constant stores; (e) `X = rand(); X = X + K;`
       double-stores collapsed into one statement (or vice versa — read
       target's store count); (f) faithful DEAD double-stores in the
       original (`f44 = 0x81088000; f44 = 0x1000000;`) — keep both;
       (g) full case-content SCRAMBLE — bodies attached to the WRONG case
       labels (verify each case against its jump-table block, not just
       presence); (h) garbage constant placeholders (`f44 = 0xff` fills)
       and single-nibble value bugs (0x80480108 vs 0x80280108) — re-derive
       every lis/addi constant from target bytes; the SAME nibble corruption
       often repeats across sibling sites (one bad transcription propagated —
       Effect4 had 5 identical 0x8028→0x8048 sites, Effect1 had 2), so when
       you find one, grep the fn for its pattern; (i) per-compare
       randomGetRange RE-ROLLS — `if (rand()==0) … else if (rand()==1)`
       where target rolls ONCE into an int local (different RNG stream =
       behavioral bug); (j) spurious local-struct construction — import
       builds an `es`-style struct + field copies where target passes
       `param_3` to the helper directly; (k) dropped `<<8` shifts on color
       constants + values shifted up one field slot; (l) in-place
       WRITE-BACK clamps gutted (`if (*(f32*)(param_3+4) <= lbl) *(f32*)
       (param_3+4) = lbl;` then use — the import dropped the caller-visible
       store, a game-visible data-corruption bug). (m) embedded
       ++/-- SPLIT into statements -- 'lha;addi;sth' interleaved INSIDE an
       address computation (load, inc, store, then the OLD or NEW value
       consumed by the surrounding subscript) = an embedded post/pre-inc on a
       narrow lvalue the import decompiled into separate statements; the
       split costs spurious extsh + reload divergence at EVERY such site.
       Write '(*(s16 *)(q+0x22))-- * 8 + 4' / 'hh[++(*(s16 *)(q+0x22)) * 4
       + 2]' back as embedded ops (post-inc: slwi of the PRE value; pre-inc:
       store-forwarded extsh-at-use of the NEW value). Demonstrated 4x on
       the pi_dolphin heap module (fn_8004AAD4/B218/B31C/AB5C -- two
       byte-exact 100s; the module's author used the idiom pervasively).
    Audit signature counts for the remaining modgfx fns are in task #147.

80. **Saved-reg HOIST-COUNT cap CRACKED — the "one extra saved reg +
    `mr rX,rY` copy at the prologue" class is a named-pointer-local
    USE-BINDING SPLIT, fixed by cast-laundering the init + spelling the
    call's PLAIN-pointer arg as the same laundered constant.** (task #149;
    foodbag dll_8X family: 12 fns lifted, 10 to 100% — 7C 7D 7E 82 83 84
    85 87 88 89 8A 8F 90.) The mechanism, nailed by /tmp probe-batch
    bisection (recipe #74 method):
    - `u8 *base = lbl_X;` (named local init'd from a symbol address) makes
      MWCC split uses into TWO webs: body offset-uses (`base+K` derefs/
      derives) bind to the SYMBOL-CSE web; the trailing call's PLAIN value
      arg (`f(..., base, ...)`) binds to the VAR web. Both live from the
      prologue -> can't coalesce -> `mr r8,r7` copy at top + one extra
      volatile consumed -> the lowest-ranked constant web (e.g. `li 2`)
      overflows into a SAVED reg (`li r31,2` vs target `li r12,2`),
      shifting every saved slot (savegpr_24-vs-23 cascade, 40-150 bytes).
    - DIAGNOSIS: prologue shows `lis r7; addi r7,r7,lo; mr r8,r7` where
      target has `lis r7; addi r8,r7,lo` (separate-dest, single web), plus
      one extra `stw r2N` save. Bisection probes: removing the base+K
      DEREF uses or the plain call arg makes the split vanish; register
      pressure is NOT the cause.
    - FIX (all three parts, byte-exact on dll_87 97.17->100): (1) launder
      the init: `u8 *base = (u8 *)(int)lbl_X;` — ALSO corrects the
      saved-reg RANK rotation (the addi-derived `base+K` web then outranks
      the li-consts for r31, matching target; recipe #36's cast-priority
      effect); (2) spell the call's plain-pointer arg as the IDENTICAL
      laundered expression `(u8 *)(int)lbl_X` instead of `base` —
      value-numbers onto the same web -> `mr r6,r8` from the shared reg,
      no copy web. A BARE `lbl_X` arg also unifies but leaves the saved
      rank rotated; `base+K` args stay spelled via `base`. (3) check the
      import-guessed stack-array size (recipe #67(b)) — dll_87/89/8F
      needed entries[33]->[32] (frame -912 vs -896 was the tell).
      NEW SUB-CAUSE (CFBaby): an import-guessed `u8 buf[N]` address-taken
      scratch array + a second `&local` call-arg can carry a 16B PHANTOM
      temp reservation that a STRUCT-TYPED local of the TRUE type
      eliminates (`ObjAnimEventList ev;` for the guessed `u8
      animScratch[0x34]`) — check for a real struct behind u8 scratch
      buffers BEFORE size-probing.
    - NEGATIVES (these spellings are exhausted — try a different axis, not
      these): `#pragma optimization_level 3`/`2` are
      byte-identical to 4 (only <=1 changes codegen — and destroys all
      CSE); struct-overlay member access does NOT hide the symbol fold;
      `(int)` cast at the ARG with an uncast init keeps the split;
      `base + 0` keeps the split; MP4 has no instance of the shape.
    - SAME-MECHANISM SIBLING: a named `f32 t = *(f32 *)(p + 8);` local
      loads at the ASSIGN position while target loads lazily at first use
      (CSE temp) — inline the deref at every use and let MWCC CSE it
      (dll_85 95.97->100, with per-arm `p += 3` phi (#93b) + s16-alias
      (#30)). Mirror of the base-web story for FP loads. Pair with #66/#5
      (p-decl-BEFORE-e flips the e/p coloring — worked on dll_81/85 where
      decl swaps were inert BEFORE the web fix) and #30 (the alias must be
      a DECLARED named local — inline `((int*)base)[i]` casts do NOT
      work — for `add base; lwz disp` table reads, dll_83 95.21->100).
    - Bonus same-sweep import bugs: dll_7D returns the dispatcher result
      (void->int, #148 class — tell: target uses r4 not r3 for a post-
      bctrl scratch); dll_8F e[5].layer = 1 in v1.0 (import had v1.1's 2).
    - Residuals still open after this recipe: value-ISEL
      `addi r0,rX,-1` deriving 0xFFFF from a live 0x10000 where target
      re-materializes `li r0,-1` at ONE of two identical sites (dll_81
      99.86; -1/0xffff/65535u/(s16)-1 inert so far — needs a VN-key lever
      like #114);
      `buf.cmds = e` storing via `mr r0,r31; stw r0` in target vs our
      direct `stw r31` (dll_86 99.53; copy-var and call-parking inert —
      ⚠️ CRACKED, task #157: the `(FbCmd *)((u8 *)&buf + 0x60)`
      re-derive spelling (#93a/#62 family) reproduces the mr-r0;
      dll_86 → 100);
      the `addi r0,rH,lo; mr rX,r0` saved-home materialization
      (dll_8B — the open triage-table residual, NOT this class).
    - LOOP-INVARIANT pragma lever (fuelcell_render, CF sweep): when
      target re-derives loop-invariant ADDRESSES per iteration and
      launders/decl-perms/#126 are all inert, wrap the fn in
      `#pragma opt_loop_invariants off` ... `reset` — LICM itself is the
      mechanism (functional in GC/2.0 per the #108 pragma note). Try it
      before the scalar-split below.
    - LOOP-INVARIANT variant (tumbleweedbush_update 97.43->99.06): when
      OURS hoists a loop-invariant STACK address (`&hitInfo[1]` passed to
      a call inside a loop) into a saved reg (`addi r28,r1,12` pre-loop +
      `mr r3,r28` per iter) while target re-derives `addi r3,r1,12` per
      iteration, the lever is the LOCAL'S SHAPE, not the use spelling:
      split the `int hitInfo[3]` array into SCALAR locals (`int hitExtra;
      int hit1; int hit0;` — reverse decl order for the #5 stack offsets)
      and pass `&hit1`. `&scalar` is a direct frame reference (no
      hoistable web); `&arr[K]` is an address COMPUTATION that LICM
      promotes regardless of spelling (natural form, (int)-cast form, and
      #55 block-scope local all tested inert). Import-written `int buf[N]`
      + `&buf[K]` call args inside loops are the tell.
    - PROJECT-WIDE SWEEP RESULTS (task #158, 75 prologue-signature hits
      A/B'd): 7 wins (linkb_levcontrol_init ->100%, dll_93 +3.0, dll_61
      +2.5, dll_7A +1.3, dll_98 +1.0, dll_AA +0.7, AudioStream_Play +0.5),
      rest resist. The signature (`addi rV,rH,lo; mr rS,rV` in current,
      direct in target) is NECESSARY-NOT-SUFFICIENT; resist sub-shapes,
      A/B before keeping:
      (a) WALKED loop pointers (`p++`/`p+=K` on the base) resisted EVERY
      spelling tried — laundering, second-local split, scalar-extern override,
      init reorder all inert or regress (fn_80204098,
      CameraShake_ApplyRadial, renderParticles' walk set).
      Allocator-internal so far; an open sub-shape awaiting a walked-pointer
      coloring lever (recognize by the `p++` walk, bank the partial).
      (b) ARRAY-typed externs (`extern T sym[]`) without a plain/offset
      use SPLIT resist decl laundering (dbstealerworm st — regressed).
      (c) Some textually-identical SPLIT siblings still regress (dll_63,
      dll_7B: both-parts and arg-only WORSE, decl-only inert) — their
      real residual is another class and the launder perturbs it.
      Decl-only laundering (without an arg rewrite) DOES win on some
      OFFS-only shapes (dll_61, dll_98) — try it cheaply before the
      full 2-part fix.

81. **fcmpo-on-RELOADED-value cap CRACKED — `*(f32 *)&lbl` launder on ONE of
    the clamp constant's two references flips the reload/limit register pair.**
    (task #150; fn_801CEA14, dim2icicle_update, wctemple_update,
    cclevcontrol_update, dll_1DB_update, fogcontrol_update — 5 to 100%.)
    The "compare on a RELOADED value" half of the FP fcmpo family (the part
    recipe-table's temp_t sub-recipe explicitly didn't reach) is NOT
    allocator-internal. Signature: clamp-to-same-constant after a compound
    update —
    `x op= k; if (x > lim) x = lim;` — target emits `lfs f1,off(rN)` (reload)
    + `lfs f0,lim` + `fcmpo cr0,f1,f0` + `stfs f0`, while the natural C gives
    the SWAPPED pair (`lfs f0`/`lfs f1`/`fcmpo f0,f1`/`stfs f1`). Mechanism:
    when BOTH references to the limit are spelled identically, MWCC's
    symbol-CSE web for `lim` (2 uses: compare + store) gets f1 and the field
    reload gets f0. Spelling ONE reference as `*(f32 *)&lbl_X` — store side
    (`x = *(f32 *)&lbl_X;`) or compare side (`if (x > *(f32 *)&lbl_X)`),
    either works — keeps the single-load CSE but flips the coloring to
    target's reload=f1/limit=f0. Byte-exact, zero instruction change.
    - DISCRIMINATOR vs the temp_t sub-recipe (95-98 triage table): if target
      reloads the field fresh (`lfs` from the same offset right after the
      `stfs`), use THIS recipe; if the compare consumes the arithmetic result
      with no reload, use temp_t.
    - The 3-constant variant (`if (x < lim) x = OTHER;`) matches naturally —
      only the store-the-compared-constant form diverges.
    - Probe notes (these spellings are exhausted for this exact divergence —
      reach past them): ternary `x = (x > lim) ? lim : x;` gives the
      right registers but the wrong branch shape (+fmr +b — 2 instrs bigger);
      `(f32)lim` cast, `+lim`, parens, block-scope extern redecl, v/L locals
      in every order, goto/inverted-else/do-while forms, volatile reload,
      and `(int)`-cast of the store base are all inert (13+11 /tmp probes).
    - When the compared constant is MULTI-USE across the fn (e.g. 0.0 used
      10×), A/B compare-side vs store-side laundering and measure — webs
      interact (exploded_stepDebrisPhysics: compare-side +1.03, store-side
      +0.76, BOTH stacked worse than either).
    - Residual NOT this class: reload lands in f1 but target wants f2 with a
      precolored call-arg web nearby (cfprisonguard_render 99.79). ⚠️
      RESOLVED — that one was recipe #65 (a Ghidra-dropped f32 call arg:
      the reload IS the arg load, CSE'd into the f2 arg register); see the
      #82 census-overturn note. A "1-use" reload feeding a compare right
      before a bl deserves a #65 hidden-arg read before any coloring work.
    **IN-LOOP HOISTED-CONSTANT extension (CF sweep, scarab loops): laundering
    a loop-hoisted compare/multiply constant (`*(f32 *)&lbl`) re-ranks the
    whole loop's FP volatile rotation in count-up scan loops (~12 instrs per
    loop from one launder) — try before banking a loop-wide FP rotation.**
    **STORE-CLAMP DISCRIMINATOR (~20-AB calibration, miner-4) — the launder
    is RELIABLE iff the clamp STORES the constant back AND the swap is a CLEAN
    SAME-REGISTER pair.** This generalizes #81 from the reload case to all FP
    clamps and tells you up-front whether to bother:
    - WORKS: a STORE-clamp — `if (x op lbl) x = lbl;`, or decrement/`fmadds`-
      then-`if (x op lbl) x = lbl;` — where the swapped `fcmpo` is a CLEAN
      same-register pair (target `f1,f0` vs current `f0,f1`, i.e. `to[-2:] ==
      co[-2:][::-1]`). Launder ONE reference (compare-side `if (x op *(f32 *)&
      lbl)` OR store-side `x = *(f32 *)&lbl;`) — A/B both, the winning side
      varies per fn. Confirmed →100 or +gain on ~15 fns (ccriverflow_init,
      sh_levelcontrol_update, pinponspike_update, DIMboss_update, fn_8014EE8C,
      gf_levelcon, fn_801EA240 ×6, dim_levelcontrol_update, …). Multi-clamp
      blocks with INDEPENDENT constants per clamp (velocity x/y/z to a shared
      [lo,hi] pair, fn_8014EE8C) launder all-at-once cleanly.
    - RESIST (bank, don't grind — these need a different lever): (a) named-
      `lim` embedded-assign clamps `if (x op (lim = lbl)) {…}` — laundering the
      init or removing the local cascades a whole-fn regression (FireFly,
      dll_2A3_update). ⚠️ **(a) CRACKED — DOUBLE-EMBED with a named field
      value:** `if ((a = FIELD) op (lim = lbl)) { FIELD = a ± step; ... }`
      (fresh `f32 a;` declared after lim). The two embedded defs number
      DESCENDING (field=f2, lim=f1 = target) and the body's reuse of `a`
      reproduces target's reuse of the compare reg. Both former resist
      examples → 100 (FireFlyFn_801f4f88, dll_2A3_update). The init-launder
      `(lim = *(f32 *)&lbl)` stays inert on this shape — but for the
      SEPARATE-STATEMENT named-temp variant (`fVar1 = lbl; if (fVar1 ==
      field)`) the plain #81 init launder `fVar1 = *(f32 *)&lbl;` IS the
      fix (fireflyLantern fn_80154870 → 100; embedding there swapped the
      whole compare — wrong direction). Read the import's form first;
      (b) NO-store reload compares (`if (x <= lbl) result=1;`
      / `Obj_FreeObject` instead of a store — cmbsrc, arwingandrossstuff);
      (c) COMPUTED-limit compares (`fcmpo x, (base - delta)` — dll_219); (d)
      whole-register SHIFTS (target `f2,f1` vs current `f1,f0` — NOT a same-
      register swap; this is the #82 expression-temp tier); (e) AMBIGUOUS
      multi-clamp blocks where ONE constant is SHARED across swapped AND
      already-matched clamps (camslide_update lbl_803E16E8 ×4, DBSH_Symbol_SeqFn
      lbl_803E50EC ×7, fn_8019C784) — laundering the shared constant flips the
      matched siblings too; high regression risk, only attack with per-site
      mapping. Tool: `tools/fcmpo_swap_audit.py` enumerates the candidates and
      flags store-clamps.

82. **The "FP volatile reg-number permutation" tier DECOMPOSES — classify
    by WEB KIND, then attack the right way.** (task #153; 3 more fns to 100%,
    1 still open.) The old triage-table entry ("decl order, temp locals,
    statement order, compare-direction flips all invariant — skip on sight")
    was too broad and steered workers away from winnable functions.
    Sub-classes, by what kind of value-webs hold the permuted regs:
    - **Symbol-CSE web in the pair (a multi-use named constant)** →
      recipe #81 launder (`*(f32 *)&lbl_X` on ONE reference) re-ranks it.
      Works for the local-variable clamp variant too (`v = (f32)(int)b;
      if ((f32)(int)b < lbl) v = lbl;` — launder the assignment):
      dll_127_init + kt_torch_init → 100%. For MULTI-symbol permutations
      (4-const matrix-build), launder combinations move the whole rank
      ordering — A/B which reference(s); each (symbol, ref-position) pick a
      different permutation (fn_8004E0FC 99.65→99.82, B20@both-m1e8-refs;
      enumerate p-variants and keep the best).
    - **Two NAMED f32 locals swapped (t/dur)** → plain DECL-ORDER swap (#5/
      #16) DOES flip FP named-local pairs (fn_8015EA48 → 100%). The triage
      "decl order invariant" claim is wrong for this sub-class — always try
      the swap first.
    - **EXPRESSION-TEMP pairs (no name, no symbol): conversion biases (@lfd),
      fctiwz results, stack-array element reads** → the remaining OPEN
      sub-class (allocator-internal on every lever tried so far). Inert
      across 25+ variants: decl-order, named
      locals, block-locals (#66), launders on adjacent webs, statement
      reorder, term-order swaps (canonicalized), pointer-form stores,
      embedded assigns (LanternFireFly_func0B 12 forms, exploded_
      seedDebrisMotion 6, Curve_SampleSegmentPoints Z-block 3, drawTexture
      fctiwz; cfprisonguard_render reload-f2 left this list — it was a
      #65 dropped arg, see the overturn note below). The residual is 1-8 bytes —
      bank it, recognize the signature, and re-attack when a lever for
      unnamed expression-temp coloring lands (the #114 conversion-node
      splitter is the closest existing tool to try).
      ⚠️ CLASS-MOVE MODEL (decoration11a → 100, superseding the earlier
      "use-count rank" diagnostic — that model was WRONG): FP-volatile
      coloring is WEB-CREATION-ORDER first-fit from f0, and queue-jumps
      are produced by moving values BETWEEN classes, never by reordering
      within one: an EMBEDDED DEF in the condition (`if ((px =
      localPos[0]) < bMin)`) moves a value temp→named (a plain named init
      from a STACK SLOT is #94 value-tracked/copy-propagated away — which
      is why entire decl matrices test byte-identical: every "named
      arrangement" silently degenerates to the temp form; CHECK FOR THIS
      before trusting any inert battery); un-naming an if/else result
      into a TERNARY JOIN moves it named→temp (the join temp ranks in the
      temp class and the arm value coalesces into it). decoration11a
      needed both, plus fn-scope bMax (block-scope regresses the
      coalesce). LIMIT: class-moving levers are verified INERT for the
      SAVED-FP pool (deathseq_update banked 99.785 — within-class order
      there is the #108 IR-internal frontier).
      4th member — NAMED-WEB PRIORITY INVERSION (mtxRotateByVec3s,
      probe-characterized via probe_battery): target gives the NAMED
      multi-def temps (u, zero) the LOWEST volatiles (f0) and the unnamed
      expr temps HIGHER — the exact inverse of #107's temp-class model.
      The #85 double-def chain (u = t1*cx; u = sxsz - u) is load-bearing
      for EVAL ORDER (single-def/inline spellings fold and reorder — keep
      it); the reg assignment itself resisted decl-position x3 (#61b),
      un-naming, w-splits, single-def forms. Same family: Vec3_Normalize
      (div-result f2-vs-f1; recycle/embed/launder/decl x4 inert),
      dim_bossgut fn_801D29E4 (sx/scale pair, launders x3 + named-const
      x2 inert). Recognize: named FP temp in f0 in TARGET with your
      compile putting the expr temp there instead.
      ⚠️ 4th member PARTIALLY CRACKED — BLOCK→FN-SCOPE PROMOTION of the
      OTHER locals is the missing lever (cfwindlift fn_8019C784 → 100,
      unit 100.0, byte-exact 395/395). The named multi-def `scale`
      (symbol init + conditional `* lbl` redef + one use) sat at f3 where
      target has f0, inert under decl order, init launders, register kw,
      (f64) sandwich, comma-embed, web-split, scope moves of scale
      ITSELF, and the whole pragma battery. The flip: promote BOTH
      if/else arms' block locals (the gb==0 arm's lim/t/d AND the gb arm's
      v/thr) to fn scope, declared BEFORE the f32 group — EACH ARM'S SET
      ALONE IS INERT, both together send scale to f0 and the temps to
      target's f1-f3. Deletion probes proved scale is always colored
      after temps as a named web regardless of single/multi-def — the
      promotion changes the surrounding web census, not scale's class.
      Finishers that rode along: #107 FP un-naming of the arm local `c`
      into `factor` (coalesces the fsubs result into factor's f3) and a
      #81 store-side launder on the final clamp. On the next 4th-member
      fn, battery scope promotions of the arm-local SETS (incl. the
      both-arms-at-once combination) before banking. Retry candidates:
      mtxRotateByVec3s, Vec3_Normalize, fn_801D29E4.
    - Sub-class-2 EXTENSION: when the swapped pair is two named f32 locals
      init'd from DIFFERENT symbols (`f1 = lblA; ... f0 = lblB;` store-burst)
      and the decl-order swap is INERT, the #81 launder on ONE init
      (`f1 = *(f32 *)&lblA;`) still flips the pair (fn_800A0478 98.37->100).
      Try decl-swap first, launder second, before classifying as sub-class 3.
    - Diagnostic: reduced /tmp probes do NOT reproduce these permutations —
      the coloring depends on whole-function web pressure; A/B in the real
      TU. ⚠️ CORRECTED (CF campaign): SOME instances DO reproduce in a
      probe (cfprisonguard_render's reload-f1-vs-f2 and cfwindlift
      fn_8019C784's scale-f0 inversion both reproduce standalone with the
      real headers) — probe first; a reproducing probe gives a 2s
      brute-force harness.
    - EXHAUSTIVE-ENUMERATION NEGATIVE (cfprisonguard_render, CF campaign):
      the expression-temp FP digit is invariant under ~50 source
      structures (named/compound/embedded/split temps, launders on every
      const ref, (f64) fcmpo promotion nodes, static-inline helper
      factoring, both visible-block shapes), 15 opt pragmas (incl.
      register_coloring/opt_lifetimes/O1/O2/O3/optimize_for_size), AND all
      20 bundled GC compiler versions (1.0-3.0a5.2 — every one emits the
      same wrong digit on the minimal reproducer). The class is therefore
      NOT version-tunable and NOT C-surface-reachable on such fns; the
      divergence lives in compiler-internal IR state the TU content does
      not determine (the #108 fn-global-state phenomenon, FP edition).
      Bank on sight once the probe confirms invariance; do not re-spell.
      Re-confirmed post-#119: the recycling lever (named const var reused
      for the reload), double-embed `(a = field) < (lim = lbl)`,
      single-embed, and reload-via-t forms are all invariant at f1 too.
      ⚠️ ANOMALY VERDICT OVERTURNED — cfprisonguard_render → 100: the
      digit was never allocator-internal; the original call passed ONE
      MORE ARGUMENT (objParticleFn_80099d84 really takes (int, f32, int,
      f32, int) per the fx/DR shared headers; the import's 4-arg decl
      dropped the f32 c = sub->alarmRamp). The arg load CSEs with the
      clamp compare's reload, precoloring the web into the f2 ARG
      register with zero extra instructions — recipe #65, not #82. The
      ~50-spelling battery could never reach it because no spelling of
      the EXISTING args changes the call's register demand.
    - ⚠️ RETAIL-ANOMALY CENSUS (the conclusive instrument for this class,
      CF research program): for cfprisonguard_render's banked digit, a
      corpus census of the exact 1-use [stfs fX,K(rN); lfs fY,K(rN);
      lfs const; fcmpo; no further fY use] shape found TARGET emits f1
      at 311 of 312 sites game-wide - the prisonguard site is the SINGLE
      f2 in the entire retail binary (its 5 census hits are one site
      under 5 historical split names), and our toolchain emits f1 at
      147/147 sites. A construct that no source spelling, pragma, or
      compiler version reproduces AND that the retail compiler itself
      emitted exactly once in the whole game is best explained as a
      non-deterministic retail-compile anomaly (host-state-dependent
      allocation, cf. the known IDO uninitialized-memory class), i.e.
      likely permanently unmatchable under deterministic re-compilation.
      METHOD (reusable): when a banked residual survives exhaustive
      enumeration, census the shape across build/GSAE01/obj - if target
      itself is near-unanimous AGAINST its own choice at the banked
      site, reclassify the residual as retail-anomaly and stop spending
      on it. Census script pattern in the CF-campaign commits.
      ⚠️ METHOD CAVEAT (the prisonguard overturn): a census shape
      filter like "no further fY use" is BLIND to arg-register liveness
      into a following bl — the one "anomalous" f2 site in the game was
      target CSE-ing the reload with a call's f32 arg the import had
      dropped (#65). Before trusting a retail-anomaly verdict on a
      "1-use" value near a call, read the callee's REAL signature across
      sibling decls (#84 arbitration) and check whether the odd register
      is the next unclaimed arg slot. "Anomalous singleton" should first
      be read as "this site has a construct the filter can't see."
      GUARDIAN COUNTER-RESULT (same instrument, opposite verdict): the
      obj-copy-vs-extra-copy saved-reg ORDER censuses at ~91% obj-BELOW
      in BOTH corpora (T 846:76, ours 817:86) - target's cfguardian
      layout is the COMMON case and our compile is the ~10% deviant, so
      that rotation is SYSTEMATIC and in-principle source-reachable
      (unlike the render anomaly). ⚠️ RESOLVED — the census read was
      right: the obj-pusher construct was the import's 19 no-op
      `(int)obj` casts at call args (#36 burst rule; cfguardian_updateMain
      94.50→99.31). When OUR compile is the census deviant, hunt for an
      import-only IR construct (cast noise) before any allocator theory.
      The same census also explains why the in-repo oracle (lightning)
      shows f2 legitimately: there the reload web is 2-USE (the arm's
      compound += CSE-reuses the compare load - fadds f0,f2,f0), a
      different, fully reproducible shape.

83. **Fresh-slot paradox CRACKED (task #151) — MWCC's conversion-temp pool
    is flushed by STATEMENT-level control-flow joins, NOT by ternary
    expressions; plus the co-located CSE divergences that actually move the
    score.** Test bed: drawHudBox 98.65->100, fn_801EE668 97.04->99.87,
    fn_8022AECC 98.27->99.81 (all committed). The allocator model, mapped
    by /tmp probe-batch:
    - int<->f32 conversion scratch (xoris/0x43300000 pairs, fctiwz stfd)
      allocates FRESH ASCENDING 8B slots through straight-line code and
      across CALLS (bl does not flush). The free-list is recycled (LIFO)
      only after a statement-level JOIN: `if`/`if-else` statements,
      `&&`/`||` expression-STATEMENTS, and discarded-result ternaries all
      flush; a ternary whose value is ASSIGNED (`x = c ? a : b;`) does NOT
      flush — branches are emitted but the pool keeps growing. Verified
      oracle: lightning_init (100%) has branch-separated fresh slots from
      `(x & N) ? 1 : 0` materializations and lives in our own tree.
      ⚠️ FLUSH TRIGGER SHARPENED (fn_801EE668 re-characterization, ~70
      probes): the pool is flushed by a conditional arm containing a
      LIVE-IN VARIABLE REDEFINITION or a MEMORY STORE — NOT by the join
      itself. Arms defining only fresh locals, EMPTY arms, and arms
      containing conversions do NOT flush. Classify the arm contents
      before assuming "if = flush".
      ⚠️⚠️ AND THEN CRACKED OUTRIGHT (fn_801EE668 99.87→100, unit →
      100.0; the SAME edit took WCPushBlock_UpdateRideTilt 99.86→100):
      the ARM'S ARITHMETIC SPELLING flips the allocator between
      LIFO-recycle and BUMP mode. The 16-bit wraparound clamp written
      compound (`d -= 0xFFFF;` / `d += 0xFFFF;`) lets the pool recycle
      at the join; the TWO-OPERATION form `d = (d - 0x10000) + 1;` /
      `d = (d + 0x10000) - 1;` — same value, and exactly target's
      `addis rX,rX,-1; addi rX,rX,1` decomposition — keeps the pool in
      bump mode: every conversion gets a fresh ascending slot, the frame
      grows to target's, all sp-offset immediates align, clamp
      instructions unchanged. Found via the in-repo oracle: sibling
      fn_801BEEA0 (mmsh_waterspike.c) spells its identical angle clamp
      `(turnDelta - 0x10000) + 1`. When target shows fresh-ascending
      slots around if-shaped wrap-clamps, try the two-op spelling BEFORE
      any ternary restructure (the ternary forms pay join taxes this
      form avoids). The "open #67(c)/#83 threshold" framing of this case
      is retired.
      Related micro-law from the same dig: MWCC hoists a FIRST-USE FP
      constant load UP past exactly ONE assigned-ternary region (with N
      consecutive assigned ternaries the lfs lands after ternary N-1).
    - So "target slots fresh-ascending but if-shaped clamps sit between
      conversions" => the ORIGINAL spelled those clamps as ternary
      ASSIGNMENTS. Constant-arm nested clamps
      (`v = (v < lo) ? lo : ((v > hi) ? hi : v);`) coalesce IN-PLACE
      (identical branch shape, score-neutral-or-positive — fn_8022AECC's
      iv clamps +0.03, fn_801EE668's v clamps neutral with +16B frame).
      Variable-arm chains (`d = (d > K) ? d - X : d;`) pay a one-time
      `b`+`mr` web-transition at the FIRST ternary of each chain (the
      second one coalesces in-place) — costs more than the slots gain
      when target shape is the in-place if-form; A/B per site and keep
      the ifs when ternaries net-lose.
    - The slot-offset residual ITSELF is nearly objdiff-free (~0.1-0.2%):
      do NOT chase the frame for its own sake. The real score in this fn
      class is in the co-located divergences:
      (a) **fresh-reload laundering** — target RELOADS a field for its
          `(f32)` conversion instead of CSE-ing the earlier `(u16)`/int
          read (tell: extra `lha`/`lwz`/`lfs` of the same offset in
          target). Spell the conversion read as a formally-distinct tree:
          `(f32)*(s16 *)(int)(obj + 1)` or `*(int *)((u8 *)p + 0x350)`.
          The `(int)`-on-the-SUM spelling is web-priority-NEUTRAL;
          `(int)obj`-on-the-BASE swaps r30/r31 coloring (recipe #36/#80)
          — avoid. `volatile` also works but is semantically heavier.
          One laundering fixed a whole volatile-permutation cascade
          (fn_801EE668 98.70->99.87; fn_8022AECC x7 sites +0.96).
          **LAUNDER DISCRIMINATOR (foxtrot-1, 5 fns):** launders bite on
          LOCAL/param-derived addresses (pointer params: fn_8014CF7C; local
          stack arrays: dbegg_update's `*(f32 *)((int)d + 8)` post-call
          reads — dropped 2 cross-call FP saves, frame -112→-96 exact) but
          are VALUE-NUMBERED THROUGH on GLOBAL-derived bases (ecsh's
          lbl_80326208 struct, WorldMap's lbl_803DD588, shrine counter
          chains — all inert across 4+ spellings each). Classify the base
          before probing.
          **Reload taxonomy, 3rd member — TWO-LEVEL chain reload:** when T
          re-reads BOTH the pointer and the field per test
          (`lwz r3,80(r31); lwz r0,68(r3)`) where C caches a typed pointer
          local, no field launder suffices — DROP the cached local at the
          test sites and inline the full chain
          (`((ObjModelInstance *)obj->def)->flags & 0x800`;
          loadCharacter 94.63→96.50).
      (b) **f32-temp split for eval order** — when current HOISTS a
          float load (timeDelta) above a conversion that target evaluates
          in source order, split the statement:
          `f32 t = (f32)(x << 3) / lbl; *p = -(t * timeDelta - (f32)*q);`
          (fn_801EE668 stmt1, +1.66).
      (c) **direct f32->s16/u16 assignment** — under peephole-off,
          `*(s16 *)p = (s16)(int)(fexpr)` AND `= (int)(fexpr)` both emit
          a spurious `extsh` (clrlwi for u16) after the fctiwz lwz;
          `*(s16 *)p = (fexpr);` (no int intermediate) emits none,
          matching target (fn_8022AECC x5 sites, 98.87->99.78).
          GENERALIZES to f32->u8 VARIABLES and to s16 locals: `u8 step =
          lbl * timeDelta;` / `s16 rot = f_expr;` (direct float
          assignment, NO (s32)/(u8)/(s16) casts) gives the raw fctiwz-lwz
          home with NO narrowing node -- per-use masks at compares
          (clrlwi+extsh for (s16)step), CLEAN compound `+=` (no mask
          before stb), `(u8)`-cast redefs land clrlwi direct in the home,
          and for s16: raw sth at plain stores with neg+extsh+sth only on
          a negated store. ANY explicit cast at the def executes the
          mask/extension there and breaks the whole shape (probe-verified
          battery; objlib playerEyeAnimFn_80038988 67.84->98.94 -- both
          instances in one fn).
          **INVERSE direction — when target HAS a dead conversion pair the
          direct store folds, route through an INT local.** A byte copy
          target compiles as `lbz; extsb; clrlwi; stb` (s8 source → u8
          dest with both conversions executed) folds to bare `lbz; stb`
          under EVERY direct-assignment spelling (u8=u8, u8=*(s8*),
          (u8)(s8) chains — front-end drops conversions dead at a
          truncating store); only `int t = *(s8 *)src; *(u8 *)dst = t;`
          keeps both nodes live (dimmagicbridge dll_19A_update → 100).
          Same int-local principle as the drgenerator (s16)t store cast.
    - Sibling discovery (drawHudBox): a no-op `(s16)` cast on ONE
      use-class of an s16 param (`(f32)(x + (s16)w)`) blocks extsh-CSE
      with the implicit promotions at the other uses — target re-extends
      raw w/h at the adds while keeping the extended copies live for int
      args => 2 more saved regs + frame -144->-160 and 100%. Same
      expression-node-identity principle as the laundering in (a).
    - Diagnostic for the class: current frame is N*8 short, current slot
      offsets repeat (uniq -c >= 2) where target's are all 1x, if-clamps
      sit between conversion statements. Fix order: reloads (a) first,
      eval-order (b), store casts (c), THEN A/B ternary forms per clamp.
      Also check the unit's peephole state (fn_8022AECC needed peephole
      OFF — tells: extsb after lbz, extsh before sth, param deref via the
      mr copy, recipe #68) and recipe #46 base bugs (its 0xac read was
      obj, not p).
    - Sub-patterns from the application sweeps (tasks #156/#159): (i)
      `outLights[(*outCount)++] = x;` — the post-increment-index spelling
      reproduces target's FRESH reload of the counter at the increment
      site where the expanded `n = *cnt; *cnt = n + 1; out[n] = x;` form
      CSEs it (modelLight selectBrightest/selectObject). (ii) Attenuation
      polynomials may be DISTRIBUTED in the original: `a + (d*(c*d) +
      b*d)` emits fmuls+fmuls+fmadds where `a + d*(c*d + b)` emits
      fmadds-first — read the multiply count off target. (iii) A
      score-vs-correctness TRAP: an import's semantically-suspect form
      can score HIGHER than the corrected one (cMenuRotateFn_80124d80:
      s16 diff with a dead >0x8000 test beats the live int form by 3.4) —
      flag such fns for a #46 logic audit instead of "fixing" them by
      score.
    - NEGATIVES (these axes are exhausted — spend new effort elsewhere):
      compiler versions 1.0-3.0a5 and
      -O0..4 (cmdline+pragma) all keep the join-flush with if-statements;
      opt_* pragmas/subflags, sched/peephole matrix, -inline
      auto/deferred/all, static-helper inlining, lang c/c++,
      -Cpp_exceptions on, &&/comma/goto/block-scope/register/volatile-int
      spellings of the clamps — all inert on the flush. MP4's fresh-slot
      fns are -O0 game code (cflags_game) — not an oracle for -O4 units.

**dtk `block_relocations` ranges currently in config/GSAE01/config.yml**
(recipe #73 instances — flag constants that coincide with code addresses):
`0x80180100–0x80180218` (fn_8017FFD0 interior), `0x80080108–0x80080120`
(randFn_80080100 interior), `0x80080208–0x80080214` (getCurSeqNo+4 /
fn_8008020C+4). When a new `sym+0xNNN` regex census
(`grep -rh "+0x" build/GSAE01/asm/main/dll/*.s`) surfaces more, verify the
addend lands mid-function (not at a symbol boundary) before adding a range.

84. **The "const-hoist-above-addr-arg" cap family is largely recipe #29 in
    disguise — the callee's REAL arg order puts the object/pointer FIRST.**
    Signature: T has `mr r3,rX` / `addi r3,...` BEFORE the `lfs` const loads;
    C emits the lfs first. The fix is the obj-first calling form:
    - `ObjAnim_AdvanceCurrentMove`: cast via the existing
      `ObjAnimAdvanceObjectFirstF32Fn` typedef (objanim.h) and call
      `(obj, speed, dt, events)` — cannonclaw_update 95.74→100 (one site
      also lifted siblings, total +0.037), ccqueen_update 96.55→100.
      MANY float-first call sites remain (grep
      `ObjAnim_AdvanceCurrentMove(lbl_`) — flip ONLY when the containing fn
      is a partial showing the mr-before-lfs shape.
    - `objBboxFn_800640cc`: real order is `(from, to, radius, ...)` per
      every caller outside main.c — dbegg_hitDetect 96.23→100.
    - `curves_getCurves`: real order is `(obj, x, z, outCount, queryAll)` —
      flipped decl+def+4 sites, fn_800E56A4 96→98.7, no regressions.
    - `objParticleFn_80099d84`: real order `(int obj, f32, int, f32, int)`
      per snowclaw/barrel callers; dll_80209FE0_shared.h carries a WRONG
      `(double,double,int,...)` decl — override block-scope (#57),
      bossdrakor_animEventCallback 96.09→99.10.
    When NOT an arg-order case (the same shape on Matrix_TransformPoint
    where the mtx IS already arg1 — wcfloortile, fn_802BC3F0), the residual
    is MWCC hoisting a multi-use const load above cheap addi/mr arg setup —
    embedded `(t = lbl)` in the arg position does NOT fix it (allocates a
    callee-saved FP and explodes) — that direction is an open 2-instr residual
    (the embedded-assign axis is exhausted for it; try a different lever).
    BUT for a const consumed inside an EXPRESSION (not a call arg), the
    embedded-assignment placement DOES work: `x / (sc = lbl)` forces the
    lfs AFTER the numerator (fn_8015F5B0 96.09→100, RandomTimer 96.3→99.8
    with the #32 acc-chain). Read the shape: call-arg hoist = open residual
    (embedded-assign won't reach it); expression-operand hoist = embedded
    assignment.
    **⚠️ MISCOMPILE HAZARD — an embedded assign in a CALL ARG whose value
    is REUSED by LATER args of the SAME call generates WRONG CODE under
    MWCC 2.0 (-O4): `f(p, (zero = lbl_A), zero, (one = lbl_B), x, zero,
    one - x)` emitted `fmr f5,f2` reading the STALE incoming param reg and
    `fsubs f6,f6,f4` reading an UNINITIALIZED reg — the embedded value
    never flows to the reuse sites. Compiler tell: warning "variable
    'zero' is not initialized before being used" on a variable that IS
    assigned (in the embedded position). The fn compiles and links —
    silently wrong at runtime. Never use #40-family embedded assigns for
    multi-use values inside one call's arg list; the safe scope is a
    SINGLE-use value or an expression operand outside arg lists.
    (modellight setSpecularAttenuation probes, task #163.)
    **SAFETY: NEVER flip the callee's DEFINITION — cast at the CALL SITE
    only.** The fn-ptr cast also preserves caller-side u8-RETURN masking
    when a same-TU DEFINITION conflicts with a donor's u8 extern after a
    TU merge (sc_totempuzzle_checkSolvedSequence, re-split campaign). Flipping modelWalkAnimFn_800248b8's def regressed the callee
    230 instrs (param homing order matters in the body); the
    fn-pointer-cast call form gets the caller win with zero callee risk.
    **Cross-caller arbitration: when 3+ other call sites agree on an arg
    order and one decl disagrees, the MAJORITY is target's real
    signature** (hitDetectFn_80065e50: attention.c had the lone
    float-first decl; objBboxFn_800640cc: main.c the lone radius-first).
    More confirmed obj/int-first signatures: hitDetectFn_80065e50
    (int obj first), gRomCurveInterface+0x4c slot (int,f32,f32,f32,f32*),
    modelWalkAnimFn_800248b8 (...,f32,int last two swapped — via cast).

85. **Recipe #32's CANONICAL form requires the SELF-REASSIGN chain — a fresh
    temp gets copy-propagated away.** `fr = (f32)(s32)x; state[2] = lbl + fr;`
    compiles IDENTICALLY to the inline expression (the temp folds). The form
    that works pins every step through ONE variable:
    `fr = (f32)(s32)x; fr = lbl + fr; state[2] = fr;` — the const load then
    lands AFTER the conversion (target's order) and the result chains in one
    reg. Same for fmadds: `fr = (f32)(s32)x; fr = lbl * fr + other; dst = fr;`
    (enemymushroom_resetToSpawn 95.06→100, both sites.)
    **WEB-TERMINATION meta-rule — the POSITION where the value web ENDS
    (store / return / further-op) controls the allocator; read target's
    endpoint and shape the last statement to match:**
    - Chain ends in a fresh reg (f0) consumed by fneg/store → fold the
      LAST op into the store expression: `dir[1] = -(fr * lbl);`
      (ktrexfloorswitch_spawnEnergyArc 97.50→100 — fully-chained fr was
      2 instrs off because the final mul self-accumulated).
    - Subtract-then-store where target's result web dies AT the store
      (fsubs f0; stfs f0, with v reloaded after) → STORE-EXPRESSION form:
      `*(p) = v - k; v = *(p);` NOT `v -= k; *(p) = v;`
      (playerUpdateWhileTimeStopped 96.29→100).
    - Wrap-subtract clamp `if (x > k) x -= k` responds to the #81 launder
      on the `-=` reference — same mechanism as the clamp-store form
      (fn_80026C54 97.69→100).

86. **Micro-residual: MWCC emits cheap `mr`/`li` set-ups BEFORE an adjacent
    `lwz`/`lbz` regardless of statement order** — when target shows
    load-then-copy (`lwz rX,disp(rY); mr rZ,r3`) and yours shows the copy
    first, statement reorder, comma-for-init, and locals were inert
    (enemy_free, nw_ice_update, fn_80063368's mr-vs-li). 2-5 instr residual.
    **PARTIAL CRACK (task #14): check the loaded byte's LOCAL
    TYPE first — `int n` instead of `u8 n` for a u8-field loop bound
    (`n = obj->byteField; for (i = 0; i < n;)`) flips the lbz/li emission
    to target's load-first order AND fixes the n/i/child web coloring in
    one move (enemy_free 18->14 diff lines; the #64-family int-local lever
    applied to emission order). Decl-order and #80 launders stay inert on
    the residual state/i chained-deref pair (the #61c subclass — re-attack
    via #107's un-naming read).** Related fold residual: a displaced
    byte/half access folds the
    constant onto the INDEX (`addi r0,idx,K; lbzx/stwx`) where target keeps
    it on the access (`add base,idx; lbz K(base)`) — struct-field,
    per-statement locals and pointer-arith spellings all fold back
    (hwSetVirtualSampleLoopBuffer, immultiseq, wctrexstatu, bossdrakor's
    2-instr tail). ⚠️ **SUPERSEDED by recipe #112** — the K-on-base grouping
    (`p = base + K; *(p + idx)`) is the non-loop escape; 4 of those
    instances are now byte-exact. The strength-reduced LOOP form (recipe
    #18) remains the other working escape.

87. **DEFINITION param order controls the prologue param-save emission order
    — declare the f32 param LAST to get `mr;mr;mr;fmr`.** When target's
    prologue saves the GPR params before the `fmr fN,f1` but yours emits the
    fmr first, the original signature listed the float param AFTER the ints
    (`fn(short *obj, int state, uint turnTime, f32 maxDistance)`). Register
    assignment is UNCHANGED (floats→f1.., ints→r3.. regardless of position),
    so the flip is ABI-neutral; other TUs' block externs with the old order
    keep compiling and matching (recipe #57). Definition-side mirror of #29.
    (fn_80154FB4 — part of 96.2→100.)
    **Elided-arg-move read (signature arbitration):** an arg with NO visible
    setup before the `bl` = the value is ALREADY HOME in its arg register
    (e.g. a `cmpwi r4,K` just before the call proves the tested var owns r4)
    — its register identity pins the whole param ordering when
    reconstructing an unknown signature from target eval order
    (quakeSpellFn's objfx_spawnArcedBurst: 11 params, u8s interleaved
    between floats, decoded from one elided move; 96.87→99.74).

88. **Multi-def web SPLIT flips saved-FP pair coloring where decl-order is
    inert.** When a saved-FP PAIR is number-swapped (T objY=f31/targetY=f30,
    yours reversed) and one of the two variables has MULTIPLE defs (a
    reassignment like `targetY = objY - targetY;` plus a clamp re-def),
    rename the post-reassign value to a FRESH variable (`dy = objY - targetY;`
    and rename the later uses). The allocator coalesces dy back onto the same
    reg (zero byte cost) but the reduced web weight flips the pair to match
    target. Decl-order swaps and #66 block-locals are inert on this shape.
    Two confirmed: fireflyLantern fn_80154FB4 dy-split (17→8 bad), dll_54_update
    t/t2 split. Sibling of #16/#61b for the FP-pair case.
    **Same session also confirmed plain #45 decl-order DOES still rule
    whole-GROUP saved-FP order** (dll_54_update: declaring `zz, xx` BEFORE
    `dx, dy, dz` flipped a 19-instr web; `d2, h, t` ordering fixed the t/h
    volatile pair) — try decl-reorder first for 3+-variable groups, web-split
    for stubborn 2-var pairs with a multi-def member.

89. **#83 corollary — MIXED if/ternary clamp split when target has if-SHAPE
    but UN-flushed conversion slots.** Only the clamp chain sitting BETWEEN
    two conversion regions needs the ternary-assignment form (to keep the
    conversion-temp pool growing → fresh slots + bigger frame); chains before
    the first conversion region stay as `if` statements, avoiding the
    `b`+`mr` web-transition tax #83 documents for the first variable-arm
    ternary of a chain. The all-ternary form costs +2 instrs; the all-if form
    reuses slots (frame 32B short); the MIXED split matches exactly.
    (dll_54_update: region-1 d-clamps as ifs, region-2 as ternaries —
    frame -176→-208 = target, zero instr cost.)

**#13 addendum — a DEAD `cmpwi <K>` followed by an unconditional `b end` in a
binary-search switch tree = an EMPTY `case K-1: break;` the import dropped.**
MWCC emits `cmpwi case+1; b end` (compare dead, no beq) for a single empty
case in the tree's interior. Writing `case 0x60a: break;` reproduced target's
`cmpwi r0,1547; b` exactly (arwbombcoll_update 98.30→99.89). A PAIR of empty
cases emits `cmpwi last+1` instead; a lone case spelled as the dead VALUE
itself (0x60b) emits cmpwi 1547 + a surviving beq (+1 instr). Read the dead
compare's immediate and subtract 1 for the real case value.
⚠️ **The K-1 reading is NOT universal — A/B both K-1 and K.** On
SB_ShipHead_update's {0x130001(empty), 0x130002, 0x130003} set the dead
`cmpwi 0x130001; b` came from `case 0x130001: break;` (the immediate ITSELF);
the K-1 reading (case 0x130000) emitted a base-reg `cmpw` + surviving beq
instead (the lis-only value needs no addi, changing the shape). When the dead
compare's immediate is reachable without an addi from the tree's lis base,
try the immediate itself first.

90. **#81 launder kills the pre-call HOIST of a doubled float arg while
    keeping the `fmr` CSE.** When a call passes the same named f32 extern in
    two arg slots (`f(.., lblK, lblK, ..)`), MWCC hoists the shared `lfs` to
    the FRONT of the call's arg setup (before the GPR moves), where target
    loads it lazily at its L2R slot (`..addi; lfs f1; lfs f2; fmr f3,f2`).
    Laundering the SECOND use (`f(.., lblK, *(f32 *)&lblK, ..)`) defeats the
    hoist-triggering CSE but MWCC still emits `lfs f2; fmr f3,f2` — exact
    match. Embedded-assignment `(t = lblK)` in the arg EXPLODES (allocates
    f31 + psq spills) even when t is otherwise dead — re-confirmed, never
    embed assignments in call args. (fn_80154870 95.55→99.85.)
    NOT UNIVERSAL: on a TRIPLED named-extern arg the `*(f32 *)&` launder is
    VN'd through (hoist survives) — the working escape there is the LITERAL
    spelling (`10.0f` ×3): a literal materializes at its L2R arg slot and
    fmr-CSEs within the statement (#71; magiccavetop → 100, near-100 sweep —
    where the import's `t = lbl` embedded form was the #84 miscompile hazard,
    silently reading stale f31 and SCORING HIGHER than correct code).

91. **The #25 counter-caveat cap (target has cror-FREE `bge`/`ble` clamps
    where your `>=`/`<=` if-chain emits the cror combine) is CRACKED — write
    the STRICT-compare nested ternary.** Target shape per clamp:
    `lfs v; lfs lo; fcmpo; bge L1; b Lstore; L1: lfs hi; fcmpo; ble L2;
    b Lstore; L2: fmr f0,v; Lstore: stfs f0` — the BOUND stays in f0 from its
    own compare, so the out-of-range arms are EMPTY (the b exits with the
    bound already in place). The C is
    `*p = (v < lo) ? lo : ((v > hi) ? hi : v);` — strict `<`/`>` compile to
    single-bit branches (no cror) and the value flow coalesces each arm onto
    the compare operand. The if-statement chain
    (`c = lo; if (v >= lo) { c = hi; if (v <= hi) c = v; } *p = c;`)
    produces identical VALUE flow but cror'd compares — that was the
    documented #25 counter-caveat "genuine residual"; it is now fixable.
    Cleared 6 cror sites (3 clamps) in objAnimFn_8014a9f0 (97.46→100, 3.7KB).
    Same fn also banked: `dx = (dz = lbl); dy = dz;` embedded-chain form for
    a direct `lfs f30` constant load + left-to-right fmr copy order (plain
    chain `dx=dy=dz=lbl` copies right-to-left; separate statements route via
    a volatile f0 hop), and the `B - A*C` spelling to get `fnmsubs` where
    `-(A*C - B)` splits into fmsubs+fneg.

**#91 addendum — int->f32 CONVERSION operands re-execute PER ARM; inline the
conversion expression at every ternary position.** When target's clamp shows
a FULL conversion blob (xoris/0x43300000/lfd/fsubs) before EACH arm's fcmpo
(2-3 blobs for one clamp), a named `fd = (f32)x;` local CSEs it to ONE blob
and never matches. Spell the conversion INLINE at all three positions —
`g = (int)(((f32)x < lo) ? lo : (((f32)x > hi) ? hi : (f32)x));` —
conversions do NOT CSE across the arm basic blocks (the #83 slot model),
while the BOUND subexpressions still tree-share onto the compare reg (#103),
so only the conversions replicate. The mirror of #97's per-statement
re-conversion, at ternary-arm granularity. (task #16, fn_802ABAE8
86.2->98.3 — the bound exprs `lbl * -f5`/`lbl * f5` stayed single-eval
while `(f32)gd` emitted 3 blobs, matching target byte shape.)

**#92 PARTIAL CRACK — the POINTER-null branch-over-branch (`cmplwi; bne/beq L;
b L2`, adjacent targets) is the RETURN-JOIN of an INLINED STATIC HELPER.**
(snd_groups InsertData 97.1->100, 26 regions -> 0, via MP4 s_data.c.) The
original factors the scan into a static helper with MULTIPLE returns
(`if (m->id == id) return m; ... return NULL;`) called via embedded
assignment `if ((m = GetXAddr(id, data)) != NULL)`. When MWCC inlines it,
the helper's internal return paths create JOIN EDGES into the test's
then/else blocks that prevent the fallthrough fold — the b-over-b emerges
naturally. CONSTRAINTS: (a) the LOOP must live inside the directly-called
helper — a shared 2-level sub-helper (GetPoolAddr) does NOT inline through
(MWCC won't auto-inline loop-bearing fns into a fn it then inlines);
(b) `static inline` does not override the loop-inline refusal. SCOPE BOUNDARY
(retry-sweep verified): the crack requires the helper's RETURN VALUE to be
USED in the surviving arm (InsertData's m feeds &m->data.cmd; projLib's
target handle feeds the body — both work). VALUE-LESS guards (scarab
dll_CE_render's conditional fade call, WClaser dll_1FB's render guard)
still fold under helper/bool-helper/ternary/empty-then spellings — the
DCE'd materialization removes the join. The objseq 15-copy ternary IS
value-producing (prime retry candidate; unit has 27 blockers so it's a
fuzzy win not a unit win). SECOND GATE: check the TARGET .o's symbol list
for the helper — a fully-inlined PLAIN static still gets EMITTED as a dead
fn, and if target lacks that symbol the extra bytes cost more than the
shape gains (dll_B7: helper form 96.8 vs 97.6 baseline despite fixing the
b-over-b; snd_groups worked because target HAS the GetXAddr symbols).
⚠️ GATE-CLEARER (fell-swoop sweep): `static inline` emits NO dead fn —
the second gate vanishes, and the helper lever opened the whole audio
85-93 loop-break band (Music_LoadChannelForTrigger x17 86.96→100,
Music_Trigger→100, Music_PlayTrackByIndex→100, Sfx_AllocObjectChannel x8
90.35→98.0) plus the objprint eye-joint scans (x2 →100) and ObjSeq island
families. The helper fixes THREE classes at once: per-copy bne+b islands,
the #160 via-r0 walker init (direct addi), and the GVN zero-share mr.
CAVEATS: (a) per-fn A/B is MANDATORY — the identical helper improved
ObjSeq_update +0.84 and regressed ApplyFrameCurves −0.84 (coloring
cascade); (b) converting shrinks the caller, which can flip the
auto-inliner on the caller's OWN callers — fix by SOURCE-ORDER move,
never dont_inline (it would block the helper's expansion). Signature-scan
seeds remaining (~210 of 236 candidates unconsumed): andross_update,
ObjAnim_AdvanceCurrentMove, trickyFn_8013b368, objInterpretSeq,
Minimap_update, ObjHits_CheckSkeletonPair, trickyFindPathRouteEntry, the
pauseMenu family, hudDrawMagicBar, trickyBallMove, groundanimator_update.

92. **LARGELY CRACKED (fell-swoop sweep) — the loop-break instances are
    inlined `static inline` helper return-joins (see the gate-clearer note
    above) and plain-statement guards are #17 pinned-`||` merges or
    #109(d) switches; the residual OPEN form is the GUARDED ASSIGNMENT
    (`if(flag) if(v>=K) v=K;` — Music_Update: pinned-|| empty-then, #63
    ternary, AND a 2-return clamp helper all fold to blt; a small helper
    gets simplified away, so the join must come from a loop-bearing
    multi-return helper that the construct doesn't plausibly contain).**
    Original entry (historical): the INT-compare `bge +8; b far` guard with
    STATEMENT-BLOCK arms (branch-to-NEXT over an unconditional b) has resisted
    every source spelling tried so far.** ⚠️ **SCOPE: this OPEN case is INTEGER
    compares whose arms are statement blocks ONLY, in LOOP-BREAK position. Two
    nearby shapes ARE recoverable, so classify carefully before banking: (1) the
    visually-identical fcmpo+cror `bne +8; b far; fneg` shape is recipe #63's
    keep-or-negate TERNARY (`x = (cond) ? x : -x;`) — scarab_update cleared two
    such sites (95.76→97.31); (2) the PLAIN-STATEMENT (non-loop-break) version
    is a single-case `switch` with `default: break;` per recipe #109(d). Classify
    by compare type + arm content + position first.** Target shape:
    `cmpwi r0,K; bge L1; b Lfar; L1:` where L1 is the literal next
    instruction. Spellings tried so far — `&&` chains, negated-`||`, DeMorgan
    variants, and even explicit `if (cond) goto L1; goto Lfar; L1:` — all get
    front-end-folded to the single inverted branch (`blt Lfar`). MWCC folds
    branch-over-branch eagerly BEFORE codegen; `#pragma peephole off` did
    not preserve it. Likely an original-compiler-version artifact, so the next
    lever to try is per-fn `#pragma optimization_level` (#110-family) and the
    older-version probe matrix. ~3 instrs per site; bank the partial and keep
    it on the retry list (fn_801DFA28 ×2 sites). Recognize it by the
    conditional branch targeting the immediately-following instruction.
    The same open shape covers POINTER-null compares with statement-block arms
    (`cmplwi; bne +8; b far`): the objseq family's 15-copy
    `val = (animEntries == NULL) ? 0 : (runLength ? interp(...) : 0)`
    if/else blocks are this class — BOTH nested-ternary directions
    regressed hard so far (88.2 -> 83.9 / 78.0 on ObjSeq_RebuildCurveStateToFrame;
    #118's pointer-ternary needs the result IN the walked reg, absent
    here). For the ObjSeq_update / RebuildCurveStateToFrame b-over-b
    sites, bank the b-over-b component as open and pocket the recoverable
    part now: #71 literal 0.0f for the 19 lbl_803DEFB0 refs. (task #16, miner-1.)
    Related wins from the same fn: a bare `(s16)` cast (NO `(int)`
    intermediate) on a float→int conversion result assigned to an `int`
    local emits `extsh rDST,r0` directly into the variable's home —
    `(s16)(int)(f)` routes through `extsh r0,r0; mr rDST,r0` (+1);
    `s16`-typing the local moves the extension to the USE side (worse).
    ⚠️ That s16-local verdict is CONTEXT-BOUND to float→int conversion
    results: for an INT-ARITHMETIC RHS, `s16 v; v = intExpr;` executes the
    extsh at the def INTO the var's home (`extsh r27,r0`) where the
    int-local + `(s16)` cast routes via `extsh r0,r0; mr r27,r0` — the s16
    local was exactly the fix on wmsun_update ×4 (94.25→100 campaign).
    Read the RHS kind before picking the local's width.
    And `x -= timeDelta * (x * k);` compound gives `fnmsubs` with
    timeDelta-first load order where `x = -(timeDelta*(x*k) - x);` splits
    to fmsubs+fneg.

93. **FbBuf/cmd-list stack-builder family (foodbag/pickup `dll_XX_func03`) —
    the four-part recipe set.** These fns build a cmd buffer on the stack
    via `FbCmd *e = buf.entries; FbCmd *p = e;` + `p->field = …; p++` walks.
    Four distinct divergence classes, each with a proven fix:
    (a) **`buf.cmds = buf.entries;` → re-derive as
    `(FbCmd *)((u8 *)&buf + 0x60);`** when target shows `addi r0,r1,K;
    stw r0` (fresh re-derive, no reg reuse). Batch-scan the unit's target for
    that 2-instr signature and fix every site at once — 9 foodbag fns had it;
    one batch took dll_8C 96.86→100 and lifted 6 siblings (+0.35 unit pts).
    (b) **Per-branch `p = e + K;` in BOTH if/else arms** (the dll_A0 phi
    pattern): identical assignments at a join defeat const-folding, so
    post-merge `p[i]` stores stay reg-relative (scratch r12 materialization
    per branch-end). dll_80 93.90→100.
    (c) **v1.0-vs-v1.1 import bug: v1.1 ADDED missing trailing `p++` in
    conditional arms.** When target's if-arm shows `stores; addi rX,rX,24;
    stores; b merge` (bump BETWEEN entries, NONE at arm end) while the
    else-arm ends with a bump, v1.0's source omitted the trailing `p++` (a
    real overwrite bug fixed in v1.1, which the Ghidra import reflects).
    Drop the trailing `p++` and rebase the count expr. dll_7F 95.73→100.
    (d) **Volatile-reg e/p coloring follows decl order + init placement**:
    declare the walker `FbCmd *p;` BEFORE `FbCmd *e = buf.entries;` and
    assign `p = &e[1];` AFTER the e[0] direct stores — flips r7/r9 to match
    target and places the addi where target has it. Part of the dll_7F 100%.

94. **MWCC value-tracks stack addresses through EVERYTHING except CSE-temp
    copies and phis — and the tracking dies at the first CALL for those.**
    Mechanism notes from the foodbag dig (explains the int/float store
    asymmetry: int header stores BEFORE the first `bl` fold to `K(r1)` and
    match target; value stores AFTER calls stay `4/8/12(rX)` reg-relative in
    target). Tested NEGATIVE fold-defeats (these are exhausted — use the WORKING
    triggers below instead): lvalue cast chains
    (`*(f32 *)((u8 *)p + 4)`), volatile deref, `(u32)`-domain address
    laundering, `(FbCmd *)(u8 *)p` self-reassign (elided), declare-then-assign
    vs initializer, inline-setter param laundering, `do { } while (0)` (loop
    pruned before const-prop), e-invalidation after `p = e`. The only WORKING
    source-level unfold triggers at -O4: (a) a JOIN feeding p (recipe #93b),
    (b) making the walker the SOLE holder so the address expression's 2nd
    occurrence (e.g. in the count expr `- buf.entries`) forces a CSE temp and
    p becomes an untracked temp-copy — BUT form (b) costs an addi/mr
    owner-swap (the temp wins r31) that can net-regress a high partial
    (dll_8E: 99.63 tracked form beats 98.81 unfolded form). Read which
    stores target folds before picking a form.
    **STORE-FORWARDING addendum — a POINTER store between a stack store
    and its re-read KILLS the forwarding (may-alias), and the escape is
    NAMED REGISTER LOCALS for the values (cfguardian_updateMain v-block,
    99.54→99.88).** Shape: compute into a stack array
    (`stk.v[i] = expr; ... stk.v[i] *= k; ... vel = stk.v[i] + vel;`)
    where the consuming statements ALSO store through an arbitrary
    pointer (`obj->velocityX = ...` between v[1]'s store and its
    re-read). MWCC forwards only the values whose re-read precedes the
    first pointer store; the rest RELOAD (`lfs` from the slot) and their
    product temps die early, scrambling the FP numbering. When TARGET
    shows stores AND register reuse with no reloads, the original
    computed through per-axis NAMED LOCALS with explicit stores
    (`v0 = expr; stk.v[0] = v0; ... v0 = v0 * k; stk.v[0] = v0;
    vel = v0 + vel;`) — locals are alias-immune, the #85 self-reassign
    keeps the product IN PLACE (fmuls fN,fN,fK = target), and the named
    k re-ranks to f0. Per-value shape mixing is readable off target's
    product regs: an in-place product = self-reassigned local; a product
    in a FRESH low reg = a separate single-def local (cfguardian's v2
    needed `p2 = v2 * k;`). Decl order then sets the sub-trio numbering
    (v1-before-v0 for the f3/f2 swap). Compound `*=` on the MEMORY
    lvalue is byte-identical to the expanded form — the in-place choice
    is allocator-level, only the named-local restructure reaches it.

95. **`#pragma optimization_level 0-4` IS accepted per-function by GC/2.0
    mwcc** (silently — no warning; `#pragma opt_propagation` /
    `global_optimizer` etc. are silently IGNORED). Levels ≤3 disable the
    sp-displacement store folding of #94 but ALSO switch the register
    allocator to creation-order priority (materialization owner gets r31,
    copies get r30; use-count weighting lost) and weaken address-mode
    selection (offset-0 member stores reuse a value-equal reg as `0(rX)`
    instead of folding). Net-NEGATIVE on every foodbag fn tested — but the
    pragma's existence is a real tool for fns whose target shows
    creation-order coloring. A/B per fn and read the prologue.
    **Correction (task #175): `#pragma opt_strength_reduction off/reset` is
    NOT in the ignored set — it is FUNCTIONAL in GC/2.0** (A/B-verified: same
    source, walker vs folded displacements). See recipe #96.

96. **Counter-chain cap CRACKED — repeated `lha; addi rX,rX,1; sth; lha
    (FRESH reload); cmpwi` blocks with ONE hoisted `li r0,K` shared across
    the resets = an UNROLLED `for` loop; write the loop + `#pragma
    opt_strength_reduction off`.** (task #175; ecsh_shrine_update
    96.34→100, +3104.) The three signatures all fall out of the loop form
    at once: the hoisted `li r0,0` is loop-invariant hoisting of the reset
    constant; the compound-home `addi rX,rX,1` (increment into the LOAD's
    reg, no temp) and the fresh reload before the compare (no extsh) are
    how MWCC compiles the rolled body. Written-out copies instead give
    `addi r0,rX,1; sth; extsh; cmpwi` + per-arm `li` — the store-forwarding
    extsh that no launder defeats on a global-derived base (the task-#175
    tested-inert list: lifted local, &-launder, member-base launder,
    (int)sum launder). C: `for (n = 0; n < 6; n++) { ps->cur[n] += 1;
    if (ps->cur[n] > 5) ps->cur[n] = 0; }`. The bare loop leaves one
    residual: MWCC strength-reduces the subscript to a bumped walker
    (`addi rP,rP,2; ... 48(rP)`) where target has folded ascending
    displacements (48,50,52..(rBASE)) — wrap the fn in
    `#pragma opt_strength_reduction off` ... `reset` (functional in GC/2.0,
    correcting #95's blanket "opt_* ignored" claim) and the unroller folds
    the constants byte-exact. DIAGNOSTIC: descending loops fold WITHOUT the
    pragma (SR rejects negative stride); u8/masked subscripts go lhax (worse).
    SCOPE NEGATIVES (this pragma is exhausted for these — use other levers):
    the pragma does NOT fix (a) cases where
    target ITSELF walks (real p++ source — the #80-resist class, 5/5 inert),
    nor (b) PARTIAL-SR targets — one byte-scaled index counter (`addi
    r22,r22,4` + per-access `stfsx`) sits BETWEEN our full per-array-walker
    SR and the pragma's no-SR; pragma scored 87.09 vs 91.24 baseline on
    RomCurve_func20 (decisively worse, reverted). That "SR WIDTH divergence"
    shape (one scaled counter in T vs per-array walkers in ours) is an open
    problem — no spelling found yet; bank the partial and re-attack when an
    SR-width lever lands.
    Sibling tells from the same fn: a constant compared at a jump-table
    DISPATCH and re-stored with no reload in later CASES = an embedded
    assignment at the compare (`if (x > (fv = lbl)) {...}` + `= fv;` in the
    case arms — the f0 web crosses the bctr); volatile-launder on a compare
    read (`*(volatile s16 *)&x > 5`) reproduces a fresh reload WITHOUT the
    loop shape (use only when the hoisted-li/compound-home tells are absent).
    **Volatile-launder also cracks JUST-STORED-GLOBAL CALL ARGS (galleon
    fn_801E1588 97.2→100): when the fn computes+stores a global byte triple
    (`lbl_X[0..2] = fexpr;` stb ×3) then immediately passes the bytes to a
    call, ours STORE-FORWARDS the computed ints (clrlwi ×3 into the arg regs)
    while target re-reads the globals fresh (`lbz` ×3, reusing the store
    block's base reg). Spell the args `*(volatile u8*)&lbl_X[i]` — fresh lbz,
    base reg reused, byte-exact ×3 sites. The scalar-extern respelling
    (#47 `(&sym)[i]`) is NOT the fix here — it regresses the store isel
    (addi-on-base + re-materialized base). Keep the sized-array decls.

97. **Conversion-CSE divergence: a LIFTED `f32 x = (f32)intGlobal;` local
    CSEs the int->f32 conversion across its uses; target RE-CONVERTS per
    use (load CSE'd, conversion not) — fix with an INT local + per-use
    `(f32)` cast.** When target shows one `lwz` of an int global but a FULL
    conversion blob (xoris/0x43300000/lfd/fsubs) before EACH consuming
    statement (`fadds f31..; fadds f29..` each with its own blob), while
    your lifted f32 local converts once and reuses the register, rewrite:
    `int ox = lbl_X; fx0 = fx0 + (f32)ox; fx1 = fx1 + (f32)ox;` — MWCC
    CSEs the load but NOT the per-statement cast. Conversion-side sibling
    of #83(a) fresh-reload laundering. Three sites took textRenderStr
    +1.6pp (ox/oy pair, `int shift = lbl << 2` with `- (f32)shift` per
    line). Inverse direction (target converts ONCE): keep the f32 local.
    Same session, two more #87 confirmations (read the prologue save order
    off the target: mr/fmr interleave = param order; flips are ABI-neutral
    because GPR/FPR slots assign per-class) — gameTextMeasureString scale
    is param 2, textRenderStr mode is LAST; both cross-caller arbitrated
    per #84. Also: u32-typed char vars make 0xE000/0xF8FF range tests emit
    `cmplwi` IMMEDIATES (the int form materializes the constants via
    lis/addi into saved regs and signed cmpw — a whole-fn coloring shift
    from one decl; recipe #58 at fn scale).
    **f32->int DIRECTION caveat (the GVN-rematerialization cap): a hoisted
    `int v = (int)volf;` makes every LATER `(int)volf` VN-reuse the result
    (`mr`), while target RE-EXECUTES the fctiwz per site.** The #97
    int->f32 "load CSEs, cast doesn't" behavior does NOT hold for
    fctiwz when a named int already holds the converted value — GVN is
    value-keyed across blocks. `*(f32 *)&volf` launder forces volf to
    MEMORY (demotes its saved-FPR home, net worse); no-op cast chains fold
    (#94 negative list). ⚠️ **CRACKED (task #13): spell the re-executed
    site `(int)(f64)volf` — the f64 PROMOTION node changes the conversion's
    VN key while emitting ZERO extra instructions** (f32→f64 widening of a
    register value is free; fctiwz-on-double is the same opcode), so MWCC
    re-executes the bare `fctiwz; stfd; lwz` exactly like target.
    `(int)(f32)(f64)x` does NOT work (emits a real frsp). Probe-proven +
    Sfx_UpdateObjectChannel3D 93.26→95.94 (both mr sites → fresh fctiwz;
    remaining residual is a #82 saved-pair rotation + a #92 param-test).

**Recipe #94 addendum (task #181) — the fold-back IS defeatable: a SAME-VALUE
CONDITIONAL second def (phi) unfolds every `*p` deref to reg-form.** Probe-
proven + verified at scale (partfx_update: 90/90 sites flipped to `0(rX)`):
`f32 *p = &cfg.m;` + a redundant `p = &cfg.m;` inside ANY conditional arm
makes p multi-def — #94's tracking only folds single-def webs — so all
derefs emit `lfs/stfs fX,0(rX)` while DIRECT member spellings of the same
field still sp-fold (write the inits as members, the work sites as `*p`).
Reachability rule: only sites reachable from BOTH defs unfold (a def inside
one switch arm does NOT poison sibling arms — put the second def pre-dispatch
under an existing branch). Materialization shapes: if-without-else merges to
ONE `addi r0,rL,K; mr rP,r0` at the first def (+dead cmp if the condition is
otherwise unused); if/else both-arms emits per-arm DIRECT addis (+1 instr at
the arm tail). Unconditional re-def copy-props away (no poison); the
sole-holder/raw-& variants and 2-local splits stay folded — the phi is the
only working trigger found (12 probe variants). partfx_update itself is held
open by an independent whole-fn param saved-reg rotation (target colors
by web weight: p2=r31/p5=r29/p6=r28; ours by param order r25-r30; #36
cast-inflation inert) — the unfold scores neutral there until that rotation
cracks (re-attack via #108/#115), so it's reverted for now. EDIT HAZARD: a bulk `&cfg.m -> p` sweep rewrites the DEF lines
into `p = p;` — uninitialized-pointer code that builds green; always verify
the addi exists in the .o after the sweep.

98. **`#pragma opt_unroll_loops off` IS functional in GC/2.0 (extends the
    #95/#96 corrections) — and the s64 fixed-point class is PARTIALLY
    CRACKED by it + a pointer-deref halving spelling.** (render fn_80007F78,
    0% -> 89.0%, 2212B.) Target shape for the unrolled rounding-division
    sequences: ctr=N loop, K single-bit signed halvings per body, each
    halving STORING both words to the stack slot but chaining values in
    regs, one reload at loop top. Recipe: (a) spell each halving through a
    pointer-to-local — `s64 tmp; s64 *q = &tmp; ... for (i = 0; i < 10;
    i++) { *q /= 2; *q /= 2; *q /= 2; *q /= 2; *q /= 2; }` — the deref
    defeats both the /2-chain constant-folding (plain or escaped scalars
    fold to srawi-25 pairs; volatile reloads per use, both wrong) while
    #94 value-tracking still resolves the address to direct sp stores;
    (b) wrap the fn in `#pragma opt_unroll_loops off` ... `reset` to kill
    MWCC's extra x5 re-unroll of the already-5-wide body (ctr=2 -> ctr=10).
    Body-statement count = target's per-body group count (read it off the
    ctr value x body groups). Other s64-class tells from the same dig:
    u64 PAIR-construction order picks the hi/lo register-pair coloring:
    `lo | ((u64)hi << 32)` vs `((u64)hi << 32) | lo` (Sfx_AllocObjectChannel;
    the addic/addze-vs-li;addc;adde isel is the open #108-GVN class).
    u64 vars passed to byte-copy helpers (render_copyPackedU64Head/Tail)
    must be SEPARATE address-taken locals, not a u64 array (`&buf[2]` call
    args get hoisted into saved regs; separate `&bufA`/`&bufB` re-derive
    per call matching target); a u16 field loaded then overwritten by a
    derived value = ONE variable (`curB = posA + curB`); 64-bit
    `(s64)bitpos > 64` compare emits the xoris/subfe/neg signed form while
    `>> 3`/`& 7` stay logical on the u64. Residual at 89%: whole-fn
    saved-reg rotation + frac/outPos hi-word spill-vs-reg balance
    (#82-family); h-reuse and web-split A/Bs all scored lower — don't
    re-grind them (masked-separate + curB-merged is the max found).

99. **O0-SHAPED bodies in an -O4 unit = per-fn `#pragma optimization_level 0`
    region; `#pragma optimize_for_size on` is FUNCTIONAL and supplies the
    `_savefpr_NN`/`stmw` helper-save prologue; both work under GC/1.2.5n
    (extending #95's GC/2.0 finding).** (e_atan2 unit 76.6 -> 100.0, all 3
    capped fns.) Recognize the class: a fn whose TARGET homes params to
    stack/saved-regs with redundant `mr r3,r31` re-derives before calls,
    keeps every named float local in its own callee-saved FP reg (f30, f31),
    and re-reads locals per use — inside a unit whose other fns are normal
    -O4 matches. That is NOT a coloring cap; the original wrapped the fn in
    a per-function O0 region. Levers, all probe-verified:
    - `#pragma optimization_level 0` reproduces the param-homing body
      (params spill to stack when address-taken or implicitly via
      `*(u32 *)&x` bit-reads; multi-use pointer params register-home with
      `mr r31,r3`).
    - `#pragma optimize_for_size on` (NOT in the ignored-pragma set) flips
      inline `stfd f31/stfd f30` saves to the `bl _savefpr_30` helper AND
      GPR saves to `stmw` — matching SDK-style prologues. Without it the O0
      region emits inline saves and the frame mismatches.
    - PEEPHOLE state is per-fn within the region: peephole OFF reproduces
      the `mr r3,r31`-before-first-call re-derive (recipe #68 copy-prop
      direction); peephole ON keeps the fused dot-form `clrrwi./clrlwi.`
      compares. Read the target: unfused compares + home-derived call args
      => off; fused record-form compares => on (powfBitEstimate needed ON,
      Vec_normalize/trigReduceQuadrant needed OFF — same unit).
    - At O0 a union round-trip (`bits.f = x; u = bits.u`) emits an extra
      copy slot; target reading the PARAM's own home as int = spell it
      `x_bits = *(u32 *)&x;` directly, with separate plain float locals per
      logical value (`*(u32 *)&frac = ...; frac + e`) instead of one reused
      union. #34/#5 decl-order then places the address-taken locals
      (first-declared = HIGHEST offset).
    - A FLIPPED per-file extern prototype (`fastCastFloatToU16(float, u16*)`
      vs the definition's `(u16*, float)`) is ABI-safe (float->f1, ptr->r3
      regardless of position) and controls O0 arg-eval order — the #29/#87
      lever at O0; a call-site CAST of the same flip scored WORSE, use the
      block/file-scope decl form.

100. **MSL/Rare -O0 math units (e_sqrt powfCore*, k_* family): `register`-class
    vars are the allocator model, and a narrowing cast assigned to an INT
    register var forces extension AT THE DEF.** (e_sqrt 27.7 -> 98.4;
    powfCoreHighPrecision -> 100.0.) Flags per the k_cos precedent:
    `cflags=msl_math_o0_cflags` + `-O0 -opt peephole -inline auto
    -use_lmw_stmw on -schedule off` (`-opt peephole` restores dot-form
    fusion at -O0; appending plain `-O0` after `-O4,p` does NOT fully
    override — use the o0 cflags base). Source model at -O0: long-lived
    values = `register` locals (saved regs, assigned f31/r31 DESCENDING in
    decl order, params after locals); plain locals = stack slots with
    per-use loads/stores (first-declared gets the higher offset); a
    Horner chain written as ONE nested expression keeps the accumulator in
    f1 with no inter-statement stores; an if/else assigning one variable
    emits per-arm stores while a TERNARY assignment emits a single store
    at the join; `*(u32 *)&x` on a param gives the stfs-home + reload
    shape. KEY extsh trick: `register s16 e; e = (s16)(expr);` defers the
    extsh to the USE site (cascade-misaligns ~50 instrs, recipe #19
    family); `register int e; e = (s16)(expr);` executes extsh at the def
    into the var's home — the cast becomes part of the VALUE. A
    `register float` param gets fmr'd from its arrival reg, but
    param-vs-local allocation ORDER seems version/context dependent —
    A/B; a register yv copy of a PLAIN param routes through the param's
    stack home (stfs+lfs, 1 instr long).

101. **dtk PHANTOM BOUNDARY symbols: a ~50-60% fn whose missing tail is a
    zero-reference gap/sibling symbol = a symbols.txt SIZE fix, not a code
    problem.** Two confirmed shapes: (a) a noreturn-style fn whose dead
    MWCC auto-epilogue retail kept inline got split into a separate phantom
    fn (OSReboot Run 54.5->100: retail Run = body + dead fralloc epilogue,
    dtk split the 20-byte tail into fn_80244C78 with ZERO refs anywhere;
    merged via size 0x2C->0x40); (b) a 2-instruction leaf split mid-fn into
    fn + gap_XX_text (wctrexstatu_getExtraSize size 0x4 + gap holding the
    blr; every sibling getExtraSize is 0x8). SANCTIONED procedure (team-lead
    ratified): size/boundary corrections are allowed -- distinct from the
    banned TYPE retyping -- when the absorbed symbol has zero references
    anywhere AND the merged span is byte-verified against the retail dol.
    Cheap-win class hiding in the 50-60%% tier; check sibling fns' sizes.

102. **Scan-loop found-flag idiom: `found = 1; goto checked;` in-loop +
    `found = 0;` on fallthrough + `checked:` label -- with `int found`,
    NO pre-loop init.** Target tell: no `li rX,0` before the loop, `li 1; b`
    at the hit, `li 0` after the loop tail, `cmpwi` on the test. The
    import's `found = 0;` pre-init + `break` form emits an extra li and a
    cmplwi (u32 found). Three audio fns matched on this
    (Sfx_AddLoopedObjectSound 89->95, Sfx_KeepAliveLoopedObjectSoundLimited
    82.7->98.8, Music_Trigger's scan). Sibling form: when the loop's found
    RESULT is the walker pointer itself, drop the flag entirely --
    `goto found; ... ptr = NULL; found: if (ptr ...)` (Music_Trigger,
    Music_LoadChannelForTrigger). Related width note: a u64 local
    initialized from an INT-typed expression (`bestAge = (mode == 2) ? 0 :
    -1;`) emits per-arm `li` + ONE shared `srawi hi,lo,31` sign-extension,
    where u64-typed constants emit two `li`s per arm
    (Sfx_FindObjectChannel 78.9->100).

103. **Repeated branchy ternaries CSE at TREE level -- statement-split
    if/else + #40 embedded bound assignment reproduces target's
    double-evaluation.** When target evaluates `(t > K ? t : K)` TWICE
    (two fcmpo/branch diamonds, the constant load CSE'd but not the
    ternary), a single expression `(t > K ? t : K) > L ? L : (t > K ? t :
    K)` folds to ONE evaluation -- MWCC shares the repeated subtree before
    lowering. The escape: spell it as `if ((t > K ? t : K) > (t2 = L)) {}
    else { t2 = (t > K ? t : K); }` -- separate STATEMENTS defeat the tree
    share, the embedded `(t2 = L)` in the condition places the bound's load
    at target's position AND coalesces the result web onto the bound's reg
    (empty then-arm, fmr only in the recompute arms).
    (Sfx_GetListenerRelativeDistance; #26/#40/#63 family.)

104. **Self-reassign accumulator chains pin FP product groups (#85
    extension): plain single-use product temps copy-propagate AWAY; the
    in-place form survives.** When target computes ALL of a group's fmuls
    before the fadds/fsubs pair (x*ca, z*ca, x*sa, z*sa, add, sub), 4
    fresh temps fold back into 2-op expressions and reorder. Write
    `t0 = x*ca; t1 = z*ca; A = x*sa; p = z*sa; A = A + t1; p = p - t0;` --
    the A/p SELF-reassignments pin evaluation order and keep all four
    products live. Carry a variable's web through phases by reusing it
    (`p = p * sb; ... p = p + t0; v[2] = p;` -- p's reg becomes C with no
    fmr). Sfx_RotateVectorByAngles 84.7->98.8.

**member-address reassociation on address ARGS (the audio memmove family) --
⚠️ CRACKED by recipe #111.** Target computes `&table->member[idx]` as `slwi;
add base,idx; addi +memberOff` (add-then-addi); our compile of the SAME
expression emits `slwi; addi +memberOff; add base` when idx is a
clrlwi'd/bounded web. The early probe set was inert (raw-sum spelling `(u8 *)
table + idx * size + OFF`, int/u16/s16 index retypes, n-local size precompute,
member/array spellings, 6+ forms, 3 fns) because the association keys on the
constant's SYNTACTIC ORIGIN -- recipe #111 cracked it: spell the constant
inside a U8-ARRAY subscript (`&table->flags[(index << 2) + 384]`) to get
target's `slwi; add base; addi 384` form. Use #111 on these; it took
Sfx_RemoveLoopedObjectSound/ForObject and Sfx_UpdateLoopedObjectSounds from
~76% to 97-99%.

**Recipe #92 evidence STRENGTHENED (audio probe session + MP4 cross-check):
the int-compare branch-over-branch (`cmp; bne +8; b far`) in LOOP-BREAK
position with VARIABLE compares has resisted every spelling so far.**
Additionally probed and folded: `if (!=) {ch++;} else goto found;`, the
empty-then variant, `do { if (!=) break; goto found; } while (0);`, and a
single-case `switch` (which also degrades the addis/cmplwi ==-1u idiom to
plain cmpwi). MP4 cross-check: 377 int-compare instances of the shape across
the matched corpus are ALL switch-lowering compare-chains (multi-case), ZERO
from if-in-loop — which says the original construct that produces this is not
yet identified, not that it's impossible. Cost model: ~1 instr x unroll factor
on every unrolled scan loop -- this was the presumed score FLOOR of the audio
85-93 band — ⚠️ AND IT FELL (fell-swoop sweep): the loop-break instances were
`static inline` helper return-joins (#92 gate-clearer) — Music_LoadChannel-
ForTrigger x17 → 100, Music_Trigger → 100, Sfx_AllocObjectChannel 90.35→98.
Plain-statement guards take the #17 pinned-`||` triage instead (far-is-an-
earlier-branch-target). Recognize and bank it — BUT first check the PLAIN-STATEMENT
case: a single compare + `beq next; b far` outside loop-break position IS
reproducible as a single-case `switch` with `default: break;` (recipe #109(d),
synthAdvanceVirtualSampleEntry x3 -> 100).

**#17-inverse defeats the adjacent-value RANGE-FOLD (coloring campaign):** when
target keeps separate `beq` tests for `c == K1 || c == K2` (adjacent values MWCC
would range-fold to `(c-K1) <= 1`), write `(c = load) == K1 || c == K2` — the
embedded assignment keeps the separate beq tests AND places the `load` at
target's position. (The other 5 coloring-campaign addenda — #74 sweep
diagnostic, #77 interleave, #107-FP directional, #108 bidirectional, #109d
plain-statement — are in-place on their recipes, commits 3e20114e5 / 89736fb06.)

## Flipping a unit to MatchingFor (team-lead-adopted standard)

100%% objdiff fuzzy is NOT flip-sufficient -- objdiff scores per-symbol
regardless of .o layout and pool placement. Before any NonMatching ->
MatchingFor flip (status edits remain the team-lead's):

1. **Symbol layout**: `objdump -t` the unit's .o; every fn's offset/size
   must equal the symbols.txt address deltas (source fn ORDER must mirror
   address order -- a swapped pair shifts the whole linked unit; objdiff
   still says 100%%).
2. **Pool claim**: `objdump -h` for non-empty .sdata2/.sdata/.data. Any
   compiler-emitted pool entries (int->f32 biases, float literals) need the
   TU's retail pool range claimed in splits.txt and our .o's pool bytes ==
   retail's at that range (arwproximit: claiming
   `.sdata2 0x803E7208-0x803E7218` made the 2 f64 biases link at retail's
   addresses; the unreferenced float slice stayed in the auto unit).
   **(b)-extended -- a local @NNN conversion-bias pool in .sdata2 with NO
   corresponding retail TU pool = flip held pending a link-level dedup;
   the unit's 100%% still banks fully (this is a flip-eligibility gate, not a
   matching limit — the functions ARE matched).** When our .o carries an 8-byte
   .sdata2 (the signed int->f32 bias `43300000 80000000`) but RETAIL's TU
   references the SHARED auto_11 copy (lbl_803E3578-class) and owns no pool
   of its own, there is nothing to claim in splits.txt -- flipping would
   inject fresh .sdata2 bytes into the link and shift every downstream
   address (the arwproximit failure mode). Known-negative: the manual
   conversion idiom that references the named bias emits fsub+frsp (#61d)
   and would break the 100%%. This class recurs on EVERY flip candidate
   whose fns do signed int->f32 -- run this check as part of any unit-100
   report (cases: dll_138, firepipe -- both 100.0, both held NonMatching).
3. **Post-flip gate**: DEFAULT-target build (report-only builds do NOT
   relink main.dol -- stale-dol trap), byte-compare the unit's dol region
   against orig/GSAE01/sys/main.dol, and confirm the dol md5. "dol changed
   after a flip" is never self-evidently fine.

(arwproximit case study: the premature flip shifted the unit +4B (fn order)
and appended duplicate pool entries at a fresh sdata2 address -- 440+2
diverged words vs retail, invisible to objdiff and to a report-only gate.)

*(Numbering note: recipes #105-106 below originally landed as a second
#98/#99 pair (track_dolphin discoveries, commit 3feef4d3a) colliding with
the MSL #98-100 set above; renumbered in 0815cd372. Older commit messages
citing "#98 K&R narrow-param" or "#99 volatile-store" mean #105/#106 here.
Conversely the e_sqrt commit's "recipe #99 -O0 source model" citation means
today's #100. Same resolution pattern as the #70-72/#93-95 collision.)*

105. **K&R-style definition for a NARROW (u8/char) param = callee masks at
    every use, caller passes the raw int — resolves the u8-param
    caller-mask paradox.** When target's CALLEE re-masks a byte param at
    each test (`clrlwi r0,rP,24; cmplwi`) but its CALLERS pass the arg with
    NO conversion (plain `mr r3,rX`), no prototyped param type fits: a `u8`
    prototype makes callers mask (clrlwi, often LICM-hoisted), `char` makes
    them extsb, `int` kills the callee-side masks. The original was a K&R
    definition (`void f(flag, a, b) u8 flag; int a; ...`) — the narrow param
    undergoes default promotion, so the incoming reg is raw int and every
    callee USE re-masks — paired with an int-typed prototype
    (`void f(int flag, ...)`, legal C89 for promoted-type match) so callers
    emit nothing. mapBlockRender_setVtxDcrs 36.69->100 byte-exact
    (track_dolphin). Same family also fixed objBboxFn_800640cc's stack
    byte-param (`u8 arg8` prototyped param reads `lbz` at slot+3).

106. **Volatile-STORE spelling keeps every per-iteration store of an
    accumulating stack slot that plain `+=` lets DSE collapse.** When
    target's unrolled loop shows `lwz rX once; addi; stw; addi; stw; ...`
    (one load, a store per source iteration) but your
    `state[4] += 8;` loop collapses to a single `+= 8*K` store per unrolled
    group, write the STORE volatile and the LOAD plain:
    `((int volatile *)state)[4] = state[4] + 8;` — loads CSE within the
    unrolled body (1 lwz/group) while every store stays (8 stw/group),
    exactly target's shape. Full-volatile (`*(volatile int *)&state[4] += 8`)
    over-produces (reloads per store). renderMapBlock 74.15->98.07
    (track_dolphin). Sibling of #96's volatile-launder note, for the
    store-side direction.

107. **#61c 2-var pair CRACKED — MWCC colors COMPILER-CREATED temp webs
    (SR temps, expression-CSE temps) BEFORE named-local webs; the swapped
    pair tells you which variable the original source did NOT name.**
    (task #12; getLoadedTexture, saveFileStruct_isCheatActive,
    playerAddHealth — all 3 → 100, byte-exact.) When the only residual is a
    2-reg volatile permutation across a load pair/chain (target q=rLOW
    p=rHIGH, yours p=rLOW q=rHIGH) and decl-order is inert (the #61c
    cap), read which value target puts in the LOWER reg — that one was an
    UNNAMED compiler-created web in the original source:
    - **Walked-pointer loop** (`lwz rH,glob; mr rL,rH`; loop derefs+bumps
      rL; rH indexed at the hit/exit): write the INDEX form
      (`if (key == base[i].key) return base[i].texture;`) — strength
      reduction recreates the walker as an SR temp, which colors LOWER
      than the named base. Instructions identical INCLUDING the mr; only
      the coloring flips (getLoadedTexture). The mr's PLACEMENT also
      tracks source: count in a named local places the SR-init mr after
      the count lwz; count read inline in the for-condition places it
      right after the base lwz — match target's prologue order.
    - **Chained load** (`base = &glob / p->inner; value = base->field`):
      DROP the named value local and spell the value as the member
      expression at each use — CSE still emits ONE load, but the value
      web becomes an expression temp and colors LOWER than the named
      base. Works for multi-use values (CSE'd across uses) and composes:
      saveFileStruct_isCheatActive needed the mask inline too
      (`if ((save->registeredDebugOptions & (1 << idx)) != 0)` — the
      `1 << idx` CSEs across both ifs); playerAddHealth dropped
      `int deref = inner->unk35C;` and respelled all 4 uses (the
      post-store use stays a fresh reload, as target has).
    - GUARD: dropping the named local can let MWCC SINK the load to its
      use / route single-use values through r0 and reorder the prologue
      (probe w1) — keep a named local for whichever value target keeps
      in the HIGHER reg (usually the base/pointer) to anchor placement.
    - Negative set (these were the OLD blockers — the un-naming read above is
      what cracks them, so reach for that, not these): decl-order both ways,
      init-order/iter-first assignment chains, #80 (int)-launders on the
      init, volatile read anchors, two-symbol-ref `p = glob; q = glob;`
      CSE forms — the copy-pair canonicalizes identically through all of
      them.
    Round-2 extensions (all 7 known #61c instances now → 100):
    - **Chained embedded assignment `dst[i] = name = expr;` FOLDS the
      named var into the temp class** — split it (`name = expr;
      dst[i] = name;`) to restore named-class coloring; one split landed
      a whole saved-reg trio (voiceConfigureParamRamp 97.75→99.13,
      audio/scheduling-ON unit — the residual volatile-pair swap there
      did NOT respond to naming; volatile pairs under scheduling-ON stay
      a cap).
    - **Retro-sweep detector**: cosmetic_audit hits whose first diffs are
      same-shape loads/mr with only r-numbers swapped = #107 candidates
      (batch 1: camcontrol_release → 100 — actually the curUiDllDraw
      #65-class dropped-2-param pass-through, sibling call sites prove
      the arg form; Obj_ApplyPendingParentLinks → 100 — #107 un-named
      parent PLUS a #60-class wrongly-guarded store the import nested:
      `unkC0 = NULL` runs whenever parent != NULL in target).
    - **Phi/merged values count as nameable too**: a branchy if/else
      reassigning one named var (`if (n) n += x; else n = 1;`) keeps the
      merged value in the var's reg; target holding the merge in r0 = the
      original computed it as a TERNARY EXPRESSION inside the consumer
      (`if (idx >= (int)(n != 0 ? n + extra : 1))`) — per-arm li/b join
      into a temp, #42 family (ObjModel_CopyJointTranslation → 100,
      combined with un-naming the pointer: `model->file->jointCount`
      spelled inline at both reads).
    - **NARROW-TYPED locals jump the coloring queue like temps do**: an
      `s16 linkOff = *(s16 *)(p + 2);` local colors BEFORE a plain `int`
      local created earlier, swapping the pair. Retype the local to `int`
      (keep the `*(s16 *)` cast on the load — lha unchanged) to restore
      creation-order coloring (Obj_InsertIntoUpdateList → 100; probe
      p9.c: s16-vs-int local was the ONLY differing lever, decl/init
      order inert). Extends #76 (int local for cmpw) to the pure-coloring
      direction.
    Sibling find, same session (recipe #65/#9 family, NOT #107): a vcall
    chain that SKIPS r3..rN with no visible arg setup = the fn's OWN
    params pass through untouched — the import dropped the fn's real
    parameter list, not the call's args (curUiDllDraw: callers already
    passed (0,0,0,0); def widened to 4 int params + 3-arg fn-ptr cast at
    the dispatch → 100). And dimlogfire_init's listed "#61c copy-pair"
    was actually a #90 doubled-float-arg hoist — launder the repeated
    const arg (`*(f32 *)&lbl`) → 100.
    **#107 EXTENDS to FP-PAIR CLAMPS — un-naming cracks part of the #82 open
    FP-pair sub-class, and it is PER-CLAMP DIRECTIONAL (coloring-A,
    fn_802ADC08/fn_802AE9C8 → 100).** A reload-clamp `v = field; if (v<lo)..
    else if (v>hi).. else ..; field = v;` where target's `fcmpo` keeps the
    CLAMPED VALUE in the LOWER FP reg (f0) but your named `v` puts it in f1:
    UN-NAME `v` — inline the field load at EVERY ternary arm
    (`field = (field<lo)?lo:((field>hi)?hi:field);`). CSE keeps ONE load but
    the value becomes an expression-temp and colors LOWER (f0), matching.
    DIRECTIONAL: read target's fcmpo — un-name only when target holds the
    value in f0; KEEP the named `v` if/else form when target holds it in f1.
    MIXED within one fn is normal (fn_802AE9C8 had 3 reload-clamps: unk408 →
    un-name(f0), velocityY-1 → keep-named(f1), velocityY-2 → un-name(f0)).
    A/B per clamp off the target fcmpo; pairs with #6 const-lift for adjacent
    same-const stores. This is the read that cracks the symbol/field-CSE half
    of the #82 FP-pair "open" sub-class (the pure expression-temp pairs with
    no field/symbol to un-name remain open).

108. **Saved-reg assignment is CLASS-POOLED, not weight-ranked — partial
    allocator model from controlled probes (task #12; /tmp battery
    E1-E15, GC/2.0 -O4 unit flags).** Use this taxonomy to DIAGNOSE
    whole-fn rotations (#16 cap) before grinding spellings:
    - **Single-def value-copy locals** (call results `x = f();`, #77
      cast-assigned locals from void* params) occupy the TOP block,
      last-created → r31 (E1: a,b,c,d call results → r28..r31 ascending;
      E15: a cast local took r31 over a multi-def web).
    - **Multi-def (φ-carrying) locals** DESCEND from the top remaining
      reg in CREATION order (E9: four `x = 500; if (..) x = g();` webs →
      r31,r30,r29,r28 in init order — opposite direction from copies).
    - **Params** rank at the BOTTOM under competition (E14: params at
      r25/r26 below multi-defs r28/r29 and copies r30/r31). Reassigning
      a param does NOT move it between pools (E12/E13 inert) — the only
      confirmed param pool-jump is the #77 typed-local copy.
    - **Induction webs** (walkers/counters) sit between params and
      multi-defs; the ORIGINAL compiler shows same-VARIABLE reg affinity
      across disjoint loops (Music_Update target: ch's loop-1 and loop-3
      webs share r21; ours cross-pairs them with i's) — not yet
      source-controllable. ⚠️ PARTIAL ESCAPE: an unrelated third web's
      decl position can flip which saved reg disjoint short webs inherit
      (#61b third-web edition, wmwallcrawler_update → 100) — bisect a
      full-reverse decl battery before banking. ⚠️ SEE-SAW ESCAPE
      (CFcrystal FireFlyLantern_SeqFn → 100): when decl perms only flip
      the PAIRING POLARITY (fixing one loop inverts the other), the
      cross-pairing IS the import's web structure — convert the named
      walker to INDEX form (#107/#160, the walker becomes an SR temp) so
      the webs target coalesces actually coalesce; pair with #121 in-loop
      literals whose LICM hoist lands after the SR-init mr.
    - **All-const multi-def flag webs** (`int found = 0; ... found = 1;`)
      sink to the very bottom, descending creation (Music_Update r20/r19
      — both compiles agree on these).
    - Use-count, first-use position, and loop-depth are ALL INERT within
      a class (E2/E3/E4 byte-identical to E1) — "web weight" is the
      wrong mental model for saved-reg ORDER; class membership + creation
      order decide.
    - Const-init'd SINGLE-def locals take no saved reg across calls
      (rematerialized at use, E5/E7) — only multi-def or address-anchored
      const webs survive.
    **BLOCK-SCOPE extension (CFBaby landed_arwing_update): DUPLICATED
    case bodies colored OPPOSITELY in target = per-case block-scope locals
    with INDEPENDENT per-block decl order (case 0: nearest-first, case 2:
    def-first → both directions from one source shape → 100).**
    **BLOCK-SCOPE lever on the within-class order (shrine1CE dll_19B_update
    99.93→99.99): a call-result local declared BLOCK-SCOPE PER ARM (3
    separate `void *handle;` inside each case block) makes each acquire/
    release web sink to the saved-pool BOTTOM — all three landed r24 =
    target — where the single fn-scope `handle` colored them r25/r24 by
    creation order.** Inverse data point: #119-style variable-merge
    (recycling a dead earlier local) moved ALL the webs to r25 (worse);
    decl-position moves were inert. When target gives several disjoint
    same-shaped webs the SAME bottom saved reg, try per-block re-decls.
    Related const-web coalescing lever (DIM2conveyor dimbridgecogmai_update
    → 100): a chain spelled `bits = (u8)x; bits = (u8)(bits | y);` SPLITS
    into per-def webs (r28 then r29) where compound `bits |= y;` keeps ONE
    web — and the merge flipped the code/bits saved pair to target.
    APPLIED — partfx_update 97.54→97.68 (+2.5K matched_code): the 40KB
    param-rotation blocker responded to the #77 conversion framed by
    this model — signature retyped (u32 p2_, u32 p5_, void *p6_) +
    cast-copy locals (`int param_2 = (int)p2_;` etc.) so the body is
    untouched; the copies enter the TOP block alongside the two
    stack-addr webs, and p1/p3/p4 stay param-pool at r25/r26/r27 =
    target. Residual: top-block internal order — ours assigns p2's copy
    early (r28/r29) where target has it LAST (r31, above the addr68
    web); 3 decl permutations mapped, kept the one with p6c=r28 correct.
    Decl order within the copy block is only a PARTIAL lever (the
    last-declared copy lands r28; the rest order by something internal).
    When the top-block order cracks, retry the #94-addendum 90-site
    unfold that was reverted as score-neutral under the old rotation.
    OPEN: cross-class interleaving is context-dependent (E14 puts copies
    ABOVE multi-defs; Music_Update target puts its 2 call-result copies
    BELOW all 7 multi-defs at r23/r24). Music_Update itself (97.78 here,
    later 98.70 via #115; instruction-perfect 13-web rotation) is an OPEN
    rotation: target is fully
    consistent with [multi-defs r31..r25 in init order, copies r23/r24,
    induction r21/r22, flags r20/r19] but our compile scrambles the
    multi-def order (lowP,lV,sB,aV,sA,bL vs init order) — the IR-level
    web-creation order diverges from source order; no spelling lever has
    flipped the remaining rotation yet (re-attack via #115 callee-decl
    widths, which already moved it once). Music_Update negatives (A/B'd —
    these are spent, try other axes): if↔ternary
    flips of the post-loop clamps (rank-inert), fadeB/fadeA u32→int
    retype with (int)-cast drops (rank-inert), and the s2Vol ternaries
    are already target-shaped (the mr-pair join is the ternary
    signature — converting to ifs would break instructions). The
    inp_value precedent (rotation DISSOLVED when source matched
    upstream MP4 ternary-macro forms — web STRUCTURE, not allocator
    preference) does NOT transfer here: Music_Update's forms already
    lower identically to target; its scramble is genuinely
    creation-order-internal. When attacking a rotation: FIRST check
    upstream-form structure (MP4 oracle the fn's family — cheap, and
    some "rotations" dissolve entirely), THEN classify every web (init
    kind + def count from source), THEN check whether the mis-colored
    web is in the wrong CLASS (fixable: name/un-name per #107, #77
    cast-local, second-def add/remove) vs wrong POSITION within its
    class (bank the partial — the within-class POSITION axis is the open
    one below, and #115 later opened a first source-side lever on it).
    **FIRST-DEF SPLIT is the cleanest class-mover (SB_ShipHead_update
    97.4→100, whole 5-web rotation collapsed in one edit): when a
    multi-def variable's FIRST def is a call result consumed immediately
    (`state = getCameraState(...); if (state == 2)...` — the test runs on
    r3, no saved materialization, so the split is INSTRUCTION-FREE), split
    that def into its own variable (`camState`). The surviving variable
    becomes a single-def copy and re-ranks with the copy pool; the
    remaining webs then followed plain decl order exactly (decl order
    player,mode,galleon,hs,state → r31..r27 = target). Decl-reorder alone
    was inert until the class move. Recognize: a rotation where ONE
    multi-def var's first def is a branch-consumed call result.**
    **The MIRROR move — LAST/EARLY-def MERGE into a different variable —
    cracked SB_ShipGun_update's "banked" state/ref2 pair (99.42→100,
    blank-canvas re-attack after decl perms ×11, launders, #115, per-fn O2
    all tested inert): the import used `ref2` as a scan-loop element
    (`ref2 = arr[i]; if (*(s16*)(ref2+0x46) == K) ...`) BEFORE ref2's real
    role (a vcall result), so ref2's web was CREATED at the loop and
    outranked `state`. The ORIGINAL reused a DIFFERENT later temp
    (`hitKind`) as the loop element; with that one substitution ref2's web
    is created at the vcall and the pair colors to target. When a 2-web
    rank battle resists every spelling, audit WHICH VARIABLE the import
    chose for each disposable temp (loop elements, scratch) — variable
    IDENTITY sets web creation points, and Ghidra's choices are arbitrary
    (#119's naming-side principle applied to rank, not just placement).**
    **CROSS-CLASS INTERLEAVE — characterized as an IR-internal residual,
    OPEN for a fresh lever (task #12 round 3, ~75-probe battery; minimal
    repro harness in the commit). The phenomenology below is hard-won
    compiler knowledge; treat it as the map to the next lever, not a wall.**
    The "target ranks a multi-def/counter web ABOVE param webs where ours
    inverts" residual (drshackle_updateSwingBlend, texscroll2_
    applyMapTextureScroll, skyFn_8008a04c vec, partfx top-block,
    Music_Update loop-3, CheckHitVolumes) is now characterized:
    - GROUND STATE = the canonical pool order (copies/multi-defs above
      params, E14) — reproduced in a 30-line minimal harness (params +
      call-crossing copy web coalesced with a multi-def web).
    - EXPANSION-CLASS CONSTRUCTS perturb it: ONE signed/unsigned
      magic-constant division ANYWHERE in the fn fully INVERTS the trio
      (multi-def sinks below params, one rank per "dose"); int<->f32
      conversions and big-constant materializations carry smaller doses.
      The effect is fn-GLOBAL and position-independent (a div before the
      webs even exist, or on an unrelated operand, inverts the same),
      FREQUENCY-WEIGHTED (div on a branch arm = half dose = one rank),
      and NON-MONOTONE (two different-constant divs CANCEL back to
      canonical; 1-2 conversions = one rank, 3-4 = two; no counting
      model fits — temp-web count, def count, parity, mod-k, big-const
      census, peak pressure, span length, use weight all falsified).
      Version-invariant across all 8 GC compilers (1.1-3.0a3).
    - ARMING CONDITION: a call-crossing COPY web competing with the
      multi-def web. Without it (result tested before the next call)
      divisions never perturb — fns lacking that shape are immune.
    - ZERO-COST LEVERS EXHAUSTED so far (the next lever must be something
      NOT on this list): decl order (both
      ways), identifier names, register kw, extra defs, dead code (DCE
      pre-empts the tick), (int)(long)/#114 sandwiches, named-temp
      statement splits, chained single-def ternary respellings of the
      multi-def web, unused vcall returns, #115 callee decl widths,
      u8/int fnptr param widths, static inlined helpers wrapping the
      div, full #77 typed-struct param conversion (S1, cast-free member
      access), FP web restructure (single-def dx/dz), sched/peephole
      pragma matrix, preceding-fn content (no cross-fn leakage),
      compiler version. The instruction stream pins the construct
      census, the census pins the interleave — so a lever that flips this
      has to change the construct census without changing the instruction
      stream, or change the priority function's inputs some other way (an
      open research direction, not a closed door).
    RESEARCH NOTE 2 (specimen census): the within-pool ORDER law VARIES
    per fn in TARGET — timer=decl-order, n_rareware initLoadingScreenTextures
    =E1-creation (same savegpr_25 both sides, pure permutation, decl+cast
    immune), foodbag=E1, Music_Update=init-order. Census correlation:
    n_rareware (E1) has 0 conversions/0 bigconsts; timer (decl-order) has 2
    conversions — consistent with ONE law (E1) + dose shifts, BUT the first
    falsification test failed: removing timer-probe's conversions did NOT
    shift OUR coloring (ours is dose-INSENSITIVE on this fn, contradicting
    the E14-harness one-div-inverts observation — web-pressure-dependent).
    The discriminating fn-input remains open; next probes should test the
    dose sensitivity ON the E14 harness with timer's web structure grafted.
    RESEARCH NOTE (timer probe, this window): a CONDITIONAL REDUNDANT
    RE-DEF (`if (obj == 0) { state = EXTRA(obj); setup = PDATA(obj); }` —
    the #94-addendum phi trick) MOVES webs between pools — the FIRST
    source-side lever observed to shift the cross-class interleave
    (obj r29->r30, setup r30->r29, flag r28->r27 on the timer probe).
    It costs ~6 added instrs (cmp+branch+defs) so it is NOT match-
    preserving by itself; use only where target ITSELF shows a mid-fn
    re-derive (the #55 read — check fresh lwz of the same offsets in T
    first; timer's T has none, so it stays banked). The pool-membership
    mechanism (single-def copies vs multi-def phi webs) is confirmed
    manipulable — the remaining question is the within-pool ORDER.
    DIAGNOSTIC (to RECOGNIZE the class, then bank-and-retry): residual =
    pure saved-reg permutation where a
    multi-def/copy web and param webs swap ranks, AND the fn contains a
    magic-const division / int<->f32 conversions / big-const
    materializations, AND target's order is closer to canonical pools
    than ours → bank the partial and keep it on the rotation retry list
    (the zero-cost levers above are spent; spend new budget on a new axis).
    The 1-2 instr "half" states (one rank off) are the same open class,
    not a separate bug. SCARAB CONFIRMATION (windlift scarab_update banked
    99.931, direction (b)): #115 callee-width flips x4, #126 param read,
    copy-init/chain spellings at every position, stack-tracked reads, and
    #114 sandwiches x4 are ALL verified insufficient — every front-end
    path to the zero folds to the constant before allocation; per-fn O1 is
    size-gated out at ~1000 instrs. The lever must make the reaching def
    opaque WITHOUT changing its li emission, or alter the priority-fn
    inputs streamlessly — MP4-oracle hunt for matched li;mr zero-chains at
    O4 is the open research route.
    (Why target differs at byte-identical streams is not yet explained —
    plausibly fixed-point rounding in a fn-globally-normalized priority
    function reacting to upstream-IR differences; MWCC source is lost, so
    the black-box probe axes above are spent, but the IR-input axis is
    open.) (probe-verified on vecmath
mtx44_multSafe): `#pragma opt_loop_invariants`, `#pragma opt_propagation`
and `#pragma opt_dead_assignments` are ALL FUNCTIONAL in GC/2.0** (removing
each changed codegen; each was load-bearing for the matched form). The
"silently ignored opt_*" list in #95 is narrower than first measured —
A/B any opt_* pragma before assuming it inert. Same unit also proved the
unroller keeps `(i << 2)`-spelled byte offsets unfolded as `li K; slwi`
per copy while `i * 4` spellings fold to direct displacements (#28
extension; mtx44_multSafe copy loop), and that an explicit `f32 *tp = tmp;`
pointer local positions a stack array's base web in decl order where the
bare array's base web is created first regardless of decl position
(mtx44_multSafe 52.43->100).
    **OPEN SUB-CLASS — small-constant-web rematerialization (coloring-A
    characterization; flagged research target, see task #27 / MP4-oracle).**
    The dominant remaining player.c coloring residual is a GVN small-constant
    web (`li 0` / `li -1` / a `mr`-copy of 0) where OUR -O4 compile and TARGET
    disagree on share-vs-rematerialize — and it is BIDIRECTIONAL:
    (a) TARGET rematerializes `li r0,0` AT THE USE while ours HOISTS `li
    rSAVED,0` into a saved reg (→ frame grows, inline saves → `_savegpr`
    helper, whole-fn coloring cascade) — fn_8029F108/FA24/E568/BDB4,
    playerRender; (b) TARGET SHARES the 0 via `mr r30,r31` (copy of an
    existing 0) while ours rematerializes a fresh `li r30,0` — fn_8029C8C8/
    802A5048/802A96D8/playerDie. Same web class, OPPOSITE direction per fn.
    These were exactly the flags360-sweep EXCLUSION set (the #74 mask change
    perturbs the same web). EXHAUSTED levers (don't re-run): #51 chains,
    casts, decl-order (inert), #110 per-fn O1 (BLOCKED — all affected fns have
    calls, O1 wrecks them), #114 conversion-node (N/A — constants fold through
    conversions). The crux (per the cross-class section below): a lever must
    change the construct census WITHOUT changing the instruction stream. NEEDS
    the MP4 oracle (find a 100%-matched fn with li-rematerialize-at-use, read
    its C) — a fresh-headroom probe-batch job, not a deep-context grind.

**#108 ROTATION-CLASS RESEARCH CAMPAIGN (timer_update deep-dive + corpus
sweep; tools/rotmap.py):**
- **ALWAYS rotmap BEFORE banking a rotation.** `tools/rotmap.py <unit> <fn>`
  aligns the two streams on register SKELETONS (regs masked) so pure renames
  pair up — the structural diffs HIDDEN under a rotation fall out as
  explicit regions. timer_update's "pure #108 rotation" hid FOUR invisible
  fixes (a missing #83a setup re-deref + 3 compare-width sites, 96.89→98.36);
  WM_ObjCreator's hid an FP-const lift diff; wcpressures' hid a #110 li;mr
  chain. The fuzzy%% of a rotation fn UNDERSTATES how much is structurally
  fixable — the rotation's transposition penalty drowns the real signal.
- **OUR O4 saved-reg ranking on timer = USE-COUNT DESCENDING** (state 29
  uses→r31, setup 16→r30, obj 8→r29, flag+v→r28 COALESCED); **TARGET's =
  DECL ORDER with const-flag sinking** (v decl-1→r31, state→r30, setup→r29,
  obj param→r28, flag const-class→r27, NO coalescing) — which is exactly the
  coloring `#pragma optimization_level 2` produces (probe: O2 = 4/5 webs
  target-exact, but O2's ISEL diverges — clrlwi/extsh artifacts target
  lacks, so a plain O2 wrap is NOT the fix). The use-count law does NOT
  generalize to drcloudper — per-fn, as #108 says.
- **Coalescing direction tell**: ours REUSES a freed saved reg for the next
  disjoint same-class web (timer flag+v share r28; WM_ObjCreator's three
  per-arm setup/spawned webs share r29); target SPREADS onto fresh regs
  (r27/r30/r31 per arm) even when the source already has block-scope
  per-arm decls. ⚠️ **CRACKED for the switch-arm case (WM_ObjCreator_update
  98.18→99.96): the spread comes from FN-SCOPE call-result locals.**
  Declare the per-arm `int setup; int spawned; int n;` at FUNCTION scope
  BEFORE the head copies (placement/state) — live-range splitting then
  re-creates per-arm webs that inherit target's spread (r30/r31, reusing
  the head webs' regs on arms where those are path-dead) AND drops the
  head copies one rank (placement r31→r30, state r30→r29 = target). Arms
  whose web sinks to the BOTTOM (r27) instead were true BLOCK-scope locals
  — mix per arm by reading target's per-arm reg (WM_ObjCreator: case 1
  block-scope→r27, cases 5/2/6 fn-scope→r30, 8/7→r31; arms with no call
  between alloc and uses keep r3-direct, no local form matters). A
  same-variable merge of an arm flag INTO the fn-scope var regresses
  (affinity coalesces all its webs to the bottom) — keep distinct
  variables. **Same-variable AFFINITY is the per-register AIMER (the
  final crack, fn → 100.0)**: when target holds an arm-local flag in a
  HEAD COPY's dead-on-path reg (ok in state's r29), the original
  RECYCLED that variable (#119: `state = (WmObjCreatorState*)0/1` defs
  + `(s8)(int)state` tests) — affinity lands the flag web on the head
  web's reg exactly, all other webs untouched. Aim the merge at the
  variable OWNING target's reg (the n-merge dragged webs to r27 = wrong
  host); decl position ×6, scope, int+(s8) retype, register kw, split
  init were all inert on the same web.
- **Exhausted levers on the standalone-reproducing timer probe (~35
  variants — do NOT re-run these on this class)**: decl-order perms,
  block-scope flag/v, v-as-ternary/x-copy/hoisted-def, #77 void*+cast-copy
  (moves state/setup to target homes but obj inverts), v init-at-decl,
  register kw, #114 (f64)/(int)(f64) sandwiches, conversion REMOVAL (the
  dose theory is falsified for this fn — zero conversions, same coloring),
  embedded-assign removal, hold-local removal, -O4 vs -O4,s vs -O4,p vs
  -O3,p, optimize_for_size on/off, global_optimizer/opt_lifetimes/
  register_coloring/opt_* pragma battery, ALL 14 GC compiler versions
  (1.0-3.0a5.2: none match target's coloring — three distinct version-era
  colorings, all wrong; NOT a version artifact).
- WORKFLOW for any banked rotation now: (1) rotmap, (2) fix every
  structural region (real score gains — the transposition penalty often
  releases more than the instr count suggests), (3) re-rotmap to confirm
  pure-rename state, (4) bank with the permutation table in the commit
  message. The pure-rename residual awaits an allocator-policy lever
  (decl-order-at-O4) that the probe battery says is not source-reachable
  with known spellings.

*(Numbering note: the entry below landed twice into collisions — first as
#107 (vs the #61c un-naming crack), then as #108 (vs the class-pooled
allocator model at 121e28185) — and is now #112. Commit messages citing
"recipe #108 K-grouping" / the #86-fold crack mean THIS entry. A separate
double-#110 (GVN chained-constant vs speculative-unroller pragmas) was
resolved in the reconciliation pass: GVN keeps #110, unroller -> #113.)*

112. **#86's displacement-fold-onto-index cap CRACKED for the non-loop case —
    the GROUPING POSITION of the constant K in `base + idx + K` picks the
    isel, and the side K is peeled FROM becomes the FIRST add operand.**
    (task #14; 5 instances, 4 byte-exact: hwSetVirtualSampleLoopBuffer →100
    [hw_sample unit →100.0], immultiseq_update →100, synthHWMessageHandler
    →100, insertPoint →100, bossdrakor_animEventCallback →100.) Forms:
    - **K-on-BASE** — `p = base + K;` then `*(p + idx)` / `p[idx]`, or the
      unnamed `*((base + K) + idx)` — emits target's usual
      `add rT,base,idx; lbz/lha/sth K(rT)` with BASE first in the add. A
      multi-def named `p` whose +K gets peeled also DEMOTES the base load
      to scratch r0 (`lwz r0; add r3,r0,idx`, hw_sample byte-exact).
    - **K-on-INDEX grouped** — `base + (idx + K)` or a hoisted
      `off = idx + K;` local — same add+disp shape but IDX first in the add.
    - **FLAT left-assoc `base + idx + K`** → `addi idx,K; lbzx/sthx`
      (fold-onto-index). Write this when TARGET has the lbzx form
      (bossdrakor; wcpushblock's recipe generalized).
    - **Sum-local `p = base + idx; *(p + K)` ALWAYS folds onto the index**
      — this is what every previously-capped instance used. Same for
      struct member arrays through a struct-typed local when the index is
      a chained in-loop load (voiceAllocate shape).
    Caveats: (a) a WIDE deref cast over the whole sum (`*(u32 *)(sum)`)
    re-folds to lwzx — put a `(u8 *)` launder around the grouped base:
    `*(u32 *)((u8 *)(base + K) + idx)` (synthHWMessageHandler). (b) a named
    pointer local costs an 8B frame slot (#67a) — for single-use loads use
    the UNNAMED parens form (synth_volume frame stayed 32); the named
    multi-def form was right for hw_sample's store pair (8-instr leaf, no
    frame concern). (c) SYMBOL-array bases (`extern u8 tbl[]`): every named
    local alias folds back (var-web binding) — DIRECT symbol indexing
    `tbl[idx * 4 + K]` keeps K-on-access (probe y7) — BUT converting moves
    the materialization web and can rotate whole-fn coloring; A/B mandatory
    (voiceAllocate: all 9 fold sites fixed yet nets −3.9, reverted for now —
    isel is correct, the block is its #82-family web cascade, so crack the
    web cascade first then re-apply the fold).
    Same session, #61c addendum: the lwz+mr base/walker pair swap that
    decl-order/launder/role-swap can't flip RESPONDS to the CHAINED init
    `p = base = lbl;` (#51's pointer cousin) — insertPoint's base/p pair
    →0 diffs (pointer decls before ints also required).
    **NEGATIVE-SCOPE addendum (model/lightmap harvest): the K-on-base named
    `p` works only when p's def has MULTIPLE USES — a single-USE p def
    gets forward-substituted and the flat sum RE-FOLDS onto the index
    (modelAnimFn_800246a0's bufs[sel]/vals[i2] sites: the matching 3-use
    `p = c + i1*4` block holds add+disp while the 1-use spellings of the
    same shape fold back; same fn proves it within one compile). And the
    caveat-(c) named-alias-of-SYMBOL resist class is broader than first
    measured: u8*-alias casts-at-use, a struct-TYPED local, AND #18
    member-array overlays through the alias ALL fold back
    (renderObjects' 3 stw sites, ObjModel_SampleJointTransform's 4 load
    sites — grouped/unnamed/named forms each probed). When the base is a
    named alias of a symbol and the use is single-site, recognize this open
    sub-shape and bank the partial (the symbol-alias fold-back is the part
    still awaiting a lever; the direct-symbol-index escape in #112(c) is the
    closest thing to try).

109. **s64/fixed-point class: three more cracks beyond #98 (task #15;
    fn_80007F78 89.0->94.0, synthAdvanceVirtualSampleEntry 95.4->100,
    _GetInputValue 95.7->100 [inp_value unit -> 100.0]).**
    (a) **Shift-count mask spelling**: target masking EVERY u64-shift-by-
    variable count (`li r0,-1; and rX,count,r0` before each `__shl2i`/
    `__shr2u` pair, masked web SHARED across the pair) = the C is
    `x <<= (n & 0xFFFFFFFF);`. Probe-verified: `(u32)n`, `(int)n`, and a
    u64 count all pass the lo word raw; ONLY the explicit `& 0xFFFFFFFF`
    spelling materializes the mask. 8 sites in fn_80007F78 (+2.7pp).
    (b) **Countdown s64-RMW unroll** (supersedes #98's `opt_unroll_loops
    off` + manual 5-statement body for this shape): the 10x5/7x2 halving
    blocks are MWCC's OWN unroll of `for (i = 50; i != 0; i--) *q /= 2;`
    (count-down form -> x5 unroll, ctr=10; 14 -> x2, ctr=7). Unroller-cloned
    RMW bodies keep ONE loop-carried web -> FIXED regs per copy (lo=r4,
    hi=r3) with store-to-load forwarding emitted as a literal `mr r0,r4`
    per copy. Count-up (`i < 50`) unrolls x8 with PING-PONG registers and
    no mr; manual 5-statement bodies ping-pong too (probed: opt pragma
    matrix, nested loops, tmp-var spellings all inert). Read the tell:
    fixed reg roles + per-copy `mr` = countdown source; ping-pong = manual/
    count-up.
    (c) **Two-web u32 address temp**: `addc rT,...; mr rVAR,rT` with later
    uses reading rT = a u32 temp assigned then copied into the persistent
    int var (`addrB = posA + curB; curB = addrB;` + calls take addrB).
    (d) **#92-shape RECOGNITION (not a probe)**: `cmp; beq next; b far` in
    plain statement position = a single-case SWITCH with `default: break;`
    in the source (switch compare-chain lowering emits branch-over-branch;
    if/else folds it). MP4 vsUpdateBuffer proved it verbatim for
    synthAdvanceVirtualSampleEntry (3 sites + `%` modulo for the wrap +
    embedded-assign callback + real loopSizePtr local). The #92 cap text
    stands for LOOP-BREAK position and statement-block arms; the switch
    reading recovers the plain-statement instances.
    (e) **#67(a)-struct corollary holds for GPR pairs on 1.2.5n**: a
    `struct { u32 len, off; } d;` local claims its 8B frame slot even when
    fully enregistered, where two plain u32 locals claim none (closed the
    last -48-vs-40 frame delta to 100).
    (f) **Audio clamp residuals: A/B the MP4 musyx MACRO spellings** —
    sal.h's `CLAMP`/`CLAMP_INV`/`MIN` are nested TERNARIES assigned to the
    variable (`value = (v > max) ? max : (v < min) ? min : v;`); the
    if/else+temp expansion emits a temp join + `mr` writeback instead of
    in-place arms. `value = MIN(value, K)` right after an assignment
    reproduces the r0-temp + `mr` writeback shape. _GetInputValue's
    whole-fn register rotation vanished once the web structure matched —
    treat big rotations as SYMPTOMS until web shapes align.
    (g) **Paired hi/lo uint masks in an import = ONE s64 variable.** The
    tell: `slw; srawi ,31; or; or` set-pairs plus `and; and; xor 0; xor 0;
    or; cmpwi` tests over two "separate" uint locals -- write `s64 mask;
    mask |= 1 << i; if ((mask & bit) != 0)` and the whole pair machinery
    falls out (CheckHitVolumes maskA/maskB/volBits, task #18).

**OPEN — n-ary sum canonicalization (>=3 variable terms): the
invariant-statement-reorder class.** (task #14; characterized with a full
probe set, awaiting a lever.) ⚠️ **PARTIAL LEVER for simple VALUE sums
(non-address): the collection's output ORDER depends on the source
ASSOCIATIVITY SPELLING — A/B the opposite parenthesization.** A 3-term
`glow + (drift + rnd)` (parens) collects to `(rnd+glow)+drift`, while the
paren-FREE left-assoc `glow + drift + rnd` re-associates to
`glow+(drift+rnd)` — opposite outputs from the same math. When a 3-term
sum's add order/grouping diverges, flip the spelling before banking
(wallanimator kaldachompspit_update → 100; the import had ADDED parens).
(int)(long) sandwiches, opt_common_subs/opt_propagation off, embedded
defs, and #15 array-index forms were all inert on that shape. For
ADDRESS sums the rest of this entry applies: recipe #112's K-grouping
levers work
for `base + idx + K` (TWO variable terms); with THREE OR MORE variable
terms (`a + i6 + i4 + i5 + i12 + 0x60`) MWCC -O4 COLLECTS the n-ary sum
and re-canonicalizes it — base joined LAST, source grouping/order erased.
Two co-occurring symptoms, both from the same collection pass:
(a) **multi-base shared-subsum**: when 2+ bases share an identical
multi-term index, ours builds ONE base-free subsum (+K folded:
`addi rX,sum,K; lhzx` per base) where target re-adds the components per
base with K as the displacement (`add base,i6; add +i4; add +i5; add
+i12; lhz K()`) keeping the components (not the sum) in registers — 13
fewer instrs ours, savegpr shifts (fn_80069B1C 70.5, the fmt==4 RGB565
blend); (b) **loop-head invariant statement reorder**: the outer-loop
component computations (hi/mid/scaled) emit in a different order than
source, and the inner sum joins base last (fn_80069EB8, 96/96 instrs,
order-only). Probed inert: flat-with-locals, full-inline (LICM then
hoists the contiguous invariant subtree — WORSE, 90 instrs),
K-on-base per-site grouping, (int)-domain sums with base leading, and
the pragma matrix (opt_propagation/opt_loop_invariants/
opt_dead_assignments/opt_strength_reduction off, optimization_level 3/2
— all >= baseline; sched-off tested earlier by match-3). The #112
grouping survives only 2-term sums; recognize >=3-term multi-base shapes,
bank the partial, and keep it open for a lever that controls n-ary sum
collection (the probes above are spent — a new axis is needed).
(fn_80069B1C also carries one #92 branch-over-branch site in its guard
chain — independent open residual.)

**#109(d) ADDENDUM — the single-case-switch reading extends to PLAIN-STATEMENT
`if (x==K) {A} else {B}` (cracks the #92 plain-statement variant; coloring-A,
fn_802A4D34/fn_802A14F8/fn_80298CCC → 100).** When target emits `cmpwi x,K;
beq <A>; b <B>` (branch-over-branch: beq jumps over an unconditional `b` to the
then-block) in PLAIN STATEMENT position — NOT loop-break — the original was a
`switch (x) { case K: A; break; default: B; break; }`, not an if/else (if/else
folds to a single inverted `bne <B>`). Rewrite the if/else as that switch and
MWCC regenerates the `beq; b`. This is the non-loop-break companion to the #92
cap (which stays open for VARIABLE-compare loop-break-position branch-over-
branch). Read the position: plain statement → switch reading; loop-break →
still #92-open. Pairs with #21 (snd ternary invert), #58 (u32 clamp cmplwi),
#93c (drop (int) on float→s16 store) when those co-occur in the same fn.
**Round-4 extensions + a hard scope limit:**
- **VALUE-ternary variant**: `cmpwi t,0; beq <li>; b <join>` over a
  keep-or-replace ternary = switch ON THE VALUE with the assignment in the
  case: `int t = lha; switch (t) { case 0: t = 0x14; break; } store (s16)t;`
  — the plain ternary AND the #63 keep-or-replace form both fold the branch.
  `int t` + a bare `(s16)` cast at the store supplies the join extsh that
  `s16 t` drops (drgenerator_init → 100).
- **Import-flattened-switch tell**: SEQUENTIAL guard returns
  `if (x == 8) return; if (x >= 8) return; if (x != 0) return;` = a
  decompiled binary-search tree — reconstruct the switch
  (`case 8: break; case 0: <body>`) to regenerate the dispatch including
  the case-0 `beq; b` (WM_seqobject_update → 100).
- ⚠️ **SCOPE LIMIT: MWCC switch compares are ALWAYS SIGNED (cmpwi).** When
  target shows `cmpLwi` + beq-over-b (u8/unsigned operand), the switch
  reading canNOT reproduce the compare width — probed exhaustively:
  `(u32)` cast, u32 local, `+ 0u`, `& 0xffu` all stay cmpwi; if/goto/
  discarded-ternary/empty-arm spellings all fold the branch. Best
  achievable is the switch's 1-byte cmpwi residual (dll_1FB_render banked
  96.5). An unsigned-compare branch-over-branch lever is still open.
  POINTER-null operands are the same wall, worse: `switch ((int)ptr)
  { case 0: break; default: <body> }` both DEGRADES the width (cmpwi)
  AND still folds to a single beq — don't convert pointer-guard
  empty-then sites at all (fxemit_update's def==NULL site, banked).
  ⚠️ THE UNSIGNED WALL IS CRACKED — it was never a switch: the unsigned
  `cmplwi; bne next; b far` plain-statement b-over-b is recipe #17's
  MERGED-`||` GUARD whose then-block (`b far`) is PINNED by an EARLIER
  `||` term's conditional branch targeting it, so the front-end cannot
  invert the final term (`if (!damaged || (impactHandled && hitStarted ==
  0u)) return;` + the body UN-nested — the import had nested it;
  landed_arwing_updateHitReaction → 100, MP4 oracle SetTeamResultTarget).
  TRIAGE RULE for any bne/beq-next-b-far: check whether `far` is ALSO the
  target of an EARLIER guard branch — if yes, merge the guards into one
  `||` chain; the b-over-b is its final term. REFINEMENT (CFTreasSharpy,
  pointer-terms variant `player==NULL || def==NULL`): the then-block must
  contain REAL code (`return;`) — an empty-then `{}else{}` folds the
  final term even when pinned. This is the unifying
  PINNING principle: a branch-over-branch survives folding iff its
  then-block is a join target of another branch (#17 merges, #91/#118
  value joins, #92's inlined-helper returns).
  The s16-field variant DOES work (fxemit_update suppressed-flag → fixed).

110. **GVN chained-constant residual CRACKED — `li rY,K; mr rX,rY` (target
    chains a constant-equal copy) is per-fn `#pragma optimization_level 1`,
    NOT a VN spelling.** (task #13; fn_80063368 96.25→100, fn_80060BB0
    94.4→100, track_dolphin, both byte-exact — the earlier "4 spellings inert"
    bank turned into a full crack once the right axis was found, a model case
    for re-attacking any open residual.) At O4 EVERY spelling of a constant-equal copy (`zero = idx;`
    after `idx = 0;`, #51 chains `zero = idx = 0;`, casts,
    opt_propagation/opt_common_subs/global_optimizer off, all 9 compiler
    versions) const-props to separate `li`s — the mr is UNPRODUCIBLE at
    O4. At O1 copy-prop doesn't fold the copy (emits the mr) and for
    SMALL call-free loop fns the rest of the codegen is identical to O4.
    O1 sub-levers: allocation goes creation/decl-order (declare locals in
    target's ascending reg order); O1-isel reassociates const offsets into
    displacements (`add; stb K(r)`) — recover the O4-style index-fold
    (`addi r0,idx,K; stbx`) with a BLOCK-SCOPE temp (`int o; o = innerOff
    + 0x12; arr[o] = zero;` — block temps land in r0 scratch);
    `scheduling off` keeps source statement order; peephole ON (local
    re-enable inside an off region, #1) keeps the stb/clrlwi fusion.
    SCALE GUARD: whole-fn O1 BALLOONS big fns 2-3x (dll_0B_func04 probe:
    629→1511 instrs — reverted); the recipe applies to small fns where
    O1≈O4 codegen. MP4 cross-check: all 150 li;mr pairs in the matched
    corpus come from chained inits in -O0 game code — same no-const-prop
    mechanism. Diagnostic: target li;mr where all C gives li;li + fn is
    small/loop-shaped → A/B the O1 wrap. Per-fn O1/O2 tested NEGATIVE on
    the audio memmove family (54.8/65.4 — allocation wrecks fns with
    calls); see #111 for that class instead. ⚠️ **The "wrecks fns with
    calls" negative is NOT universal — PARTIALLY CORRECTED by recipe
    #126**: O2's allocation was target-EXACT on a call-bearing fn
    (wmspiritplace_SeqFn, 6 calls + jumptable switch); only O2's isel
    diverged. A/B the O2 wrap per fn instead of skipping on sight.
    FIELD CONFIRMATION (objlib, ObjHitbox_SetStateIndex 90.86->100
    byte-exact): the scope holds outside the discovery unit. The target
    mr,mr zero-chain (two locals copied from a third's `li r8,0`) was
    unproducible at O4 under every spelling (plain copies, #51 chains,
    (s16)-cast chains all const-prop to separate li's); per-fn
    `#pragma optimization_level 1` + `#pragma peephole on` (the peephole
    re-enable supplies the beqlr early-return fusion AND drops the
    redundant clrlwi-before-stb) + decl order in target's creation-order
    coloring landed it exactly. Same tells: small call-free loop fn,
    li;mr in target where all C gives li;li.
    **VALUE-DIAMOND else-arm copies (`cmpwi; blt Lmr; addi r0,rX,-K; b Lj;
    Lmr: mr r0,rX; Lj: <consume r0>`) ARE O4-producible — an "UNPRODUCIBLE
    at O4, needs per-fn O1" verdict here was OVERTURNED the same day by a
    blank-canvas re-attack (SB_Galleon_func0E 95.9→100, no pragma).** The
    O4 form that keeps the else-arm `mr`: the diamond's INPUT is a REPEATED
    LAUNDERED EXPRESSION (CSE'd multi-use temp), the RESULT a NAMED local
    assigned per-arm in an if/else —
    `if ((s8)*(u8*)&p->f >= 5) w = (s8)*(u8*)&p->f - 5;
     else w = (s8)*(u8*)&p->f;` — the 3 occurrences CSE to ONE
    `lbz r0; extsb r3,r0` (also landing the two-register load shape) and
    `w`'s per-arm defs join in r0 with the real `mr r0,r3` else-arm. The
    if-conversion that folds ~27 other spellings (ternaries, self-assign,
    embedded-in-consumer, split vars, goto diamond, switch-on-bool, #114
    sandwiches, #92 inline helper, NAMED-local input + if/else) keys on the
    input being a NAMED variable — an expression-temp input + named per-arm
    result is the combination that survives. The earlier O1-wrap reading of
    this fn was a COMPENSATING INSTRUMENT (re-audit any O1 wrap kept for a
    value-diamond before calling it original). Model case for the
    fresh-eyes protocol (Prime Directive section).

111. **Member-address reassociation cap CRACKED (the audio memmove NAMED
    cap) — MWCC's address-sum association is keyed on the constant's
    SYNTACTIC ORIGIN; plus #40 embedded assignments as arg-eval-order
    FOLD-BLOCKERS.** (task #13; Sfx_RemoveLoopedObjectSoundForObject
    76.55→98.91, Sfx_RemoveLoopedObjectSound 76.39→99.2,
    Sfx_UpdateLoopedObjectSounds 79.11→97.64.) Association rules, probed:
    - struct-MEMBER offset (`&table->objects[index]`, member at 384) →
      `(idx*4 + 384) + base` = `slwi; addi 384; add` (the old parked form);
    - constant inside a U8-ARRAY subscript
      (`&table->flags[(index << 2) + 384]`, flags at offset 0) →
      `(base + idx*4) + 384` = `slwi; add base; addi 384` — TARGET's form.
      MP4 oracle: ReverbHICreate's `lens[k+5]` (optimized musyx).
    - raw pointer arith `(u8 *)table + (i << 2) + 384` re-canonicalizes
      BACK to addi-first — the array-subscript NODE is load-bearing;
    - DISPLACEMENT-FORM sibling (`add base; lha K(base)` wanted, flat sum
      gives `addi idx,K; lhax`): the TYPED-SUBSCRIPT spelling
      `((s16 *)((char *)base + K))[idx]` lands K-on-base where BOTH the
      flat sum and #112's paren grouping `(base + K) + idx*2` fold back
      on some sites — and which spelling works is PER-SITE (CFtoggleswitch:
      the s16-index site took the paren grouping, the u8-index site needed
      the typed subscript). A/B both per site (cctestinfot_update → 100).
    - CONTEXT-dependent: in ASSIGNMENT context (walker-pointer inits) use
      the NESTED subscript `op = (u32 *)&(&table->flags[i << 2])[384];`
      (gives in-place `add rW,base,r0; addi rW,rW,384`); in CALL-ARG
      position nested re-canonicalizes to addi-first — use the FLAT form
      there. Named single-use dst/src locals get copy-propped into the
      args and re-canonicalize, so that spelling is a dead end here — use
      the flat form.
    THE ARG-EVAL ANCHOR (the +12pp move): when target evaluates the SIZE
    arg BEFORE dst/src (subf/clrlwi r5 ahead of the r3/r4 setups), the
    original embedded a DEF inside the size statement:
    `sz = (u16)((count - (index = (u16)i)) << 2);` — the side effect makes
    the single-use sz statement NON-foldable into arg-3 position (a plain
    `sz = ...;` folds to arg position regardless of statement order; sz
    multi-use isn't needed, the embedded def suffices). Same trick
    `&table->flags[((index2 = index + 1) << 2) + 384]` in the src arg
    places the addi at target's position with index2's web surviving
    across the later calls (saved reg). Companion levers from the same
    family: compound `gCount--` drops the store-side clrlwi under
    peephole-off (#20) and the store-forwarded re-read of the global
    yields target's mask-at-use `clrlwi r0,r0,16`; #83a `(int)`-launder
    on an else-arm `*fp` re-read reproduces target's fresh lbz (local
    bases launder fine); #43 comma-init for li-then-addi loop prologues.
    Residual class (~1-2%/fn, OPEN): arg-position sum nodes build
    scaled-first (`add rD,r0,rBASE` vs target `add rD,rBASE,r0` — encoding
    only; ~12 spellings inert so far) and whole-fn saved rotations (#16-class,
    re-attack via #107/#108/#115; the #80 table-init launder tested NEGATIVE
    on UpdateLoopedObjectSounds).
    Retry candidates: dataInsertMacro/dataRemoveMacro/dataGetFX loop
    reassociation (90-92%), voiceAllocate's addi+lbzx (94.6, its "-O2
    reproduces target form" note = this association, fix at O4 with the
    subscript-origin spelling).
    **ORDERING-DEPENDENCY note (#111 embedded defs x #62 launders): when a
    fn needs BOTH an embedded-def size arg AND an address-CSE-breaking
    (int)-base launder, the launder is only safe AFTER the embedded defs
    are in — applied alone it ROTATES the param saved-reg coloring
    (#36-style cast priority inflation: ObjModel_BlendPrimaryVertexStream
    A/B'd both orders — launder-first 83.5 with params scrambled
    r18-r21, defs-then-launder 94.1 with params at target r26-r30). Apply
    embedded defs first, measure, THEN launder. Same fn: the (int)-on-SUM
    spelling `(lbl + 1)` is VN'd through (no CSE break); only
    `(int)lbl + 4` on the BASE breaks it — the #83a sum-vs-base polarity
    INVERTS for symbol bases.

*(Numbering note: the speculative-unroller entry below landed as a second
#110 (f6cb57505), colliding with the GVN chained-constant entry that landed
first (da10a6db7) — renumbered to #113. Commits citing "recipe #110
speculative unroller" / the ppc_unroll_* pragmas mean THIS entry.)*

113. **The SPECULATIVE unroller is a separate pass from opt_unroll_loops —
    and it is pragma-controllable. NEW FUNCTIONAL PRAGMAS (GC/2.0 strings +
    probe-verified): `#pragma ppc_unroll_speculative on|off`,
    `#pragma ppc_unroll_factor_limit N`, `#pragma ppc_unroll_instructions_limit
    N`, `#pragma opt_unroll_count N`.** (task #15; objDrawFn_80061f0c
    77.6->93.8, objSeq_onMapSetup 76.6->81.2, curves_getCurves 84.9->97.5.)
    Signature of the pass: `srwi rC,count,1; cmplwi; mtctr; beq remainder`
    + x2-duplicated body + `andi. rC,rC,1; beq end` + 1-wide remainder loop
    — a RUNTIME-count x2 unroll. `opt_unroll_loops off` (#98) does NOT
    touch it. Both directions:
    - CURRENT unrolls / TARGET doesn't -> wrap the fn in
      `#pragma ppc_unroll_speculative off` ... `#pragma ppc_unroll_speculative
      on`. ⚠️ `reset` is a SYNTAX ERROR for these pragmas (reported at a
      misleading later line, masquerading as an ICE at a closing brace) —
      restore with `on` / an explicit N. `opt_unroll_count reset` IS valid.
    - TARGET unrolls / CURRENT doesn't -> the import hand-wrote the
      pair+remainder loops (Ghidra decompiled the unrolled binary
      literally). ROLL IT BACK to one count-up loop and let the pass
      regenerate the exact shape (curves_getCurves: pair-do-while +
      `remaining &= 1` + tail-do-while collapsed to one for-loop; outPoint
      in INDEX form per the #160 direct-addi tell; keep the import's named
      count local — the count web colored as a named local (r6), the bare
      guard expression makes it a compiler temp (r3)).
    PROBE TRAP: a /tmp probe compiles at whatever pragma state the probe file
    declares; the in-tree fn inherits the FILE's effective stack state -- a
    probe that scores 0.98 can land at 58% in-tree because the in-tree region
    lacks the probe's `ppc_unroll_speculative off` (fn_8004B31C). Carry the
    full pragma set into the probe AND re-A/B in the real TU before trusting
    a probe score.
    Project sweep (srwi-,1+mtctr signature diffed target-vs-current): only
    2 fns had current-only unrolls, 1 had target-only — all 3 fixed. The
    sweep script pattern is in commit b3fd48c41/f99dce7d2 messages.
    **FACTOR-mismatch addendum (modelWalkAnimFn_800248b8 80.0->88.0): when
    the speculative pass picks a SMALLER factor than target (ours x4
    srwi-,2/andi.-3 vs target x8), raise `ppc_unroll_factor_limit 8` AND
    `ppc_unroll_instructions_limit 256` TOGETHER — either alone is INERT
    (factor-limit alone, instructions-limit alone, and `opt_unroll_count 8`
    all probed no-op), and `ppc_unroll_speculative off` KILLS the unroll
    entirely rather than handing the loop to opt_unroll_loops (68.6%,
    runtime counts are speculative-only). Restore with explicit values
    after the fn (no `reset` per the syntax-error caveat above). Residual
    shape note: the speculative srwi/andi prologue+remainder differs from
    the older compare-8-first/subf-remainder shape some targets show
    (MP4 has no instance of the latter; #28's count-down header lever does
    not flip it) — that 1-2% stays.

114. **No-op CONVERSION NODES split VN webs at zero codegen cost — the
    general GVN-key splitter (cracks fctiwz-remat AND distributive
    factoring).** *(Numbering note: landed as "#112" in commit d9e799e23's
    message, racing the reconciliation 2b25af170; renumbered to #114 per
    the ledger — #112 is the displacement-fold K-grouping crack.)*
    (task #13.) MWCC's GVN is value-keyed, but the key is the
    expression tree INCLUDING no-op arithmetic-type conversions: a
    conversion through a DIFFERENT-RANK type creates a persistent node that
    blocks merging while emitting nothing. #94's "no-op cast chains fold"
    holds for POINTER casts only.
    - **`(int)(f64)volf`** re-executes a bare `fctiwz; stfd; lwz` where a
      plain `(int)volf` VN-reuses the earlier conversion via `mr` (f32→f64
      register widening is free; fctiwz-on-double is the same opcode).
      `(int)(f32)(f64)x` does NOT work — emits a real frsp.
      (Sfx_UpdateObjectChannel3D 93.26→95.94, supersedes #97's f32→int
      "no spelling found" caveat.) UNSIGNED sibling: `(int)(u16)x` splits
      a u8 ZERO-EXTENSION's VN key (fresh per-use clrlwi) where
      `(int)(long)x` gets folded (CF sweep).
    - **`e * 48 + (int)(long)(c * 48)`** keeps SEPARATE mulli products
      where the plain distributed spelling gets re-FACTORED to
      `(e+c)*48` (add; mulli) — the (int)(long) sandwich blocks the
      distributive re-association. Pair with explicit shift spelling
      (`((e * 3) << 4)`) when target keeps mulli-3 + slwi-4 unfused.
      (dll_0B_func04 92.27→92.87, site byte-exact — closes the
      "distributive factoring VN-internal" negative.)
    - **Put the MULTIPLY INSIDE the sandwich to split a shift's VN key at
      zero cost: `(int)((long)x * 8)`** emits ONE slwi under a fresh VN key
      (the (long) node launders the operand, the fold still combines to a
      single shift); the whole-expression form `(int)(long)(x * 8)` blocks
      the shift-combine and emits TWO shifts. Use when a scaled index is
      VN-shared between a loop condition and its body (or any two sites)
      and target re-derives per site (pi_dolphin heap sift-up loops,
      fn_8004B31C/fn_8004AB5C).
    Scope notes: works on RUNTIME values only (constants fold through
    conversions in the front end — the li-fresh-vs-merged small-constant
    store class is NOT crackable this way); GLOBAL re-reads in call-free
    ranges still need `volatile` (type/address launders on loads fold —
    probed (u32)-lvalue, (int)(long)-value, (int)&-address; only the
    load-INSTRUCTION-changing u16-vs-s16 cast differs, and that changes
    lha/lhz). Same boundary for CR0 REUSE: repeated FP compares on the
    same operands (else-if chains) need the volatile launder to re-emit
    the fcmpo — `*(f32 *)&` and `(f64)` are VN'd through (CFlevelControl).
    Sibling of #83a (launders) and #59/#78 (FP reassociation);
    same mechanism family as #110/#111.

115. **CALLEE-DECL PARAM WIDTHS shift the caller's WEB CREATION ORDER at
    zero instruction cost -- the first source-side lever on the #108
    within-class scramble (the "IR creation-order" residual).** (task
    #12; Music_Update 97.78->98.70 from ONE block-scope decl line.)
    Mechanism, probe-bisected: when a value flows into a call argument
    with an explicit narrowing cast (`sndSeqVolume(0, (u16)(v < 500 ?
    500 : v), h, 1)`), the EXTERN's param type decides whether the cast
    creates a persistent conversion node (int param -- cast node feeds a
    widening: extra IR web) or is ABSORBED (matching u16 param: no
    node). The nodes emit NOTHING (instruction streams byte-identical)
    but shift the multi-def webs' creation order -- scrambling/restoring
    the #108 within-class saved-reg ranks for exactly the values that
    flow into the call. #114's conversion-node insight applied to the
    ALLOCATOR side instead of VN.
    - Music_Update: engine_shared.h's Ghidra-flattened `sndSeqVolume(int,
      int,int,int)` scrambled 8 webs; the true MusyX-shaped narrow form
      `(u8 volume, u16 time, u32 handle, u8 mode)` (matching
      synth_handle.c's pre-existing #57 block extern) restores TARGET's
      clean init-order ranks. Applied as a #57 block-scope extern inside
      Music_Update only -- sibling callers/the all-int definition
      untouched. Probe trail: v6 (only sndSeqVolume narrow) = target
      coloring; v7 (only Stop/Mute/Continue narrow) = scrambled; sized
      vs incomplete array decls, pragma stack depth, TU dummy padding,
      and prefix fn bodies ALL inert (82 bodies stubbed -- scramble
      persisted; header decl bisection found it).
    - DIAGNOSTIC METHOD (general, reusable for any parked rotation):
      extract the fn + its statics into a standalone /tmp TU with
      MINIMAL hand-written decls and exact unit flags. If the probe's
      coloring matches TARGET, the fn text is right and a DECL in the
      TU's header set is the perturber -- bisect decls, not spellings.
      If the probe matches OURS, the perturbation is in the fn/statics
      text itself.
    - Where to suspect it: any rotation where the mis-ranked webs feed
      call args through casts, especially against Ghidra-flattened
      all-int prototypes (grep the fn's callees' decls vs their defs/
      upstream MusyX/SDK signatures; #84 cross-caller arbitration picks
      the real one). Candidate retries: partfx_update's top-block order,
      the audio 85-93 band, Curve_BuildSegmentLengthTable
      (Curve_SampleSegmentPoints' 8-param decl).
    - Residuals NOT this class (Music_Update's remaining 1.3%): two #92
      branch-over-branch sites target-side (task #16's family) and the
      loop-3 ch/i cross-pairing (induction-affinity, #108 -- callee-sig
      A/Bs inert on it).
    - SCOPE (sweep results): #115 requires CALL-ARG conversion sites --
      CALL-FREE leaf rotations are out of reach (hwChangeStudio,
      s3dInsertActiveEmitter: the audio band's small rotations are
      mostly leaves; decl-order/un-naming/launders A/B'd inert on both,
      and un-naming hwChangeStudio's voice alias broke isel per #30 --
      the named alias is load-bearing there). partfx_update's top-block
      order also resists (#114-style (long) node on the p2 copy inert;
      prefix-stub + include bisection clean = fn-text class).
      s3dInsertActiveEmitter's real divergence is a target-side
      materialized entry copy (`mr. r8,r4` = `scan = next` kept where
      ours copy-props it away; assign-split and (int)-launder both fold
      per #94) -- #110-family, possibly per-fn O1 in the original; bank it
      and try the #110 per-fn O1 wrap next.

116. **Embedded-assign in the STORE ADDRESS (`*(p = &arr[K]) = value;`)
    reproduces T's value-BEFORE-address emission under scheduling-off.**
    (task #17; fn_801821FC 97.24->98.89, gcrobotlightbea.) When target
    shows `lfs f0,src; addi rX,r1,K; stfs f0,0(rX)` (the value load
    BETWEEN the address materialization and the store) but the natural
    two-statement form (`endY = &endPoints[1]; endPoints[1] = obj->y;`)
    emits `addi rX; lfs; stfs` (address first, statement order under
    scheduling-off), fold the pointer init INTO the store's address
    position: `*(endY = &endPoints[1]) = obj->y;` — MWCC evaluates the
    RHS first, then the embedded address def, then stores through it.
    Works for constant stores too: `*(axes = hitResults.axes) = -1;`
    gives `li r0,-1; addi r29,r1,216; stb`. #40-family (embedded assign)
    aimed at EMISSION ORDER rather than reload elimination. CAVEAT: the
    embedded def reclassifies the pointer's web into the temp class
    (#107 round-2) — the saved-reg NUMBERS of the pointer trio may
    permute against neighbors (cross-class interleave, the #108 open class);
    A/B-verify the order win outweighs the renumber (here +1.65pp).
    Sibling probe that FAILED on the same fn (this spelling is spent — try a
    different axis): #77 void*-param cast-copy to re-rank the obj param
    (98.89->98.12).

117. **Embedded-def ternary `t = (x < (t = lo)) ? t : ((x > (t = hi)) ? t : x)`
    lands the clamp bounds DIRECTLY in t's callee-saved home.** When target's
    #91 clamp loads each bound INTO a saved FP reg (`lfs f31,lo; fcmpo f1,f31;
    ... lfs f31,hi; fcmpo; fmr f31,f1`) because the result variable lives
    across later calls, the plain ternary computes the whole clamp in a
    VOLATILE temp and copies once (`fmr f31,f2`, +1-2 instrs, bounds in wrong
    regs). Embedding the bound assignments (`(t = lo)`) makes each bound load
    target t's home directly and the arms coalesce in place — the #103
    embedded-bound trick aimed at a saved-reg-homed result. Safe scope per
    #84: expression operands, NOT call args; single-use embedded values.
    SCOPE CAVEAT: REGRESSES on VOLATILE-homed clamps — strictly a saved-home
    tool (2 probes: DR_CloudRunner_stateHandler05 spd 97.63->97.54,
    firstPersonDoControls zoom/fovTarget 97.64->96.78, both reverted; when
    the plain #91 form already colors right, leave it).
    (task #16: fn_802B0EA4 t-clamps -> f31 byte-exact; fn_802A5384 same
    shape.) RELATED caveat from the same session: a branchy ternary inside a
    larger EXPRESSION always hoists to statement front — compound `*=` does
    NOT un-hoist it; NAMING the leading operands as pre-statements
    (`v430 = lhs; diff = a - b;` then the assignment) is what pins the
    fsubs/loads BEFORE the ternary (fn_802B0EA4 unk834 block, +0.4).

118. **POINTER-VALUED nested ternary for fully-unrolled free-slot scans —
    `cmplwi 0; bne next; b found` per copy with the result in the walked
    reg.** When target shows N unrolled copies of `lbz r0,off(rW); cmplwi
    r0,0; bne next; b found; next: addi rW,stride` ending `li rW,0; found:`,
    the source is an N-level pointer-valued ternary, NOT nested ifs (the
    import's N-deep nested-if manual unroll folds every level to a single
    `beq found`):
    `freeSlot = (slot->f == 0) ? slot : ((++slot)->f == 0) ? slot : ... : NULL;`
    The #91 value-join machinery emits the branch-over-branch per level with
    EMPTY in-range arms because the join value already lives in the walked
    reg. CRITICAL: the walked operand must be a SEPARATE dead variable
    (`slot`) from the ternary RESULT (`freeSlot`) — self-walking the result
    (`(++freeSlot)->f`) routes the walk through a temp web and emits a
    `mr` per arm (+N instrs); with the split the result coalesces onto the
    walker reg byte-exact. For other statement-position int b-over-b sites,
    re-read #109(d) first (single-case switch — but switch compares degrade
    cmplwi->cmpwi; A/B which residual is smaller) and #92 (variable-compare
    loop-break stays capped). Pairs with #107 un-naming for adjacent
    re-derived address args (the `path` buffer re-derive). (task #16:
    loadGameTextSequence 90.85->98.06, gameTextLoadForCurMap 88.18->95.13,
    gameTextRun chain byte-exact; 3x 8-level chains, commit 546beb98b.)

119. **VARIABLE RECYCLING is a recoverable signature: target reusing a DEAD
    variable's home register for a "new" value = the original source
    REASSIGNED that variable; write the reassignment, not a fresh local.**
    GUARD (wmsun campaign): GC/2.0 -O4 LIVE-RANGE-SPLITS same-variable
    disjoint webs, so #119 only pins the home when the reuse CHANGES
    LIVENESS at the allocation decision point (e.g. keeps the old value
    live into the def that would otherwise coalesce); a 4-way reuse of one
    dead var did NOT keep the webs in one reg. Minimal merges (one
    variable, one boundary) work; bulk merges don't.
    (task #18, objhits reconstructions -- 6 instances, each fixing placement
    AND coloring at once.) Read the target reg: when a mid-fn value lands in
    a register that previously held a now-dead param/local (f28=t becomes
    the reflection factor, f29=axial becomes the new length, f22=sumSq
    becomes len/depth, f14=bb becomes rs, r26=hit becomes idxB), a fresh
    named local CANNOT reproduce it -- the fresh single-def web gets
    forward-substituted into its consumer (statement placement collapses)
    and/or colored elsewhere. Reassigning the dead variable makes the web
    MULTI-DEF, which (a) blocks forward-substitution (#94 -- the def stays
    a separate statement at its source position) and (b) pins the home reg.
    PARAM reassignment is the strongest form (t/axial in
    CalcSkeletonResponseXZ: `t = lbl + (one - t) * lbl2;` reproduced the
    separate factor statement where every fresh-local spelling folded into
    the next expression). BYTE-INVISIBILITY caveat (CF final maverick):
    web construction SPLITS disjoint def-use chains regardless of naming —
    recycling a dead variable is byte-identical unless the dying value's
    web actually CONNECTS to the new def (liveness overlap at the
    allocation decision, per the wmsun guard).
    ⚠️ THE CAVEAT IS TOO BROAD — same-variable affinity CAN pin fully
    DISJOINT webs (cfmaincrystal fn_8019D9F0 → 100, unit 100.0). The tail
    pylon loop's counter/value pair colored r27/r28 with a fresh `s16 v`
    local; target keeps the reused `i` at its first-loop r29 AND puts the
    value in `idx`'s old r27 — BOTH webs disjoint from their earlier
    lives, no liveness overlap, yet reusing the two variables (`i` for
    the counter, `idx` for the loaded temp) landed both regs exactly,
    zero instruction change. So when a TAIL/secondary loop's webs sit in
    registers that earlier loop variables owned, try the recycle even
    when liveness clearly does NOT connect — it is cheap and sometimes
    the whole fix. (The GC/2.0 affinity tiebreak evidently survives the
    live-range split in some web-pressure states; the wmsun negative and
    the prisonguard re-test show it is not universal — A/B per fn.) Diagnostic order: when a single-use local's
    statement keeps folding into its consumer against target, FIRST check
    whether target's result reg was home to a dead earlier variable --
    cheaper than #94's phi tricks and plausibly the original source (tight
    hand-reused locals). Sibling of #107 (un-naming) and #108 (class
    pools): this is the NAMING side -- merge webs the original merged.

120. **Import-SPLIT aggregates: Ghidra routinely splits ONE stack array into
    "array + adjacent scalars" (or two arrays) -- diagnose via whole-object
    vs interior addi shapes, DSE'd store blocks, and un-reachable layout
    orders; rejoin to fix frame layout AND store liveness.** (task #18;
    extends #67(b)/#79.) Three tells, each independently sufficient:
    (a) **whole-object vs interior address**: `aPtr = arr;` emits a DIRECT
    `addi rS,r1,K`; `aPtr = &arr[k]` (interior) emits `addi r0,r1,K; mr
    rS,r0` when register-homed -- so a target DIRECT addi into the middle
    of your buffer = the buffer boundary is wrong, that address is a
    whole-object base (CalcSkeletonResponse*: projBuf[9] + 3 accum scalars
    were ONE float[12]; the import's separate decls placed the pair in an
    unreachable layout order through every decl permutation). CAVEAT: when
    the pointer is STACK-homed the interior form is `addi r0; stw r0` --
    indistinguishable from whole-object; use tells (b)/(c).
    (b) **DSE'd store block**: a target store-run your compile silently
    drops (build green, stores absent) = the import split a written-only
    tail off an aggregate whose base escapes -- rejoining under the
    escaping base keeps the stores live (CheckHitVolumes defs[8]: the
    def-B block defs[4..7] only lives because defA=defs escapes; as a
    separate defB0[4] MWCC dead-store-eliminated it).
    (c) **layout order unreachable by decl permutation**: when two
    same-kind locals refuse every decl-order/type permutation (the
    accumA-vs-projBuf 80/116 pair), suspect they are one object.
    Frame-size deltas (#67) localize WHICH buffers; sibling-fn layouts
    disambiguate sizes. After rejoining, spell tail accesses as
    `arr[k+i]` or via a pointer local per target's addressing.

121. **Preheader-hoist shape `[int li inits][lfd conv-bias + lis][f32 lfs
    constants]` = the f32 constants were IN-LOOP LITERALS, not preheader
    named locals — literals LICM across body calls; named extern globals
    don't.** (task #12; modelCalcVtxGroupMtxs 96.07→98.84,
    sc_totembond_spawnGameBitOrbs 97.22→99.01, firefly_update 98.29→100.)
    Mechanism, probe-verified: a `f32 scale = lbl_X;` preheader statement
    emits its lfs at STATEMENT position (before any compiler hoists, which
    are appended) and the named global can't be hoisted out of a
    call-bearing loop (mutable alias); a LITERAL (`0.25f`, `180.0f`,
    `3.1415927f`) is a compiler-owned pool constant and IS hoisted across
    body calls — landing exactly in target's after-the-bias position. The
    @NNN-vs-named reloc difference is score-neutral (#70) as long as the
    literal's bytes match the original pool value (read them out of the
    retail dol). Order/coloring rules that fall out (use to fine-tune):
    - Hoist-web FP coloring is ASCENDING in creation order (bias created
      first → f29, next const f30, ... — opposite of #45's decl rule,
      which is for named locals).
    - Hoist DISCOVERY is per-STATEMENT, and within a statement bottom-up
      by expression tree with the node's CONSTANT before a conversion's
      bias (`conv * K` discovers K, then bias; `(K1 * conv) / K2`
      discovers K1, bias, K2). To get the BIAS hoisted before a
      multiply's constant (target `lfd bias; lis; lfs K`), SPLIT the
      conversion into its own statement: `w = (f32)x; w *= K;` — a
      single-use fresh temp does NOT work (copy-prop folds it back and
      the discovery reverts; the #85/#94 fold family).
    - A post-loop use of the same constant CSEs onto the hoisted web
      (spell it as the same literal — firefly's second `= 180.0f`).
    - Non-FP constants behave the same: a big case constant inside the
      loop's switch (firefly 0x7000B) hoists as a GPR web among the same
      group.
    Tells: named lfs/lfd AFTER compiler hoists in target's preheader;
    Ghidra imports systematically name these (`scale = lbl_X;` head
    statements) because the shared .sdata2 pool labels look like globals.
    Residual fmuls operand order from the self-accum compound form
    (`fmuls fD,fD,fK` vs target `fmuls fD,f0,fK`) is canonicalization-
    internal (operand swap, fresh temps probed inert) — bank it.
    **EXPRESSION-VARIANT addendum (task #16, miner-1): in-loop literal
    EXPRESSIONS hoist like bare constants — including an invariant
    literal-op-PARAM division.** The import-named head local
    `invPeriod = lbl_803DF350 / period;` was really `65535.0f / period`
    written INLINE in the loop: LICM hoists the whole fdivs into the
    preheader hoist group (after the int hoists, ascending FP coloring
    with the other literals). WM_newcrystalFn_800969b0 81.4->98.8 from
    converting a 4-local head group (0.0f/1.0f/65535.0f/period/0.5f) to
    inline literals+expression. FALSE-POSITIVE GUIDE (census noise ~4/7
    in the heuristic list — verify the asm tell first): (a) fns inside
    `#pragma opt_common_subs off` regions — the pragma BLOCKS literal
    hoisting entirely (no fN webs at all, hard regress) AND is
    load-bearing; the named locals are correct there (fn_801E991C);
    (b) mutable-global expression inits (`frac = lbl - (f32)fi`);
    (c) min/max ACCUMULATOR inits (`nearest = lbl;` reassigned in-loop);
    (d) address-taken outparam inits (`f32 radius = lbl; f(&radius)`).
    All four read as `f32 x = lbl_X;` to the regex but are real named
    locals.

122. **At 99.9%, one immediate/offset diff is often imported STRUCTURE,
    not MWCC magic: verify switch case bounds and field ownership before
    allocator grinding.** Two cheap checks cracked current near-misses:
    (a) **Dead empty switch cases can widen MWCC's range guard by exactly
    one.** If target and current are identical except a compare immediate
    in the generated switch guard (`cmpwi ...,3` target vs `...,4`
    current), remove the highest empty imported case and remeasure. Ghidra
    often keeps a no-op case that the original source did not spell. This
    took `androssligh_update` 99.98→100 by dropping dead `case 3`, leaving
    cases 0/1/2 and matching the target's upper-bound check.
    (b) **Single-byte store offset after `memset` is likely the wrong
    struct member, not a scheduling cap.** If a clear/init function is
    byte-identical except `stb K,offA` vs `stb K,offB`, read the struct
    layout and nearby uses before trying source-order tricks. In
    `curves_clear`, target stored the initial `5` at offset `0x258`
    (`heightPadding`), while the import wrote `surfaceFlags` at `0x260`;
    assigning the real field took 99.97→100 and improved the layout
    documentation.

123. **FP-register residuals can hide WRONG CONSTANT ownership: when target
    keeps an earlier constant live in `f1` while current reloads a later
    `scale`/parameter constant into `f1`, audit which constant each
    expression should semantically use.** In stack-builder functions with
    repeated initializers, Ghidra often points every later expression at the
    most recent visually-similar float label. The target tells you otherwise:
    if `buf.scale = lbl_Scale` loads/stores through `f0`, but the following
    optional position offset does `fadds f0,f1,f0` without reloading `f1`,
    then `f1` is still the earlier base/zero constant, not the scale.
    `dll_76_func03` and `dll_77_func03` both sat at 99.93 with exactly this
    shape; changing the position-offset adds from `lbl_803E0C54/6C` to the
    earlier `lbl_803E0C4C/64` took both to 100 and fixed the behavior.

124. **Classify partials by first REAL diff before grinding: the current
    unmatched tail is dominated by value/register spelling, branch/block
    structure, and stack/temp layout.** Run
    `python3 tools/categorize_near_misses.py --min-pct 0 --max-size 0 --limit 2500`
    to bucket every `<100%` function from `report.json` by its first normalized
    instruction-diff symptom and print dominant categories per source file.
    Current full-pass counts: `798` GPR register/value spelling, `495`
    branch-target/block-layout, `320` stack/temp layout, `309` mixed structural
    drift, `117` register-coloring cascades, `59` off-by-one/immediate
    constants, then smaller signedness/FP/loop-bound buckets. Sweep order:
    near-100 exact mistakes first (`off-by-one`, `loop bound`, signed compare,
    FP constant ownership), then file-wide dominant buckets. Biggest source
    clusters: `player.c` is register/value + branch/block; `gameplay.c` is
    mixed structure + stack layout; `track_dolphin.c`, `curves.c`, `model.c`,
    `shader.c`, `objprint.c`, and `modgfx.c` are mostly register/value
    spelling. **Validation pass:** taking the
    `compare width/immediate/sign` bucket literally exposed `hwIsActive` as the
    wrong signed declaration (`int hwIsActive(int)` vs MusyX/reference
    `u32 hwIsActive(u32)`). Aligning the declaration/definition and making the
    `synth_voice.c` caller explicit took `EventHandler` 99.40→100 and
    `macHandle` 99.27→100, while `macStart` improved to 99.99. So the category
    is actionable: audit callee return/param signedness first, especially when
    the first diff is `cmpwi 0` vs `cmplwi 0`.

125. **Loop-tail guard polarity controls `cmpwi K; blt` vs `cmpwi K-1; ble`:
    when target increments then continues on `< LIMIT`, spell the positive
    continue guard, not the equivalent exit guard.** Signature: only the loop
    tail differs, target has `addi i,1; cmpwi i,8; blt loop`, current has
    `addi i,1; cmpwi i,7; ble loop`. Rewrite:
    `if (i < 8) { continue; } return 0;` instead of
    `if (7 < i) { return 0; }`. This took
    `mapBlockBounds_HasCornerPastDepthThreshold` 99.976→100; the source is
    semantically identical, but MWCC does not canonicalize the two branch
    forms to the same compare immediate.

126. **Param-TYPE pool classing: a POINTER-typed param colors into the COPY
    pool (top, r31-ward) while an INTEGRAL param colors into the PARAM pool
    (bottom) — independent of how its uses are spelled. Read target's
    prologue coloring to RECOVER the original parameter type.**
    (wmspiritplace_SeqFn, 10-variant battery, byte-proven both directions.)
    A `GameObject *obj` param stole r31 from the loop counter under EVERY
    use spelling — including ZERO direct refs (every site laundered
    `(GameObject*)(int)obj`), void*/copy-local forms, register/const/K&R
    defs, #61b decl shuffles, and #114 (int)(long) sandwiches on
    neighboring webs — while `int obj` + per-use `(GameObject*)obj` casts
    landed the canonical bottom-up order (params r28/r29 in decl order,
    copy r30, multi-def counter r31). So the pool selector is the param's
    DECLARED TYPE CLASS, not its use binding (sharpens #77/#108/#114).
    SIGNATURE-RECOVERY READ: when target keeps the obj param in the BOTTOM
    param pool (obj=r28 under state/counter), the original took a WORD
    (`int obj`); when it colors copy-class with/under the state copy
    (wmspiritplace_update: obj=r30 under state=r31), the original took a
    typed pointer. Both forms in the SAME TU is normal — read each fn's
    prologue and type the param accordingly; per-fn cast noise on an int
    obj is then FAITHFUL reconstruction, not import damage.
    NOTE — decl-order stays LIVE for the non-param webs even while the
    param web is stuck: under the rotated pointer param, swapping the
    state copy's decl above the loop counter still landed state in
    target's r30 (19→14 diff regions). Fix what decl-order can reach
    before judging the param type.
    ADDENDUM — per-fn `#pragma optimization_level 2` CAN land the
    typed-pointer form byte-exact even in call-bearing fns (corrects
    #110's blanket "O1/O2 wrecks fns with calls": O2's ALLOCATION was
    target-exact here, switching to decl/creation-order coloring), but
    O2's weaker isel needs unnatural respellings to match O4 output:
    u8 locals keep a redundant clrlwi (retype the local `int`), and
    member-array reads emit add+lbz-disp where O4 folds onto the index
    (`actor->eventIds[i]` only matches via the raw int-domain sum
    `*(u8*)((int)actor + i + 0x81)` under O2). When the typed-O2 route
    demands unnatural spellings for lines that match naturally at O4, the
    integral-param O4 reading is the faithful one — prefer it.

127. **`extern const f32 lbl_X;` = a STORE-ALIASING EXEMPTION — cross-
    statement load CSE without naming a local.** When target loads a float
    symbol ONCE and keeps it live across intervening STORES (sth/stfs)
    while the plain `extern f32` form re-loads after each store (MWCC
    assumes the store may alias the global), adding `const` to the extern
    exempts the load from store invalidation so the CSE survives — AND the
    value stays an UN-named temp-class web (a named local achieves the
    same CSE but flips the FP pair per #107's class model). rope → 100,
    CRsnowbike clamp (near-100 sweep); independently rediscovered on
    CFlevelControl lbl_803E3DE8 (load survives the stfs → CSE + FP
    numbering). Decl-only change, A/B per unit —
    `const` on a symbol other fns WRITE would be wrong; check writers
    first.
    **SB-lane confirmations (4 units): the CSE'd value can sit in f1 — the
    FLOAT-ARG register — so later calls passing the same constant need NO
    reload at any call site** (SB_ShipMast_update: one lfs feeds 3 stfs AND
    two ObjAnim_SetCurrentMove f1 args → 100). More wins: sbminifire 0.8
    (velocityX + rootMotionScale), sbcloudrunner ×3 consts, sbgalleon 56CC.
    **CAVEAT — the const can CSE-OVERSHOOT a SIBLING fn in the same TU**
    (galleon fn_801E1588: target reloads 56CC at one compare, the const made
    ours hoist it): fix per-site with the #81 launder `*(f32 *)&lbl_X` at the
    reference target reloads — don't revert the const. Always re-ndiff every
    <100 fn in the TU after adding a const.
Field-tested across the object DLL near-100 tier (src/main/dll/{baddie,DIM,DR,CF,
WC,ARW,MMP,WM,DB,SH,...}). RELIABLE here — reach for these first:
#12 bitfield single-bit clear (rlwimi-from-bitfield, e.g. `((Flags *)&f)->b80 = 0`);
#14/#3 width WHEN it's a TRUE type mismatch (call-result/pointer null-test → `(void*)x
!= NULL` for cmplwi; the shared `BaddieState.eventFlags` u32 tested signed → `(s32)`
cast for cmpwi; the shared-field sites already use the `*(int *)&` launder convention);
#15 array-index `(s8)arr[off]` vs `*(s8*)(p+off)` for byte sign-extend ORDER
(target `lbz r0; extsb r3,r0` = array-index form; ours-via-deref = `lbz r3; extsb
r3,r3`); #29/#84 arg-eval reorder; #5 decl/init SPLIT (decl-order fixes the coloring,
init-order fixes the emission/load-order — lands "coloring right but 2 loads swapped"
residuals); #121 defer const-load (move `f32 k = lbl;` AFTER an earlier RMW when
target loads the const lazily). RESISTANT here — bank on sight after ≤2 tries, do NOT
grind: #82 FP-expr-temp operand-order (commutative-reassociation-internal — fmuls/fsubs
flips INERT); FP-compare-operand flips (regress as often as help); 2-var GPR coloring
swaps that SEESAW (fixing one site moves the divergence to the adjacent instr —
scarab_render, imicemountain decrement); #61c walker/value pairs (need index-form loop
restructure, low ROI); #108 small-constant rematerialization. CONFIRMED NEGATIVE: the
flag-word #74 bulk-sweep that worked on player.c flags360 has NO object-DLL analog —
there is no single recurring materialized-mask field at the near-100 tier.

**#84-objanim mini-sweep (confirmed, ~19 object-DLL fns +0.3 to +3.2pp).** The two
hot ObjAnim dispatchers have float-first real signatures but ALSO object-first typedefs
already in objanim.h: `ObjAnim_SampleRootCurvePhase(f32,obj,out)` →
`((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)(obj,f32,out)`, and
`ObjAnim_AdvanceCurrentMove(f32,timeDelta,obj,events)` →
`((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj,f32,timeDelta,events)`
(use `ObjAnimAdvanceObjectFirstFn` for the `double`-arg sites). The cast flips caller
L2R eval to obj-before-float (target's `mr rN,obj; fmr fN,..` prologue/setup shape) and
is ABI-NEUTRAL (float/int are separate register banks, so each arg keeps its register
regardless of position; callers' own externs are untouched). GATE PER-FN: flip ONLY
partials whose call shows mr-before-fmr; A/B and keep only if fuzzy improves — ~1/3 of
sites are inert (already-100 sites leave alone; some partials' divergence is elsewhere)
and an occasional site REGRESSES (SCchieflightfoot SHthorntail_update). Same applies to
the `ObjAnim_AdvanceCurrentMove` family per #84. Big wins seen: DBstealerworm
SB_ShipMast_update +3.2, sandwormBoss sandworm_turnTowardTargetAnim +2.4.

**OPEN — branchy-arg pre-eval hoist (the in-place L2R ternary arg).**
When target evaluates a branchy ternary CALL ARG at its L2R slot (args 1-7
set up first, the clamp 8th, then 9-10 — ObjHits_CheckSkeletonPair's two
CalcSkeletonResponse sites), no C spelling found so far reproduces it: MWCC
pre-evaluates branchy args at the call statement's FRONT. Probed broadly
(task #16): all 9 GC compiler versions x peephole/scheduling states, inline
ternary, named arg-locals for the leading args (gets the conv+loads above the
clamp but the simple mr/addi args still sink below it). Naming args 2/5/6 as
locals recovers MOST of the order (+7pp there) — do that, pocket the gain,
then bank the ~6-instr residual and keep it on the retry list. Recognize by:
branchy arg + strict-L2R target (and check the BOUNDARY exception below first
— the hoist often doesn't fire at all).
**BOUNDARY (task #18): the hoist does NOT fire when the args preceding the
branchy slot are LOADS (stack-homed params/locals, lbz/lwz chains) rather
than simple mr/addi setups -- and a shared base-pointer local (#112
K-on-base, `pb2 = &spheresB[idxB * 4];` before the call) keeps the arms
cheap enough that the ternary evaluates IN-SLOT (CheckHitVolumes
RecordPositionHit y-arg, +3pp in one edit). Try the base-local + load-y
args shape BEFORE banking this as an open residual.

**OPEN CLASS — the addi-fold (3-use threshold) on big-offset slot-indexed
fields.** At 3+ uses of `t->bigTable[slot]` (member offset > 16 bits), MWCC
folds the @lo into the saved base (`addi rB,rB,lo` + `0(rB)` accesses under
peephole-off; `lwzu` first-access under peephole-on) where target keeps the
@lo as a PER-ACCESS displacement off the shared `(base+ha+idx)` partial
(`add rB,(addis base,2),idx4; lwz lo(rB)` repeated). 2-use webs stay
disp-form (recipe #18/#112 shapes hold); at 3+ the full-address VN web wins.
Probed (task #16, /tmp/probe*.c battery, mapLoadDataFile): `opt_common_subs
off` flips to per-ACCESS re-derivation (addis+slwi+add each — over-shoots);
versions 1.0-2.5 identical; phi'd slot inert; (int)-launder only per-site;
member vs pad0-subscript origin only moves WHICH operand takes the addis.
No spelling found YET that keeps the shared partial AND per-access lo at 3+
uses — holds mapLoadDataFile at ~93 pending a new lever.
**Round-2 findings (task #12 — RECLASSIFIED as fn-context-bound, the
#108-dose family):** (a) minimal /tmp probes CANNOT reproduce the fold —
exact site replicas (3 same-address uses, call-crossing, same
struct/offsets, scheduling+peephole off, GC/2.0 flags) all compile to
target's disp-form in isolation; the fold only fires inside the real
8.4KB fn, i.e. a fn-global trigger like the #108 interleave dose. ALL
future probing for this class must be in-tree (the #113 probe-trap,
isel edition). (b) The #112 K-on-base laundered spelling
(`*(u32 *)((u8 *)((u8 *)t + 0x195D8) + (slot << 2))`) fixes the addis
OPERAND side (addis binds the base = target's shape) but NOT the fold,
and NET-REGRESSES in-context (93.33->92.00; emission order shifts
addis-before-slwi; the swapped-operand spelling canonicalizes
identically — both reverted). (c) The trigger involves same-ADDRESS
multi-use (lwz+stw read-write pairs), not constant site count: in the
SAME fn, MLDF_OWNER's 14 read-only big-offset sites stay disp-form
while MLDF_PTR's lwz+stw clusters fold. This is an open in-tree-only class
tied to the #108 fn-global state mechanism — bank the partial and re-attack
together with #108 when a fn-global lever lands.

## Foreign-compiler objects (GCC/SN ProDG): out of MWCC scope, matchable via a build-rule path

The retail dol links a small number of objects that were NEVER compiled by
MWCC -- they are GCC (SN ProDG family, older vintage than our bundled ProDG
3.5-3.9.3 / GCC 2.95.x; the idioms point at 2.7/2.8-era SN or Cygnus). MWCC
recipes won't move these because the toolchain itself is different — their
fuzzy% under MWCC is a floor of the WRONG compiler, not a skill issue, and
NOT a permanent dead end: they become matchable through the build-rule path
below once the owner greenlights it. The job here is to RECOGNIZE one (so you
don't spend MWCC effort on a non-MWCC object) and tee it up for the
foreign-toolchain route, not to abandon it.

Detection signature (any one is suspicious; three+ together is conclusive --
probe-verified against all 14 MWCC GC versions, task #19):
1. **`mflr r0` BEFORE `stwu`** in the prologue (MWCC always emits stwu first,
   every version/opt-level/pragma combination probed).
2. **`andi.` for CONTIGUOUS masks** (`&3/&7/&0x1f`) with cr0 unused -- MWCC
   always picks `rlwinm`/`clrlwi` for contiguous masks.
3. **`mcrxr cr0; addme.` decrement loops** -- MWCC never (MP4 corpus: mcrxr
   appears only in carry-flag tests after addc).
4. **`stmw r14`/`lmw r14` bulk saves** in a unit whose MWCC fns use
   `_savegpr_NN` helpers or inline stw saves.
5. **Creation-order register allocation** with params kept/modified in their
   ARRIVAL registers (r3/r5 reassigned in place), sequential r7,r8..r12,r14+
   homes, plus retained DEAD compares (identical-arm conditional residue --
   old-GCC weak flow opt).

Confirmed instances: **zlbDecompress** (main/pi_dolphin, at 42.5% under MWCC --
the Rare zlb INFLATE; GCC-buildable source reconstruction already staged in
docs/foreign/zlb_decompress_gcc.c) and **gap_03_80006C6C_text** (main/render,
~5KB unclaimed -- same signature, likely the DEFLATE/compress side of the
same Rare zlb library; N64 ancestor: dinosaur-planet decomp src/rarezip.c).
Path to 100% for these is an own-unit split + exact-vintage GCC + custom
build rule (the zlbDecompress source is already reconstructed for it) -- an
owner-level toolchain decision, so flag it for the owner rather than building
the rule yourself. When a new fn resists every MWCC recipe AND shows the
signature above, check its prologue order against its unit siblings to confirm
the foreign-toolchain ID, then route it to this path instead of more MWCC
probing.

## Compiler-emitted 64-bit / fixed-point math: a recognizable class

A function full of `__shl2i`/`__shr2u` runtime-shift helpers, `addc`/`adde`/
`subfe` long-long arithmetic, and unrolled rounding-division/reciprocal loops
(often 10×-then-7× `rlwimi` rotate sequences) is **compiler-emitted s64/fixed-
point math**. ⚠️ **LARGELY CRACKED — see recipes #98 and #109** (countdown
RMW loops, shift-count masks, pointer-deref halving, two-web temps). Apply
those first; the residual saved-reg/spill balance after them is the open part.
When the remaining divergence is allocator-internal,
commit your best clean-C partial, document exactly what's left, and keep it on
the retry list. A future recipe that cracks the remainder will make every such
function tractable at once — so a well-documented partial here is high-leverage
seed for that recipe.

## No `asm { }` blocks — ever

**Hard rule, no exceptions.** Inline `asm { }` is never an acceptable match
tool on this project, even for cases the playbook previously sanctioned
(materialized-mask `li`/`lis;ori` + `and`, GQR/MSR/HID0 `mtspr` ops, `rlwimi`
bit inserts, register-order forcing via `register` decls). If clean C won't
reach 100% today, **bank the partial as an OPEN problem and document the
residual** — there is always a C recipe for the divergence; we just don't know
it yet, and the documented partial is what the next recipe builds on. New C
techniques land in this playbook as they're discovered; asm escape hatches
don't. Banking is a checkpoint, never a verdict that the function is
impossible.

Previous reference commits using asm (`2e20e326`, `01400901`, `a42bb90b`) are
being reverted by the repo owner (see "Replace X flag asm with C" commits) —
do not cite them as precedent.

If a function is stuck below target because of an unknown-C divergence, the
correct action is:
1. Commit the highest clean-C partial you've reached.
2. Document the divergence (target asm shape vs your output) in the task
   notes or commit message — this is the seed for the next recipe.
3. Keep it on the retry list. The function gets re-attacked as new playbook
   recipes land; "stuck today" is never "stuck forever."

## Caller-side width controls extsb/extsh emission

| Source pattern | Emits |
|---|---|
| `void f(s8 type) { *p = type; if (type==2)... }` | `stb r4` + `extsb r0,r4; cmpwi r0,2` |
| `void f(int type) { *p = (s8)type; if (type==2)... }` | `extsb r0,r4; stb r0` + `cmpwi r4,2` |
| `void f(s16 v) { arr[i] = v; }` (with `u16 arr[]`) | `clrlwi r4,r4,16; sthx` |
| `void f(int v) { arr[i] = (s16)v; }` (with `s16 arr[]`) | `extsh r4,r4; sthx` |

Rule: when target's extsb/extsh appears on the *parameter side*, widen the
param type to `int` and cast at the use site. The narrow param type pushes
extension to the *use side* instead. For half-word stores, the array element
type also matters — `s16[]` triggers `extsh`, `u16[]` triggers `clrlwi`.

**Storing the constant `0xFFFF`: `*(u16*)p = 0xFFFF` emits `lis;addi` (full
materialization); `*(s16*)p = 0xFFFF` emits `li -1` (one instr short).** When
target materializes 0xFFFF via `lis;addi`, use the `u16` cast; when it uses
`li -1`, use `s16`. (november12.)

**HARD NEGATIVE -- the u16->s16 store-conversion `extsh` is NOT launderable.**
When target stores a halfword param raw (`sth r4`) and yours emits
`extsh r0,r4; sth r0`, no lvalue respelling helps: `*(s16 *)&dst = u16val`
STILL normalizes the u16 value (extsh kept). The only fix is the VALUE being
genuinely s16-typed -- flip the param/decl to s16 (ABI-neutral, promoted) and
gate it with a full-project .o-hash A/B (`find build -name '*.o' | md5sum`
before/after): objlib ObjHitbox_SetSphereRadius 94.39->100 with only
objlib.o changing project-wide. The import's `undefined2` (u16) param guesses
are a recurring source of this class.

## FP compare operand order picks the load registers

`fcmpo cr0, f1, f0` puts the LHS of the C compare in f1 and the RHS in f0,
which then drives the order of the two `lfs` instructions before it. If the
residual diff shows the two `lfs` lines swapped, flip the compare:
`a <= b` → `b >= a`. Booleans are identical; codegen is not.

## `extern T lbl[]` for `.data` labels, scalar for `.sdata`

| Section | Declaration | Addressing |
|---|---|---|
| `.sdata` / `.sdata2` / `.sbss` | `extern int lbl_xxx;` | `lwz r3, lbl@sda21(r0)` |
| `.data` (anything not sdata) | `extern int lbl_xxx[];` | `lis ha; addi lo` |

Writing the scalar form for a `.data` symbol mis-emits sda21 and breaks every
load/store of it. Check `config/GSAE01/symbols.txt` for the section.

**Passing a `.sdata` string BY ADDRESS — declare a SCALAR `extern char tag;` and
pass `&tag`** to get `addi r5, r13, tag@sda21`. The `extern char tag[];` array
form emits `lis;addi` (wrong) for the same symbol. (hotel5, sMmShowInfo tag →
matched the OSReport arg.)

**For an ARRAY-typed `.sdata`/`.sbss` symbol, give the extern a KNOWN SIZE to
get sda21.** An INCOMPLETE array `extern u8 lbl[];` emits far `lis;addi`; the
SIZED form `extern u8 lbl[8];` lets MWCC pick `@sda21`. (mike8 — sizing
lbl_803DC8D0[8]/lbl_803DC8C0[2]/lbl_803DC8B8[2] lifted resetLoadedMaps 88→94.3%,
~+3% each on two fns. Read the size from symbols.txt.)

**Sized-array fails for `.sdata` objects >~8B — use scalar extern + `(&sym)[i]`
indexing instead** (sdata threshold). For larger pooled-data arrays, the
sized-array form mis-emits FAR `lis;addi`. See recipe #47 for the full
two-direction recipe (also covers when target USES far `lis/addi` and your
scalar extern wrongly emits `@sda21` — declare it incomplete to force the
far form).

## `#pragma dont_inline on` for callees that live in the same TU

With `-inline auto`, MWCC inlines small functions into their callers within
the same `.c`. If the target binary keeps the `bl callee`, the caller will
never match. Wrap the callee:
```c
#pragma dont_inline on
void small_helper(...) { ... }
#pragma dont_inline reset
```

**CAUTION — `dont_inline on` disables inlining in BOTH directions: it stops the
fn from being inlined into callers AND stops it from inlining ITS OWN callees.**
So if target *keeps the `bl`* to a helper but that helper itself *inlines* its
own leaves (which target does), wrapping the helper in `dont_inline` will fix the
`bl` but REGRESS the helper (its leaves stop inlining). hotel5 hit this — wrapping
mmFree regressed it 99→73 because mmFree relies on inlining mmGetRegionForPtr.
**The safe fix in that case is SOURCE ORDER, not dont_inline:** place the new
caller *before* the helper's definition so MWCC can't inline the helper upward
(it's not yet defined), while the helper still inlines its own callees normally.
Reach for `dont_inline` only when the wrapped fn has no callees it needs to
inline.
**When source-order is IMPOSSIBLE (the dont_inline'd fn has callers on BOTH
sides of its definition), MANUALLY INLINE the blocked callee's body.** If the
wrapped fn must stay un-inlined (38 callers before+after the def, so no
source-order placement works) but it calls a `static inline` accessor that
target inlines, the dont_inline wrap blocks that accessor too, leaving a
`bl` target doesn't have. Fix: spell the accessor's body inline at the call
site (e.g. `Player_GetObjHitsState(obj)` →
`(ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState`) — removes
the `bl`, keeps the load-bearing wrap, call-set matches. (miner-4,
fn_802AB5A4 78.93→80.63; detect via callset_audit's CUR-only flag for a
same-TU static-inline.)

**Diagnostic:** when a freshly-added function lands mysteriously low (<70%) for
no visible source reason, suspect a same-TU callee got auto-inlined into it.
Wrap that *callee's definition* (not the caller) — this frequently lifts the
caller AND every other caller of that helper to 100% in one move.

**Confirm via symbol size, and expect multiple victims.** `objdump -t` (or the
`.o` symbol size) showing the function *much larger* than target is the
fingerprint of auto-inlining. A single dispatcher can inline *many* siblings at
once — wrap *each* inlined callee's definition; one fix then lands the
dispatcher and all the siblings together (a real case: a GameBit dispatcher
inlined 5 `fn_802A9xxx` siblings, all at 0%; wrapping the 5 callees lifted every
one to 99-100%). Inserting a new function *after* its callees' definitions in
the file also avoids forward-decl churn.

**90-95-band triage order (standing protocol): (1) call-set diff (below),
(2) frame check (#67 tells), (3) per-class recipe work.** On the 90-95
≥1.5KB band the deficits are structural (inline victims, frame/spill bugs,
import simplifications) — the call-set diff is the cheapest possible win
and goes FIRST (newClouds 94.25→98.94 from one dont_inline).
**The band playbook (one-day evidence: 6 large fns, +0.126pp project-wide —
fn_802A0680, Minimap_update, textRenderStr, worldplanet_update,
andross_update, Tricky_update; every one followed this pattern):**
1. **#74 LL masks + #91 ternary clamps come in BURSTS** (macros, repeated
   case bodies — andross had 40 clamp sites, Tricky's reset macro 4 adjacent
   masks). Convert WHOLE bursts before measuring or the A/B lies (see the
   #74 burst addendum).
2. **Ghidra width damage derails difflib into fake giant regions** —
   u32-vs-int char vars (cmplwi immediates vs lis/addi materializations),
   u16-vs-s16 timers (clrlwi/extsh at joins), int-copied float fields
   (lwz/stw vs lfs/stfs). Fix the small REPEATED class first; 1000+-instr
   "block reorder" regions snap back into alignment (andross's 1727-instr
   region was an extsh cascade, NOT a reorder — the jump table already
   matched).
3. **Signature reconstruction is cheap and reliable** — read the prologue
   save order (#87: mr/fmr interleave = param order) and arbitrate across
   callers (#84: majority decl wins); flips are ABI-neutral per-class.
4. **Reload-vs-CSE of constants/conversions is the most common FP residual**
   — #71 literals for per-use const reloads, #97 int-local + per-use (f32)
   cast for per-statement re-conversion, #83a launders for field reloads.
5. **UN-NAMED locals (alias-forced per-statement reloads) are the #1 import
   damage class at unit scale** — the Ghidra import names every repeated
   chain (`model = obj->modelInstance;`, lifted products, cached flag
   bytes) that the original derefed inline per statement; int stores
   through computed pointers force MWCC to reload, so the named/cached
   form diverges at EVERY copy site. Drop the local and inline the chain
   (#107/#83a) — objlib's twelve 100s were dominated by this single move.

**Call-set diff = a systematic detector for inline victims.** Instead of
guessing which leaf inlined, diff the partial's CALL SET against target
(`tools/function_objdump.py --diff`): any callee that appears as a `bl` in
*target* but NOT in your output has been auto-inlined into your function. Wrap
that leaf's definition in `#pragma dont_inline on` — fixes the caller AND lifts
the leaf standalone. Catches hidden ones a size-check misses (a small leaf
inlined into a big caller barely moves the symbol size). On any inline-heavy
TU, run this check first on any partial <90%.
**Inverse direction — extra `bl`s in YOURS (not target) of the SAME callee
repeated = a DUPLICATED code BLOCK, not an inline victim.** If your call set has
*more* `bl`s than target and the extras are repeats of the same callee(s), it's
usually because a `switch`/`if` arm DUPLICATES the common post-block tail
(e.g. a case emits its own copy of the shared `PSVECScale/Add; return` tail)
where target shares ONE tail. Fix by replacing that arm's body with `break`
(or a goto-the-shared-tail structure) so it falls through to the single common
tail — the call set then matches. NOT a dont_inline case. (november11,
fn_8029E568 86.8→91.7%.)

**THE CALL-SET-DIFF FIELD is a PROJECT-WIDE, +15pp/fn vein — run
`tools/callset_audit.py` (per-fn diff of bl reloc-target sets, target.o vs
current.o).** Two recurring import-damage sub-classes, both reliably large:
(1) **auto-inline victim** — a TGT-only call is a same-TU helper the caller
auto-inlined (the dont_inline fix above + its CAUTION: A/B mandatory, some
"victims" are false — target actually inlines, e.g. isSpace into
textMeasureFn regressed when wrapped; use the source-order fallback when the
callee must inline its own leaves); (2) **wrong-symbol phantom** — the import
called a Ghidra `FUN_<addr>` / mis-suffixed extern (e.g. `PSMTXMultVecSR2`,
`objAnimCurvFn_800849e8`) resolving to a DIFFERENT address than the canonical
symbol target calls — often a genuine RUNTIME BEHAVIORAL BUG; verify the
address via `config/GSAE01/symbols.txt` and map each call by target's bl order
+ arg shape. Spurious discarded calls (a trailing `FUN_xxx()` / a doubled
getter target CSEs) are a sub-shape — drop/hoist. NOT-a-clean-fix: when CUR
has a SET of unrelated extra calls with no same-TU helper, the import
mis-structured the logic (reconstruction, treat separately). Confirmed wins
(task #20/#21, miner-3): drakorhoverpad_updateMain +16.7, Sky_func03 +15,
ObjSeq_update, cfguardian_updateMain, + 4 behavioral bugs (staffAction,
titleDoLoadSave, CameraModeViewfinder_free's all-6-calls-wrong, barrelgener).
The MSL math cluster (savefpr/restfpr-only diffs → #99 optimize_for_size) is a
parked delicate -O0 batch. `tools/unrolled_loop_audit.py` is the sibling #28
detector (target has more runtime `slw` than current = a manual-unroll the
import should have left as a for-loop; sky skyFn_80088c94 69.8→99.2). Both
tools carry a STALE-.o caveat — run after a full `ninja`.
**Three INLINE-CONTROL sub-patterns for call-set mismatches — pick by what
target does with the same-TU callee:** (1) **block** — target keeps the `bl`,
ours inlined (TGT-only callee): `#pragma dont_inline on` the callee. (2)
**enable (source-order-up)** — target INLINES it, ours emits the `bl`
(CUR-only same-TU callee) because the callee is `static inline` / defined
AFTER its caller so MWCC can't inline it there: MOVE the callee's definition
UP before its first caller (the mirror of the dont_inline trap). objfsa
curves_lengthFn24 70.7→84.52 (moved Objfsa_FindRomCurveById's 28-line
static-inline def above its first caller → all 3 sites inline). (3)
**manual-inline** — when neither source-order nor a pragma reproduces target's
inline/no-inline choice, hand-inline (or hand-call) the body to match.

## `for (i=0; i<n; i++) { use(*p); p++; }` vs `*p++`

MWCC emits a `bdnz` countdown loop only when the increment and the
dereference are separate statements. `*p++` merges them and the loop loses
the tight `lwz; addi; cmpw; b` body that target uses. Keep `*p` and `p++`
on separate lines inside the loop body.

**Inverse case — `arr[i] = …` (index) NOT `*p++` when target strength-reduces
to induction pointers off saved-reg params.** When target copies a base param
into a volatile reg and bumps it per iter (`mr r3,r28; … ; addi r3,r3,4`),
write the output as `outX[i] = v;` (array indexing with the loop counter).
MWCC then strength-reduces the index to exactly that induction-pointer form;
`*outX++` produces a different pointer-walk. (mike7, curveFn_80010018 output
loop → 99.5%.) Match whichever the target uses — neither form is universally
right.
**The SYMBOL-INIT MATERIALIZATION SHAPE is a tell for which form the source
used** (task #160 minimal-repro proof): a walked pointer init'd from a global
symbol (`p = sym; … *p; p++`) emits `lis; addi r0,rX,lo; mr rS,r0` (via-r0
copy); the INDEX form (`sym[i]` + i++) emits the direct `addi rS,rX,lo` AND
still strength-reduces to the same per-iter `addi rS,rS,K` bump. So target
showing direct-addi + bump = index-form source; via-r0 copy + bump =
pointer-walk source. CAVEAT — fixing the isel can break the COLORING: the
SR-created web ranks differently from a walked-var web (renderParticles: index
form got the direct addi but grabbed r31 instead of target's r26, rotating 5
saved regs, net WORSE; decl-order rank flips inert). Only convert when the fn
is otherwise clean or target's reg assignment survives; A/B mandatory. Also
from #160: a GLOBAL inline/overlay change (e.g. re-basing gExpgfxTableEntries
as runtime+0x980 per recipe #16 — confirmed correct for SOME target fns by
`add rX,r31; lwz 2440(rX)`) can be per-fn MIXED — expgfx family nets NEGATIVE
globally (+1.4 free, −3.9 expgfxRemove); apply per-fn, never per-inline,
when the family's target uses both forms.
**SR init/bump GROUP-ORDER tell (the multi-walker extension of the #160
shape):** when target's loop preheader emits the SR'd INT-OFFSET webs
(`li rX,K` byte-offset counters) BEFORE the pointer-walker inits, with the
SAME grouping repeated at the latch bumps, the original source had NO named
walkers at all — every access was index form (`base[i*stride+k]`,
`&arr[i*stride]`, `(u8 *)p + i*stride + K`) and strength reduction created
ALL the walkers in one creation-order group. Named walker statements
(`p = base; ... p += 3;` at body end) emit their inits/bumps at statement
position with the SR webs APPENDED after — no statement reorder can
interleave them. Converting the named walkers + body-end bumps to full
index form let SR regenerate target's exact group order byte-exact
(fn_80174BFC 98.22->100, dll_138 unit -> 100.0). Same A/B caveat as #160:
the conversion moves web classes; verify coloring survives.

**Loop induction-update ORDER is sometimes an open ~1-3 instr residual.** Target
emits `addi ptr; addi counter; cmpwi counter; b`; clean-C array-index form emits
`addi counter; cmpwi; addi ptr` (counter bumped/tested before the pointer). On
the first pass it didn't respond to index-vs-pointer-walk OR scheduling toggle.
Holds some array-walk loops at ~93-95% — but read the SHARPENED mechanism
below, which makes it a controllable tradeoff rather than a wall.
**MECHANISM SHARPENED (task #14 probe battery, q1-q5 both compilers +
wmseqpoint_update in-place A/B): the cap is a SCHEDULING-OFF artifact.**
Under scheduling-ON, the bump order at the tail FOLLOWS SOURCE ORDER —
comma-increment order (`p++, i++` vs `i++, p++`), body-end `p++` placement,
and the SR'd index form (ptr-first) all reproduce their respective orders;
the cap shape never appears. Under scheduling-OFF, walker bumps (named OR
SR-created) pin to the latch AFTER the compare (`addi i; cmpwi; addi ptr`)
and NO source form flips it (body-end bump, comma-order, explicit walker
all tested; walker forms also add an init `mr` + swap the i/q coloring —
net WORSE than the plain index form). When target shows ptr-bump-first in
a fn that needs scheduling-off for its other divergences, the 1-instr
transposition is the current price of the pragma — bank it (wmseqpoint_update
99.0, musicInitMidiWad) and keep it open. If the fn does NOT otherwise need
sched-off, try sched-on + source-ordered increments first, which removes the
transposition entirely.
⚠️ **CRACKED — the bump-after-compare sink is the PEEPHOLE pass, not SR,
not scheduling, not the compiler version (wmseqpoint_update 99.0 → 100,
unit → 100.0, commit 5e22dc6ee).** Under peephole-OFF + scheduling-OFF
the SR walker bump emits at the TOP of the latch (`addi ptr; addi i;
cmpwi; blt`) = the common target shape; a fn-local `#pragma peephole on`
wrap is what sinks it to after the compare. Verified in both directions
across all 20 GC compiler versions. TRIAGE for this residual: check the
fn's effective PEEPHOLE state FIRST — such wraps are usually added to kill
a narrow-store `clrlwi`/`extsb`, and the wrap's real job can be replaced
by a width-correct callee decl (#11/#57: block-scope `extern u8 fn(...)`
+ cast-free store — with a u8-typed RHS there is no assignment-conversion
node, so peephole-off emits the bare `stb` directly; note #83c's
"front-end drops conversions at a truncating store" does NOT extend to
int-returning CALL results, only the callee retype removes that node).
Then drop the wrap and the latch fixes itself. musicInitMidiWad is worth
re-attacking with this lever. An earlier session-day claim that the
bump-first latch was "scheduler output / sched-ON tell" was WRONG —
falsified the same day; sched-ON × all versions = 20-40 regions (dead
axis). Negative map preserved in the 5e22dc6ee campaign notes: walker
spellings (7 forms) re-canonicalize AND add the #160 via-r0 init
divergence (target's direct `addi rW,rBase,lo` proves index-form source);
opt_* pragma sweep inert on the latch under peephole-ON.

**Passing a small by-value struct (e.g. `GXColor`, 4 bytes) goes BY ADDRESS in
this ABI — load the global STRAIGHT into the outgoing-arg slot.** Write
`GXSetFog(..., *(GXColor*)&lbl_xxx)` so MWCC loads the global directly into the
arg stack slot (one store); an intermediate local (`GXColor c = ...; f(c)`) adds
a redundant copy. (november12, dll_07 GXSetFog.)

## Don't hoist a global/`.bss` address when target RE-DERIVES it per use

The mirror of #6/#16 (lift/base-pointer-hoist): if target emits a fresh
`lis;addi` (or `lis;lfd`) to re-derive a `.bss`/`.data`/`.sdata` address at
*each* use, do NOT pull it into a local — hoisting parks it in a saved reg and
shifts the whole register-coloring + frame size, making the match worse. Only
hoist when target itself keeps the base live in a saved reg across the body.
(mike7, curveFn_80010018 coeff table lbl_80338790 — leaving it re-derived per
use was required for the 99.5%.)

## Graduating a `placeholder_XXXX` catch-all into real DLL files

The `unknown/autos/placeholder_XXXXXXXX` units are dtk auto-splits that bundle
several real per-object DLL TUs into one file (named by load address). Once a
placeholder is meaningfully recovered, it can be *graduated* — dissolved into
the real `dll/<AREA>/dll_XXXX_<name>.c` files — and this is **byte-for-byte
match-preserving** when the preconditions hold. Done twice (80211C24→19 files,
801F5184→17 files), exact conservation both times, 2 functions even *improved*
(splitting removed a wrong cross-family auto-inline the false single-TU caused).

**Match-safety preconditions (verify in Phase 1, no edits):**
- Unit is **`.text`-only** (no `.data`/`.rodata`/`.sdata`/`.bss` in its `.s`) —
  so there are no per-TU pooled constants that splitting would re-pool. If it
  has pooled data, splitting is risky; stop.
- **0 file-local `static`s** (all `.fn … , global`) — no shared helpers pinning
  a TU boundary.
- Symbols place by **name→address** (symbols.txt), independent of which `.c`
  defines them or source order — so identical compiled bytes ⇒ identical
  placement ⇒ conserved.
- Families are **contiguous address-ordered runs** (each = one original TU);
  confirm boundaries by call sites + any descriptor table / doc-skeletons.

**Procedure (per family, conservation-checked):**
1. Map each family → real `dll/<AREA>/dll_XXXX_<name>.c` (canonical `dll_XXXX_`
   prefix dodges basename collisions with unrelated existing DLLs).
2. Shared header per area (`include/main/dll/<AREA>/<area>_shared.h`) carrying
   the **complete** extern set — collect **every** `extern`/forward-decl in the
   WHOLE placeholder `.c`, not just its preamble (auto-gen scatters callee
   externs through the body; missing ones fail to compile). Externs emit no
   code → duplicating them is harmless. **Include standalone col-0 forward
   prototypes too** (e.g. `void fn_802BF4D8(int);`) — once functions are
   reordered into a new file, a call that precedes its def with no prototype
   gets an implicit-`int` decl that then conflicts with the real definition.
3. **Graduate EDGE-FIRST in address order** — dtk requires linear link order;
   a mid-unit hole makes the placeholder appear on both sides of another unit's
   range → cyclic-dependency abort. Keep the placeholder one shrinking
   contiguous range (carve the front edge each step).
4. Emit each family's fns in **source-line order** (preserves intra-family
   call-before-def) and wrap **each fn** in its **effective** pragma state
   computed from a **stack model** (`reset` pops — see recipe #1; tracking only
   the last label silently miscompiles nested-region fns). When CONCATENATING
   segments from one donor, BALANCE each segment's pragma forest to net-zero —
   a non-net-zero segment re-states every fn after it (resplit pipeline:
   dll_19B_SeqFn 100→84.17 until balanced).
5. Update `splits.txt` (replace placeholder range with the per-family ranges) +
   `configure.py` (replace the 1 placeholder Object with N). Delete the
   placeholder `.c`/`.h` and any unbuilt doc-stub.
6. **Conservation check** after each family: combined `matched_code` +
   matched-fn-count across (shrunken placeholder + new file) must EQUAL the
   pre-move total (NOT the headline %, which shifts with the denominator).
   Revert any family that doesn't conserve. Build green, **land on `main`**.

### Don't delete a "zero-text" placeholder before checking its data sections

A placeholder showing `total_code: 0` / `fuzzy_match_percent: 100` is **NOT
automatically a stub** — it may own `.data` / `.bss` / `.rodata` / `.sdata`
ranges that other TUs `lis;addi` into. Deleting the file orphans those ranges
and breaks the link.

Test before deletion: grep the unit's `.s` file (`build/GSAE01/asm/<unit>.s`)
for non-`.text` sections. A placeholder with `.data` / `.bss` lines is a
**data-owning TU** — graduate it to a topical filename (e.g. `audio/mcmd_data.c`
for an audio pitch/midi2time table) and reference it from the consumer TU as
a normal extern. Only delete when the unit truly has *no* sections at all.

Charlie-29 task #138 found 4 of 5 "zero-byte stubs" in the 0x8032xxxx range
were actually data-owning: 8032EDD0 (1096B mcmd pitch/midi2time/aux tables,
referenced from mcmd_exec.c → became `audio/mcmd_data.c`) and 8032F618
(388B adsr volume-curve, referenced from adsr_handle.c → became
`audio/adsr_data.c`). The other two (8032C984 OSContext FPU sliver, 803D8888
TRK 8.7KB) belong to SDK units (OSContext.c, TRK.c) and need an SDK-side
splits change — leave in place until that's done; deleting wedges the link.

### Skeleton-copy carve method (preferred for messy multi-family units)

For units where the original `.c` has **sloppy call sites** (implicit-decl
arity-0 calls, missing prototypes, calls-before-defs that compile because the
def lives in the same TU), the "complete extern set in a shared header"
approach (procedure step 4 + the shared-header lesson below) **FAILS** — adding
full prototypes to the carved files changes f32-promotion codegen at the
implicit-decl call sites, producing per-fn fuzzy regressions even though the
fns being moved are unchanged. The textrender/model carves in 8001746C hit
this on the first build attempt.

The fix that lands byte-exact on the first try: **each family file is the
ENTIRE original `.c`** with other families' definitions collapsed to a
**one-line prototype AT THE SAME POSITION** the def used to occupy. Key
properties:

- **A definition IS a declaration** — collapsing a def to its prototype at the
  same line preserves the decl environment exactly. The carved-away fn's
  signature is still in scope, so any sloppy implicit-decl call site sees the
  same visible signature it saw pre-carve.
- **All `#pragma` lines stay verbatim** — pragma stack state at every retained
  fn is identical by construction. No pragma-stack recomputation, no
  effective-state derivation, no risk of mis-classifying a fn's pragma scope.
- **No decl reconstruction** — typedefs, externs, includes all stay in place.
  No SJIS-encoding surprises from header rewriting.
- **No shared-header authoring** — the `engine_XXXXXXXX_shared.h` /
  `engine_XXXXXXXX_phantoms.h` pattern is OPTIONAL with this method; the
  shrinking placeholder carries the shared decls until it's empty, then the
  last carve absorbs them.

Cost: each family file initially carries the FULL original decl/typedef set
+ FUN_ extern decls (files are 4.5-6.5K lines vs. the few-hundred-line "clean"
form). That's a Phase-3 cleanup target — conservation-gated trims, the same
discipline as newclouds-style dup-def cleanup (recipe #56). Transitive-closure
dead-decl analysis (start from retained-fn bodies, walk all referenced
identifiers, drop unreached typedefs/externs/defines) takes 7 carved files
38K → 18K lines (alpha-35 task #134) with byte-identical .o output.

**Trim-tool failure modes to avoid** (alpha-35 task #134):
- Multi-line `#define NAME(...) \\` macros must be span-tracked; trimming the
  primary line without its continuations orphans the body lines.
- Multi-bracket array externs (`extern char x[6][8];`) need name extraction
  before the type-bracket parser sees them, or they get wrongly dropped.
- Pragma `push`/`pop` regions emptied by the trim must keep their empty
  push/pop pair intact — orphaning one side throws off the pragma stack
  state of every fn after it. Empty push/pop pairs are state-neutral; leave
  them.

When to use:
- **Multi-family unit with messy call sites** (implicit-decl arity-0 calls,
  unprototyped intra-TU references) — skeleton-copy is the safe path.
- **Multi-family unit with clean prototypes throughout** (DLL TUs with
  ObjectDescriptor handlers, no sloppy calls) — the shared-header procedure
  still works fine.
- **Single-TU 1:1 rename** — N/A, the file isn't being split.

Took 8001746C from 96KB / 354 fns / 7 families → 7 clean engine files in one
session, every carve byte-exact first try. (alpha-35, task #134.)

### Lessons from the 6-unit graduation wave (8020C9CC/800944A0/80220608/80295318/800066E0/80080E58)

- **Pre-build + DRY-RUN the split script in /tmp** (parse all bodies, classify every
  line once, compute the pragma-stack-per-fn) before any repo edit. Then **Phase-1
  GATE**: report the family→file map + conservation baseline and get sign-off
  BEFORE editing. Caught every structural surprise read-only.
- **Directory/filename is PURELY organizational** — symbols place by name→address
  regardless of which `.c`/dir defines them. So don't agonize over `dll/<AREA>/`
  vs `dll/` root vs `src/main/`; it's conservation-neutral and renameable.
- **Don't FABRICATE TU boundaries.** Only split where descriptor tables / call-graph
  coupling / doc-stubs EVIDENCE a boundary. Engine-wide library fns with no
  descriptors + ~0 internal coupling → group HONESTLY (coarse subsystem file), don't
  invent per-object files. Coarse-by-evidenced-subsystem beats fine-but-guessed.
- **Multi-area placeholder → ONE common shared header** (declarations-only =
  conservation-neutral; address-based name like `dll_80220608_shared.h` matches
  the prior `dr_802bbc10_shared.h` convention). Per-area headers are only for
  single-area placeholders.
- **MERGE into existing TU slivers** when a family is contiguous-adjacent to a real
  file that already exists (e.g. 8020C9CC's worldplanet/crcloudrace slivers). To
  preserve a caller's `bl` when caller+callee land in one TU, **append the merged
  fns AFTER the sliver defs** (source order ⇒ MWCC can't inline upward).
  ⚠️ SIZE CORRECTION (re-split campaign): fns up to ~0x100 bytes DO get
  auto-inlined — apply helper-last placement for ANY newly co-resident
  callee, not just small leaves (dll_010C: two 0x100B helpers inlined into
  LanternFireFly_update, 100→65.86, caught by the conservation gate;
  helper-after-caller restored 100.0). Helper-last is achievable BY
  CONSTRUCTION: address-ordered assembly + EOF appends keeps moved fns
  below their callers; the mechanized demote-to-EOF retry recovered the
  one regression observed (resplit pipeline, dfptargetblock_hitDetect).
- **MWCC ERRORS (not warns) on implicit int→pointer args in PROTOTYPED
  calls** — drift code compiles only because its externs are UNPROTOTYPED.
  When merging TUs, keep the donor's unprototyped extern forms (or cast at
  call sites); with that understood, #57 block-scope overrides are often
  unnecessary.
- **DROP dead v1.1 `FUN_xxx` phantoms during the carve** (unreferenced, not in
  symbols.txt ⇒ objdiff never scored them). Conservation-neutral, gives clean real
  files. 800066E0 shed 236.
- **Multi-placeholder DLL merge: a DLL fragmented ACROSS N placeholders can
  be MERGED into one TU per descriptor, byte-exact** — the "coordinate later"
  case is solvable now. Procedure: descriptor-back the boundary (gFooObjDescriptor's
  slot map gives address ranges per family); compile a /tmp dry-run of the merged
  TU(s) with exact MWCC flags; verify per-symbol byte-AND-relocation-identical
  vs. the current 4 .o files. Reconciling the merged decl namespace is the hard
  part — see recipe #57 (block-scope extern overrides) for the safe technique
  when the placeholders disagreed on extern types. Took DIMSnowHorn1 + dim2prisonmammoth
  (4 placeholders: 80295318/802BACC0/802BB4B0/802BBC10, 55 fns, 12352B) → 2 clean
  DIM DLL TUs in a single commit, 55/55 byte+reloc-identical. (delta-29 task #133.)
- **80080E58 clouds = −48 was reloc-stealing, not pool migration** —
  see recipe #56 (duplicate-def reloc-stealing). The "tail TU that cross-inlines
  leaves from an already-carved sibling" case the original wave-lesson warned
  about is FIXABLE when the cross-coupled leaf isn't a true `extern inline`:
  drop the duplicate def, force the external resolve, the −48 becomes a +N.
  Engine units stay exact when subsystems either don't cross-inline (800066E0's
  9 files) or when reloc-stealing dups are systematically dropped (newclouds,
  recipe #56). Exact IS the bar — and exact is now achievable in cases the
  earlier wave gave up on.
- **A stale task OWNER (a dead hunter still listed) reads as an "active recovery"
  conflict to a splitter** — close recovery tasks when a unit parks, or splitters
  will (correctly) refuse to edit. Three splitters flagged this; all were phantoms.

## Drift handling (Ghidra-imported `FUN_xxx` don't match v1.0)

**Drift stubs HIDE large recoverable functions — a tiny header size (e.g. "4b")
can mask a big real v1.0 body, so size-based triage UNDERCOUNTS the work.** When
a unit looks "mostly capped/drained" by function-size, run `drift_audit.py` and
check the real `.s` body sizes: a 0%/"0.1%" symbol the report calls tiny may be a
1-4KB drift stub fully recoverable by the reconstruction recipe below. hotel8
found ~111 such stubs on placeholder_8001746C (textRenderStr was labeled "4b" but
is ~4100B → reconstructed to 83%). Before declaring any unit drained, confirm via
the .s sizes, not the header/report sizes.

**A stuck mid-range partial (60-95%) is OFTEN a CORRECTNESS bug, not a codegen
cap — verify the target's actual control flow BEFORE assuming a cap.** The
Ghidra import frequently got the C *logic* subtly wrong: a `return`/store nested
inside an `if` that target executes unconditionally, an over-simplified switch
arm (a bare list-walk where target has an inner sub-switch), a spurious extra
`return 0`. These read like "register-allocation residuals" but are really wrong
behaviour. Before filing a partial as a cap, diff the target asm's branches/
returns against your C control flow and fix the logic — november11 took
fn_80295A04 66.6→100% and fn_802A7160 93.6→100% this way (both were import
control-flow bugs, not caps). Only after the control flow provably matches should
a residual be called a coloring/codegen cap.

Many `.c` files were imported from a v1.1 Ghidra session and have wrong
function boundaries vs the v1.0 `.s`. **Don't try to fix `FUN_xxx`** — instead:

1. Add the asm symbol as a **NEW function** in the `.c` with the correct
   name, signature, and body. The linker matches by symbol name, so the
   `FUN_xxx` floats harmlessly while your new function lands at the right
   match. See `aedc9605` (mmsh_shrine_free), `fa042933` (mmsh_shrine_render),
   `77438a6f` (fn_80189F44, fn_80189BE4).

2. **For deeper rewrites** when the .c is too misaligned: list the asm
   symbol set with `grep '\.fn ' build/GSAE01/asm/<unit>.s`, move plausible
   bodies to the right symbol names with corrected signatures, stub the
   truly-missing ones. See `dbbc5ba9` (laser19F full restructure).

3. **Use `tools/drift_audit.py <unit>`** to get a precise drift diagnosis
   before guessing. `tools/realign_skeleton.py <unit>` emits a v1.0-aligned
   skeleton.

## Vtable double-deref pattern

Target asm `lwz r4, lbl@sda21; lwz r4, 0(r4); lwz r12, 0x34(r4)` (two `lwz`s
through the variable) requires source `*(int *)lbl_xxx + 0x34`. Writing
`*(int *)&lbl_xxx + 0x34` only emits one `lwz` — the `&` flips it from
"deref the pointer-variable's value" to "load the variable's bytes," which
is one level less indirect. The matched-code convention is `extern int *lbl;`
+ `*lbl_xxx` (no `&`).

## Build hygiene (don't break shared `main`)

- **Run `timeout 60 ninja; echo EXIT=$?` and confirm `EXIT=0` BEFORE every
  commit/push.** Never push a new function body you haven't compiled.
- **In A/B batteries, gate every variant on the COMPILE EXIT before reading
  any diff — a failed compile leaves the PREVIOUS .o on disk and
  ndiff/objdump/objdiff happily score the stale object.** A silent compile
  failure mid-battery scores as "this variant diverges" and can enshrine a
  false "spelling X is load-bearing" verdict that later reads as a cap
  (wmspiritplace_SeqFn's typed-mapId "negative" was exactly this — a
  corrupted edit failed to compile, the stale-.o diff was logged as proof,
  and the wrong conclusion survived until a clean re-test). Also gate
  default-target `ninja` expectations: it does NOT compile NonMatching
  units' source .o files — build the unit's .o (or the report target)
  explicitly when iterating.
- **Warnings ≠ a broken build.** MWCC prints `'extraout_f1'/'in_rN' is not
  initialized before being used` for raw Ghidra register-phantoms — these are
  *warnings*; the object still compiles and `ninja` exits 0. A real break shows
  `error:` / `FAILED:` lines and a non-zero exit. Don't raise alarms on warnings.
- **The strict-hash / checksum (CI match) target ALWAYS "fails" until the
  project is 100% matched** — that is the decomp, not a build break. "Build
  green" = `ninja` compiles+links (exit 0); it does NOT mean the hash matches.
- **Clean Ghidra phantoms out of committed bodies** (`extraout_*`, `in_rN`,
  stray `local_N`) — replace with real locals for plausible C.
- **Two agents must never edit the same `.c`** — concurrent recovery of the same
  unit produces duplicate definitions and rebase conflicts. One owner per unit.
- **Edit SJIS-bearing files BYTE-WISE (python rb/wb or byte-safe tools), never
  through a text codec round-trip.** A UTF-8 read/write of a file carrying
  Shift-JIS comments mangles the bytes; sjiswrap's reaction ranges from a
  non-fatal warning (Tumbleweed.c compiled anyway) to a HARD compile error
  (src/track/intersect.c failed the build). Known SJIS carriers hit so far:
  src/track/intersect.c, src/main/dll/baddie/Tumbleweed.c -- check for the
  sjiswrap warning after the first edit to any unfamiliar file, and if it
  appears, revert and redo the edit byte-wise.
- **Blind first-occurrence replaces corrupt pragma-dense files; anchor edits
  to the function definition.** A `data.replace(b'#pragma scheduling off\n',
  ..., 1)`-style edit in a file with many pragma lines (arwingandrossstuff.c
  carries 40+) lands on the WRONG region and silently re-states sibling
  functions -- the file still compiles green. Always anchor pragma
  inserts/flips to the unique fn-definition text (or its immediately
  adjacent pragma line read FIRST), and re-grep the file's pragma sequence
  after the edit. (Pragma-field batch 5: one self-inflicted mangle caught
  pre-commit this way and redone anchored.)
- **NEVER `git stash` / `git stash pop` in a hunter worktree.** The stash store
  lives in the COMMON git dir and is SHARED across all worktrees, so a `git stash
  pop` can pop a DIFFERENT agent's (or an old) WIP stash and splatter it as
  conflicts across dozens of files. For the recurring `.claude/scheduled_tasks.lock`
  modification, use ONLY `git checkout -- .claude/scheduled_tasks.lock` before
  rebasing — never stash. If a stray pop hits, `git reset --hard HEAD` recovers
  cleanly (a failed pop does NOT drop the stash). (mike7 hit this — popped
  hunter-bravo's WIP by accident.) For relocating uncommitted WIP between
  worktrees, COMMIT it on a branch instead of stashing.
- **A `shutdown_request` ack is NOT a process death.** Swapped-out hunters have
  repeatedly replied "shutting down" / gone idle while their process kept running
  (idle-but-alive zombies that keep drawing tokens → rate limits). After every
  swap, VERIFY the predecessor is actually gone (`ps aux | grep "agent-id hunter-X"`
  / its tmux pane) and hard-kill the PID + `tmux kill-pane` if it lingers. Removing
  the config entry and pruning the worktree does NOT kill the process. Only spawn
  the successor once the predecessor's process is confirmed dead.

## Tooling

- `python3 tools/ndiff.py <unit> <symbol> [--classify] [--fingerprint REGEX]
  [--context N]` — normalized per-function instruction diff (branch-target
  addresses masked, divergences grouped into regions; exit 0 = streams match).
  THE first diagnostic to run on any partial. `--classify` pattern-matches each
  region against the recipe taxonomy (ext-insert/reg-perm/via-r0/
  branch-over-branch/cmp-width/fcmpo-swap/frame/pool-reloc/mr-copy/
  deref-via-copy/sched-order/...) and prints the recipe numbers to try first.
  `--fingerprint 'fmuls|fadds'` prints just the operand columns of matching
  instructions — the probe-battery comparison format. Same reloc-tolerance
  caveat as --diff: certify 100% only via report.json.
- `python3 tools/probe_battery.py extract <unit> <symbol> --out DIR` then
  `run --dir DIR [--fp REGEX]` — the /tmp probe-batch workflow (recipes
  #74/#80/#83/#107, mtx44_mult) as a tool: extracts the fn slice + the unit's
  EXACT mwcc invocation from build.ninja + normalized target asm into DIR;
  `run` compiles every `*.c` variant in DIR and prints regions-vs-target (or
  fingerprints) one line per variant. Hand-fix base.c first (decls + the
  unit's pragma state — #113 probe-trap) until it reproduces the in-tree
  divergence; if base.c MATCHES target while the in-tree fn diverges, the
  divergence is fn-global/context-bound (#108 dose) — stop probing, A/B
  in-tree.
- `python3 tools/function_objdump.py --diff <unit> <symbol>` — per-function diff.
  **⚠️ DO NOT use --diff to declare a match %.** It MASKS two real diff classes:
  (1) scheduling REORDERINGS of same-opcode instructions, and (2) SIZE diffs from
  peephole fusion (`extsb.+cmpwi→extsb.`, `and.+cmpwi→and.`) — so it prints
  "CLEAN" on functions that are really only 88-97% in objdiff. The SOURCE OF
  TRUTH for any reported % is **objdiff's `report.json` `fuzzy_match_percent`**
  (`rm -f build/GSAE01/report.json && timeout 30 ninja build/GSAE01/report.json`).
  Use --diff to LOCATE a divergence, never to certify 100%. (november12 reported
  several "100%"s off --diff that were actually 88-97%.)
- `python3 tools/drift_audit.py [--only-drifted] [--csv] [unit]` — find drifted units
- `python3 tools/stub_queue.py [--aligned-only] [--max-size N]` — ranked targets.
  **CAVEAT: output is STALE** — it flags already-matched functions (and dead
  `FUN_xxx` at drift addresses) as stubs, so its counts overstate real work.
  Prefer `drift_audit.py <unit>` + `grep '\.fn ' build/GSAE01/asm/<unit>.s` to
  find the genuinely missing-from-src symbols.
- `python3 tools/realign_skeleton.py <unit> [--merge]` — v1.0-aligned skeleton
- `python3 tools/cosmetic_audit.py [--min-pct N] [--max-pct N] [--unit-filter S] [--max-size N]` —
  screen <100% partials for REAL byte differences (not pool-name artifacts).
  Reads `report.json`, extracts the raw `.text` bytes per fn from both target
  and current `.o` files, computes a reloc-aware byte mask, and reports only
  fns whose remaining diff is non-empty after masking — with target/current
  disassembly side-by-side for each differing instruction. **The empirical
  finding** (recipe #60): out of 14 fns at 99.9-99.99%, ZERO were purely
  cosmetic. Use as a screening pass before grinding any 99%+ partial.
  **CAVEAT — output truncates to the first ~3 differing instructions per fn**:
  when sweeping for a specific signature (e.g. recipe #81's lfs-pair/fcmpo
  swap), grep ALL printed lines, not just per-fn heads — fns whose signature
  sits behind earlier unrelated diffs are otherwise missed (task #162 found
  4 hidden #81 sites this way, all -> 100%).
- `python3 tools/categorize_near_misses.py [--min-pct N] [--max-size N] [--limit N]` —
  heuristic taxonomy for every `<100%` function in `report.json`. It resolves
  report units through `source_path`, objdumps target/current symbols, normalizes
  object-local branch addresses, and buckets the first real instruction
  divergence (register/value spelling, branch/block layout, stack/temp layout,
  signed compare, loop bound, FP constant ownership, etc.). Use it to choose
  file-wide sweeps; it is a prioritizer, not proof of the exact fix.
  **The "compare width/sign" bucket is a RELIABLE ~1-build/fn vein (miner-6:
  9 fns to 100% in one session).** Signature: a single cmpwi-vs-cmplwi (or
  cmpw/cmplw) diff. A pointer/u32 value compared as int -> add a `(u32)` cast;
  an int compared unsigned -> `(int)` (recipes #3/#14/#58). The cleanest, highest
  hit-rate sub-class is a CALL/VTABLE RESULT cast to int then null-checked --
  `x = (int)getById(...); if (x != 0)` -> `(u32)x != 0` (target cmplwi). Also
  here: `< 1` vs `<= 0` (#69), and == operand-order via a #66 block-local.
  SKIP-ON-INSPECT traps that look like this bucket but resist the simple cast
  (don't grind them): (a) a `*(char*)`/byte-field compare that already reads
  signed yet emits cmplwi -- a CSE subtlety, not a type bug (scarab fn_8015E8BC);
  (b) `== key` where the loaded operand is CONDITIONAL -- a #66 block-local
  HOISTS the load out of the guard and regresses (mapTextureOverrideSetValue);
  (c) `*(void**)(p+off) != NULL` that emits cmpwi anyway because MWCC CSEs it
  with an int-typed `p->field` access at the same offset -- the (u32) form is
  multi-site identical so a replace_all is dangerous, needs surgical line edits
  (player.c inner+0x7f8). The "off-by-one/immediate" bucket is MOSTLY mislabeled
  register-coloring + inlining-unroll artifacts (textrender GameText_*, whose
  standalone getControlCharLen is 100%) -- the "compare width" bucket is the
  real one.
- `python3 tools/pragma_minimize.py [--apply] [--filter S]` — rewrite a
  file's sched/peep pragma forest as the MINIMAL straight-line transition set
  producing the same per-fn states (byte-gated, auto-revert). Run after any
  per-fn pragma work to keep files in canonical form; the minimal form makes
  the ON-region/OFF-tail structure (see "Pragma states" section) visible.
  Skips push/pop files; reverts cleanly when the fn-state model mismatches
  (mid-fn pragmas). Phase-1/3 sweep results: 90 uniform files migrated to
  unit cflags (cflags_dll_noopt/nosched/nopeep), 119 mixed files minimized,
  ~2400 lines removed, all byte-identical.
- `python3 tools/rotmap.py <unit> <symbol>` — register-rotation mapper:
  skeleton-aligns T/C streams, prints the T→C register permutation with
  per-web counts + the STRUCTURAL diffs hidden under the rotation. Run on
  every #108-class partial before banking (see the rotation-campaign
  section).
- `python3 tools/pragma_depushpop.py [--apply] [--filter S]` — eliminate
  `#pragma push/pop` scaffolding: full-environment model (push/pop saves +
  per-kind value/reset stacks across 9 pragma kinds incl. optimization_level
  and ppc_unroll_speculative), per-fn effective state, straight-line minimal
  rewrite, byte-gated. Phase-4 result: 13/14 files converted (~2650 lines;
  the engine files' ~100 push/off/off/pop wrappers each collapsed to <40
  lines; backpack/NWsfx push/pop blocks were pure no-ops -> 0). Only
  track_dolphin keeps push/pop (genuinely fine-grained controls).
- `python3 tools/pragma_audit.py [--max-pct N] [--unit-filter S] [--all]` —
  flag <100% fns whose effective pragma state (stack model, recipe #1) is an
  OUTLIER vs their unit's majority state. ⚠️ CAVEAT: the tool does NOT read
  unit cflags — in a `cflags_dll_noopt` unit (-opt nopeephole,noschedule)
  its "sched=def-on/peep=def-on" flags are NOISE (CF sweep: scarab/fxemit
  flagged, wraps byte-inert). Check the unit's configure.py cflags first. THE highest-yield triage signal on
  the 60-90 band: run it BEFORE any shape work on a partial (per-fn #1 wraps
  alone ran +12 to +27pp; intersect.c's 7-fn cluster banked ~+103pp in one
  commit). A/B MANDATORY both ways — ~50% of peep=ON-only flags are correct-
  ON (jump tables, #68 peephole-ON-target units; allocLotsOfTextures
  REGRESSED with the wrap) and inert wraps must be removed (#173). The
  sched=ON flag class hits near-100%. Sub-class: peephole-off-only regions
  MISSING scheduling off (vfplift pair +21pp). Sub-class 2: EXPLICIT
  import-era WRONG wraps — fns deliberately wrapped `#pragma scheduling on`
  whose targets are off/off (fn_8022ECE0 64→94, fn_8022F27C, androssligh_
  update); `grep -rn "#pragma scheduling on" src/` is a standalone
  residual-damage census for this shape (flip to off/off in place, A/B).
  SJIS carriers (intersect.c, Tumbleweed.c) take byte-wise edits. The wrap
  UNMASKS recipe-class residuals rather than finishing the fn — expect
  #74/#112/#20-style work after.
- `python3 tools/width_audit.py [--all] [--arrays]` — enumerate extern decls
  whose C type width contradicts symbols.txt's `data:N` annotation, ranked by
  consuming-fn fuzzy% (full triage taxonomy in the script header).
  **Width-audit lesson (task #176): "symbols.txt width is the physical truth"
  INVERTS in practice** — when a 100%-matched fn disagrees with the
  annotation, the CODE is the truth and the annotation is drift (73 of 78
  scalar mismatches were this). The live win class is wrong-SYMBOL references
  (a double's address where a float was meant, semantically masked when the
  values coincide — TrickyCurve_updateBurstTrigger +992 to 100%); the width
  lens catches them as a side effect. Retyping symbols.txt annotations is the
  wrong axis (#70's decisive negative); fix wrong-symbol refs in <100% fns
  instead. Deliberate "mismatch" classes that are NOT bugs (correct code — not
  candidates): u8 scalars used only via `&sym`
  (sda21 address-of form), u32 RGBA overlays accessed via `(u8*)` casts,
  u8/char blob arrays on 4byte/float data (access width comes from the
  cast-derefs, not the element type).
- **Removing Ghidra-style `*(T*)((u8*)var + 0xNN)` derefs**: replace with typed
  `var->field` access BY HAND. Read the real struct definition (its explicit
  pads name the exact offsets), map offset->field, and write clean member
  access. Keep the deref width/signedness matching the field: a u16-deref of an
  s16 field flips lhz/lha, an int-deref of a pointer field flips cmpwi/cmplwi —
  launder with `*(T*)&var->field` only when the field type genuinely differs.
- **Byte-exact cleanup verification (task #164 pattern)**: baseline = objdump
  `-d -j .text` of every `.o` under `build/GSAE01/src` (NOT `build/GSAE01/obj`
  — that is the dtk-extracted TARGET tree and never changes); edit; rebuild;
  diff every disasm vs baseline; commit only on zero diffs. **TRAP: after every
  `git pull`/`git pull --rebase`, OTHER hunters' match commits make THEIR .o
  files flag as changed — confirm any flagged .o is yours, then re-save the
  baseline after every pull+build before the next edit.**
- `rm -f build/GSAE01/report.json && timeout 30 ninja build/GSAE01/report.json` — refresh report
- `python3 tools/include_audit.py --audit [--filter SUBSTR] [--out F.json]`
  then `--apply F.json [--filter SUBSTR]` — empirical unused-#include
  detector/remover (task #168): blanks one top-level include at a time,
  rebuilds just that TU, classifies by .o byte hash (build-fail / bytes-change
  = NEEDED, bytes-identical = removable). MWCC .o output is deterministic and
  carries NO line info, so deleting include lines is .o-byte-neutral when the
  token stream is unchanged. `--apply` re-verifies per file (combined removal,
  greedy fallback for interacting includes — includes individually removable
  are NOT always jointly removable) and auto-reverts on any byte change. A
  TU's own header is kept by convention even when unused (`--include-own-header`
  to override). Full-sweep findings: ~680 includes removed across ~590 TUs
  (`ghidra_import.h` import-era cruft was ~480 sites); `NEEDED-codegen`
  verdicts (bytes change, no compile error) are real macro/typedef-width
  effects — never remove those by eye. Audit artifacts GO STALE: each
  applied removal changes the joint include state, so a deferred queue
  from an old `--audit` run accumulates now-divergent entries (task #170
  found all 24 deferred dolphin/audio candidates flipped to NEEDED after
  sierra-1's sweep) — always re-audit before applying a saved report;
  `--apply`'s per-file byte gate makes stale entries safe but wasted work.
- `python3 tools/extern_audit.py [--csv | --symbol X | --real-conflicts-only]` —
  extern decl audit across src/+include/: canonicalizes signatures into
  CODEGEN-equivalence classes (return width/signedness, param widths, f32/f64,
  varargs — recipes #3/#11/#24/#58 aware) and reports REAL conflicts (recipe
  #57 block-scope-override territory; per-file form is LOAD-BEARING, never
  naively unify) vs cosmetic-only variants vs consistent dups vs static
  candidates (cross-checked against symbols.txt scope). Key negative (task
  #165): same-file `extern` forward decls of globally-placed symbols must NOT
  become `static` — symbols place by name via symbols.txt; the extern-should-
  be-static class is essentially EMPTY on this project (7 scope:local decls,
  all with data still in asm units).
- `python3 tools/forward_decl_static_audit.py --audit [--out F.json]` then
  `--apply F.json [--classes fwd,static,static-inline]` — redundant-decl +
  dead-static detector/remover (task #171). Three fwd-decl classes: a .c
  prototype/extern covered by a codegen-EQUIVALENT header decl in the file's
  #include closure (extern_audit canonicalization — recipe #57 disagreements
  are auto-excluded), exact-text dup-in-file, and decl-after-def. Apply mode
  rebuilds just the TU and auto-reverts on ANY .o byte change (same-line-code
  guard skips decls sharing a line with live code). Sweep result: 255 decls
  across 64 TUs removed, zero .o byte changes. Dead statics are REPORT-ONLY
  in practice: every unreferenced plain static found was EMITTED matched code
  (musyx AddDpop, OS.c asm exception vectors — removal would LOSE bytes), and
  unreferenced `static inline` helpers are usually staged accessors for
  in-progress recovery — leave them. Rule of thumb: an unreferenced static
  may be EMITTED matched code (exception vectors, musyx helpers) — check
  symbols.txt presence before treating it as dead.
- **Gold-standard verification for refactor/cleanup commits: full-build .o
  hash comparison**, strictly stronger than report.json (catches reloc-encoding
  changes report.json doesn't surface). `find build -name '*.o' -exec md5sum
  {} + | sort > before.md5`, make the change, `ninja`, re-hash, `diff` — any
  changed .o = revert that file. Task #165 swept ~917 dup extern lines across
  ~150 files this way with zero regressions (2 parser-bug bad edits caught and
  reverted by exactly this check).

### In-repo oracle: grep the matched corpus's TARGET .o for a shape

Sibling of the MP4 oracle, using OUR OWN tree: when a residual is a specific
instruction shape, walk `build/GSAE01/obj/**/*.o` disasms for the exact
pattern and read the C of any unit already at 100% that produces it (the
re-split duplicates make multiple hits per shape likely). One script find:
the store-reload-into-f2 fcmpo shape (cfprisonguard_render's once-banked
digit) EXISTS in matched dll_0141_lightning (lightning_update, compound `-=`
+ `<=`), proving the compiler emits it from plain C. (The prisonguard site
itself turned out to be a #65 dropped f32 call arg — the reload CSEs into
the f2 arg register — so its "dead-slot reuse divergence" framing was a
misread; see the #82 overturn note.)
Use the oracle to settle whether a shape is C-reachable at all before
banking; the corpus-walk script pattern is in the CF-campaign commits.

### Matching-help corpus (Discord export + decomp.me scratches)

A year of decomp.me's matching-help Discord channel (`reference_projects/Discord_chat_*.csv`,
5000 messages, 989 unique scratch links) plus the already-fetched scratch
payloads (`reference_projects/decompme_scratches.jsonl`, gitignored) form a
searchable corpus of real-world matching attempts: someone posts a scratch
with their stuck C, others respond with the recipe that fixes it. Useful when
a residual's symptoms match something others have already solved (FP register
coloring, fmadds fusion, peephole behavior, rlwinm vs andi, fp_contract
surprises, etc.). There is NO working scripted network path to decomp.me —
treat the JSONL as a static snapshot, and use the prep tool below for
outbound scratches (manual paste).

- `python3 tools/decompme_prep.py <symbol> [--unit <substr>] [--out DIR]` —
  prep PASTE-READY decomp.me scratch inputs for one function, no network:
  target.s (dtk asm slice, comments stripped, @sda21/.L_ labels kept),
  context.c (the unit's decompctx output, ninja-built if missing), source.c
  (best-effort fn slice), fields.txt (platform gc_wii + the decomp.me
  compiler id mapped from the unit's mwcc version + verbatim build.ninja
  flags). NOTE the version map: GC/2.0 = `mwcc_242_81` — objdiff.json's
  scratch presets say mwcc_247_92, which is GC/2.5; trust the tool. CAVEAT:
  the .ctx embeds the WHOLE TU including the target fn — strip the fn's own
  definition from the context before pasting or the scratch double-defines.
- `python3 tools/discord_search.py <keyword>...` — unified AND-search across
  both Discord messages AND the fetched scratch corpus. Examples:
  - `discord_search.py "rlwinm" "switch"` — Discord threads + scratches mentioning both
  - `discord_search.py --asm "rsqrte" "fmadds"` — grep inside target+current asm only
  - `discord_search.py --code "fp_contract"` — grep inside C source+context only
  - `discord_search.py --scratches "f27 register"` — Discord threads that posted a scratch
  - `discord_search.py -C 5 "permuter"` — wider Discord context window
  - `--skip-discord` / `--skip-scratches` to restrict to one side
- A scratch's `score` (vs. `max_score`) is how close its C is to matching —
  **lower score = closer to a match** (objdiff convention; score is the diff
  penalty, 0 = perfect). A 200/22100 scratch is mostly there; a 22000/22100
  scratch is still broken. Filter accordingly when grepping for recipes that
  actually worked.

### Retail-ISO forensics (object names, DLL ids, placements, cut content)

The retail ISO at `orig/GSAE01/*.iso` answers naming/identity questions no
amount of asm reading can (WM-folder relabel campaign: proved deaddino.c/
WMcrystal.c were mislabeled SC totem units, wallcrawler is cut content,
WM = Krazoa Palace). Verified facts + offsets (v1.0 USA):
- GC FST: header at 0x424 (`>II` fst_off, fst_sz); entries 12B each, names
  follow. Per-map `<map>.romlist.zlb` = the placement list.
- ZLB payloads are zlib WITH header after the 16-byte ZLB header —
  `zlib.decompress(data[16:])`, NOT wbits=-15.
- Romlist record: `>h` romlist TYPE id at +0, length-in-WORDS u8 at +2;
  the record from +0 is what init receives as `spawn` (ObjPlacement head:
  pos at +8/+C/+10, unique id at +0x14). `anim.seqId` (obj+0x46) holds
  the romlist type id at runtime.
- OBJECTS.bin @ISO 0xb390e90 (301696B) + OBJECTS.tab @0xb424490 (1480
  `>I` offsets): per-def the FIRST ASCII string is the retail object
  name; the handling DLL id is `>H` at def+0x50. OBJINDEX.bin @0xb42ecd0
  (2192 `>h`): romlist type → def index.
- The dol's `gResourceDescriptors` (0x802C6300, size 0xB08) is the DLL
  id → ObjectDescriptor* table — INDEX = the dll_XXXX number used in
  filenames (verified 0xFC, 0x20B-0x212). Descriptor fn pointers locate
  which text range (= which unit) a DLL id really owns — the tool that
  exposed every WM-folder mislabel.
Use for: naming units/objects from retail truth, cut-content checks
(zero romlist placements), MapData field verification, and unit-boundary
audits (descriptor fns straddling a file boundary = wrong split).
THE TU MODEL (boundary-audit campaign, validated on descriptor-carved
units): a DLL's descriptor fns sit in REVERSE slot order ascending
(getExtraSize lowest → initialise highest); the DLL's TU spans
(previous DLL's initialise end)..(own initialise end); helpers precede
their own descriptor fns. Tools: `tools/dll_boundary_audit.py`
(--census / --map LO HI --syms / --md) + `tools/dll_boundary_resplit.py`
(the SURGEON: snaps boundaries to TU edges and executes skeleton-projection
ABSORB/MOVE/CARVE with per-case ninja+dol+EXACT-conservation gates,
auto-commit/auto-revert) + the cut table in docs/boundary_audit.md.
Campaign status: 132 cuts found → 66 remain after 5 manual + 38 pipeline
surgeries (sandwormBoss, ARWarwingattachment, modgfx field, CAM, DR lane
all canonical). The 19 flagged cases in the doc are real import drift —
boundary sides disagreeing on shared symbols (conflicting typedefs,
def-vs-header signature splits, one double-decomp) — fix path: #84
signature arbitration, then re-run the tool (it picks cases up from the
live audit); plus the 2 deferred engine extractions (gamecube.c dll-0x009
stubs, light.c/main.c VFP code).
NonMatching boundary moves are dol-safe BY CONSTRUCTION (dtk re-splits
on splits.txt edits; the link stayed byte-identical across all five
carves) — the conservation gate, not the dol, is what catches mistakes.

### MP4 as a "what C makes this asm?" oracle

Mario Party 4 (`reference_projects/marioparty4`) is 100% byte-matched
against the original game, so every function in MP4's compiled `.o` files
is a definitive C↔asm pair for whatever MWCC quirk produced that
instruction shape. When SFA is stuck trying to coax MWCC into a specific
sequence (rlwimi at a given bit position, `cntlzw` idiom, paired-single
`psq_st`, a specific fmuls operand order, `__cvt_` helper invocation,
etc.), grep MP4 for the pattern and read the C that produced it —
regardless of whether the MP4 function is semantically related to your
SFA target. You only need the *pattern* to match, not the family.

- `python3 tools/mp4_asm_search.py "<pattern>"` — grep across all MP4
  binaries' disasm cache for the asm pattern; returns hits as
  (MP4 unit, fn name, asm context). Cache builds on first run (~2-3min,
  ~13MB at /tmp/mp4_asm_cache.txt); subsequent queries are <1s.
- `--with-c` to also locate and dump the matching C definition.
- `--unit-filter <substr>` to restrict to a subset of MP4 units.
- `-C N` for wider asm context (default 4 lines before/after).
- Examples:
  - `mp4_asm_search.py "rlwimi"` — any rlwimi anywhere
  - `mp4_asm_search.py "rlwimi.*,5,26,26"` — specific bit position
  - `mp4_asm_search.py "cntlzw" --with-c` — find one + see the C
  - `mp4_asm_search.py "psq_st" --max 3` — limit results
- Best practice: when a residual category (per `cosmetic_audit.py` /
  `function_objdump.py`) names a specific instruction or operand shape,
  query MP4 for it FIRST — it's faster than hand-crafting a C variant
  and bisecting.

## Reference commits

| Technique | Commit |
|---|---|
| ~~asm{} + register-order (rlwimi/li+and)~~ — **REVOKED** under no-asm directive; repo owner reverting (do not cite) | ~~`2e20e326`, `01400901`, `a42bb90b`~~ |
| Add-new-function for drifted .c | `aedc9605`, `fa042933`, `77438a6f` |
| `if (v > K) v = K;` clamp form for `blelr` | `77438a6f` |
| `u8` vs `char` to drop `extsb` | `6863ffe7` |
| `& ~constant` for `rlwinm` | `782a09a8` |
| `*(void **)` for `cmplwi` | `a42bb90b` |
| `#pragma peephole off` mass fix | `b7eda753` |
| Lift temp for forced CSE | `75660758` |
| Local declaration swap for stack offset | `91f5f4ab` |
| Source-set restructure | `dbbc5ba9` |
| Bitfield member for clean-C `rlwimi` flag set | `a3a86c446`, `34ee540c0` |
| Reorder `case` labels to match block layout | `61dd19936` |
| `int` param → `cmpwi` on `(arg & bit)` | `1ebdcf015` |
| `*(s8 *)(p+off)` to land byte in arg register | `b42e26e71` |
| Local decl-order for register coloring (clean C) | `fa209c270` |
