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
**commit the partial, document the divergence, and move on.** There is always
a C recipe for the divergence; we just don't know it yet. New C techniques
land in this playbook as they're discovered. Don't reach for asm to fill the
gap — the gap is the point.

Heuristic:
- Residual is a single instruction / register-allocation choice? → leave at
  partial, commit, move on.
- Function ≥80% fuzzy on clean C? → leave at partial, commit, move on.
- Looks like "MWCC can't pick this from any C"? → **commit the partial** and
  flag the function so it can be revisited with the next playbook recipe.
  Never asm.

## High-impact one-liners (try first when a function is already 80-95%)

1. **`#pragma peephole off` + `#pragma scheduling off`** around the function
   (matched-with `#pragma peephole reset` + `#pragma scheduling reset` after).
   This alone routinely takes 80-95% fuzzy functions to 100% by disabling the
   peephole pass that fuses `extsb + cmpwi → extsb.`, `rlwinm + cmpwi →
   rlwinm.`, and similar dot-form merges. Single most useful change on this
   project. See `b7eda753` (dll_198 — 3 functions to 100%).
   **Caveat — peephole-off suppresses jump tables.** `peephole off` also turns a
   `switch` MWCC would lower to a jump table into a compare-chain. If a function
   is *all-switch with no bit-ops*, keep it OUTSIDE the peephole-off region so
   the jump table survives; if it mixes a switch with bit-ops you can't have
   both, so pick whichever the target uses and leave the other as the residual.
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
   **Inverse cap — when target MATERIALIZES the mask (`li rX,-K; and` /
   `lis;ori`) MWCC won't reproduce it from clean C.** For some constants (e.g.
   `&= ~K`, `|= 0x800000`) target emits a materialized-constant `li`/`lis;or`
   form while every clean-C spelling gives `rlwinm`/`oris`. This is NOT
   peephole-controllable (confirmed: peephole-off region still emits `rlwinm`).
   Caps tiny flag fns ~70%. **Leave as documented partial — the Prime
   Directive forbids asm; there is no asm fallback.**

3. **`*(void **)ptr != NULL` instead of `*(int *)ptr != 0`**. The pointer form
   emits `cmplwi` (unsigned); the int form emits `cmpwi` (signed). Target
   almost always uses `cmplwi` for pointer-typed compares. See `a42bb90b`.

4. **`if (v > K) v = K; return v;` instead of `if (v <= K) return v; return K;`**.
   The former produces target's `blelr` clamp pattern; the inverse form emits
   `bgt + mr + blr`, adding an instruction. See `77438a6f`.

5. **Swap local declaration order to control stack offsets.** When you take
   addresses of multiple `int` locals and pass them to a single function
   (e.g. `ObjList_GetObjects(&objectIndex, &objectCount)`), MWCC assigns stack
   offsets in declaration order. If target has `&first` at sp+8 and `&second`
   at sp+0xc but yours is the opposite, swap the declarations. See `91f5f4ab`.
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
    *worse*). If the explicit cast doesn't flip it on a late-pool function, it's
    a genuine residual (~85-96%) — leave it, don't keep retrying.
    **The `@NNN`-vs-named-`lbl` LABEL is largely a MEASUREMENT ARTIFACT — NOT
    fixable via symbols.txt.** ⚠️ **PARTIALLY SUPERSEDED — see recipe #60**:
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
    So the `@NNN` print is cosmetic when the bytes match — do NOT retype symbols
    or chase the label. The GENUINE caps are the float-pool-ORDERING cases above
    (the entry lands at a *different address* than the shared pool symbol, so the
    bytes can't content-match) — those are real and not symbols.txt-fixable.
    (zulu14, task #9, decisive negative — don't re-run this experiment.)

11. **`extern int fn(...)` for callees whose return is treated as `int`** —
    even if conceptually the return is a byte. Declaring `extern u8 fn(...)`
    triggers a spurious `clrlwi r3, r3, 24` after every call to zero-extend
    the result, which target omits. Check the asm — if there's no `clrlwi`
    after the call, the project treats the return as `int`. Picked up
    `MMP_levelcontrol_init` in DIMlavaball via `extern int getSaveGameLoadStatus`.

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
    before declaring a saved-reg-coloring cap. See `fa209c270`
    (fn_8019C3A0 → 100%).
    **But SAVED-reg coloring is sometimes allocator-internal and NOT
    source-flippable — after trying decl-order BOTH ways, treat it as a hard cap
    and STOP.** On some units there's a *systematic* saved-reg permutation: target
    assigns the LOWER reg# (r27/r29) to the longer-lived / earlier variable (the
    obj/setup base), MWCC does the reverse, and it cascades through every
    instruction referencing that var. Declaration-order reorder (both directions)
    does NOT flip it. This caps fresh functions at ~74-90% on units where
    MWCC's coloring inverts target's saved-reg priority. The partial still
    banks real fuzzy%; commit and move on rather than grinding.
    **BUT before declaring a coloring cap, try making the base a REAL PARAM
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
    **Single-base struct-overlay for a CLUSTER of globals.** When target addresses
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

20. **Compound-assign a narrow lvalue (`*(s16*)p += K`) instead of the expanded
    read-modify-write (`*(s16*)p = *(s16*)p + K`).** The expanded form reloads
    the value and re-sign-extends it, emitting a redundant `extsh` (or `extsb`
    for `s8`); the compound form folds load+add+store and drops the extra
    extension. Took fn_802B7B0C 96.5% → 100%. Clean C, no asm. (Same family as
    the caller-side extsb/extsh table below.)

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
    NOT leave these partial. The cap is ONLY when target *materializes* the
    boolean into a GPR (`int x = a >= b;` / `return a >= b;`), which clean C
    emits via `mfcr`/`rlwinm` and rarely matches. So keep float compares inside
    `if`/`while`/`?:` conditions; only accept the residual when the boolean is
    actually stored or returned. (Corrects the over-broad "FP-compare → mfcr/cror
    cap" that earlier handoffs propagated.)
    **Counter-caveat — the reverse divergence IS sometimes a real cap.** On some
    targets a clamp uses a SIMPLE `bge`/`ble` (single branch) where clean-C
    `v>=lo`/`v<=hi` *over-produces* the `cror eq,gt,eq; bne` combine, and nothing
    in C flips it back to the simple branch (peephole-on tested, no effect). So
    #25 cuts both ways: when target has the cror combine, write the operator (not
    a cap); when target has a plain `bge`/`ble` and your `>=`/`<=` emits the cror,
    that 1-2 instr divergence is a genuine residual — leave it, and DON'T rewrite
    the clamp chasing it (a logically-correct rewrite of this pattern has been
    confirmed to score *lower*).
    **A MATERIALIZED float-bool (stored to a GPR) is NOT always a cap — two
    confirmed recipes, pick by the FORM target uses:** (a) **mfcr/srwi form** —
    target does `fcmpo … ; mfcr; rlwinm/srwi` to land 0/1 in a reg: reproduce with
    a `goto`+ternary `cond ? (fcmpo-expr) : 0` and put the inactive/fall-through
    block FIRST (recipe #21 layout). (zulu18, arwbombcoll 90.9→98.3%.) (b)
    **li-branch form** — target does `li r0,0; fcmpo; bge; fcmpo; ble; li r0,1;
    cmpwi r0,0; beq`: reproduce by ASSIGNING the `&&` to an int temp THEN testing
    it — `int v = (d < A && d > B); if (v){…}`. Writing `if (d<A && d>B)` directly
    short-circuits with NO materialization (loses the `li r0,0/1`); the int-temp
    assignment forces it. (zulu19, arwsquadron_update — all 5 instances,
    83.4→85.8%.) Only leave it a cap if NEITHER form lands.

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
    such fns just CAP at ~66-70%; commit the for-loop partial and move on.
    **Unroll-FACTOR mismatch is a separate, often-uncontrollable cap.** Even with
    the right loop form, MWCC sometimes picks a DIFFERENT unroll factor than target
    for a fixed-trip loop (target unrolls a 16-trip init to ctr=4 / x4, a 12-trip
    to x3; MWCC unrolls your identical-body source MORE — x8 / x4). Field-reorder
    and constant-lift don't flip it, and there's no per-loop unroll pragma. When
    the only residual is "target unrolls x4, mine x8" on an init/clear loop, it's a
    codegen-heuristic cap — leave the partial.

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

48. **"WCTileIface vtbl struct" form documents a CAP, not a fix — `lwz r12,
    off(iface); mtctr; bctrl` ALWAYS hoists to statement front.** When target
    evaluates a dispatch's args L2R but the 3-load iface chain
    (`lha r3; addi r4; addi r5; lwz r6 x3; lwz r12, off(r6)`) sits at the
    LAST-ARG position in target while MWCC's output puts it at the *first-arg*
    position — there is NO clean-C form that defeats the hoist. Tested
    exhaustively: GC 1.2.5-2.7, sched on/off, -O2/3/4, lang c/c++,
    struct-member / raw-cast / local / inline-helper / volatile forms — all
    no-flip. ~6 reordered instrs × N call sites is the residual. Commit the
    partial and move on; same cap likely caps wcpushblock and other
    iface-dispatch fns. (wctile, task #120.)

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
    output is identical to the per-file form. Took the 4-placeholder
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
    register-coloring residuals (recipe #16 cap), branch-displacement
    layout (recipe #21). Not all are tractable — but knowing which
    *category* a partial is in lets you skip the unrecoverable ones.

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
    scratch local (`int ret;`/loop counter) FIRST.** Three confirmed wins in
    one session: when target colors params/early locals to HIGHER saved regs
    than yours (obj→r31 vs your obj→r29, with the whole body cascading),
    insert/move a plain `int` local that's only used LATE to the TOP of the
    decl list. MWCC then assigns it last-internally and the param/early-local
    coloring shifts up to match (endObjSequence j-first → j=r31;
    explodeplan_updateTriggerCallback ret-first → obj/q/runtime=r31/r30/r29;
    fn_802C0A5C inner-before-q → p2/q=r31/r30). Try this BEFORE declaring a
    recipe #16 coloring cap.

61c. **Limit of #61b — 2-variable chained-deref pairs (`p = load; q = *(p+off)`)
    do NOT respond to decl-order.** When the ONLY divergence is a 2-reg
    permutation across a load chain (target q=r5/p=r6, yours p=r5/q=r6, every
    use cascading), decl-order flips were tried both ways and failed on 5
    separate fns in one session (getLoadedTexture, saveFileStruct_isCheatActive,
    playerAddHealth, fn_8002CE14, ObjModel_CopyJointTranslation — also the
    `lwz+mr` copy-pair direction in dimlogfire_init/curUiDllDraw). #61b works
    when there are ≥3 independent locals to reorder; the 2-var chain coloring
    is allocator-internal. Classify on sight and skip — the residual is
    ~5-10 bytes.

61d. **The @NNN-vs-named conversion-bias cap: MECHANISM + tested negative.**
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
    fsubs. The real fix is splits/link-level (dedup our .sdata2 bias entries
    onto the auto_11 symbols) — out of recipe scope; don't grind it per-fn.

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
    fneg` empty-then layout; `if (!(x>=K)) x = -x;` and `if (x>=K){}else{}`
    both materialize the bool (mfcr) instead.** When target shows the odd
    `fcmpo; cror eq,gt,eq; bne L1; b L2; L1: fneg; L2:` shape for a
    conditional negate, the C is the ternary keep-or-negate assignment, NOT
    an if-statement. BUT for a conditional RETURN with the same cror+bne
    shape, `if (!(f >= K)) return;` works directly (no mfcr) — the
    materialization only bites in an assignment context. Both instances were
    real Ghidra import condition-INVERSIONS on fn_80151DB8 (the import
    negated/returned on the opposite branch) — whenever target's branch
    sense differs from the import's, suspect inverted logic (drift section)
    before a codegen cap. fn_80151DB8 98.16→100.

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
    (d) **`_savegpr_NN` differs (extra saved reg)** → NOT a frame mystery:
        one extra live range, usually MWCC CSE-ing a repeated address expr
        (`(char*)o2 + 0x18` ×3) into a saved reg where target recomputes.
        Value-numbered CSE — different SPELLINGS of the same value
        (`(char*)(o2+6)`, `(u8*)o2+0x18`) do NOT defeat it. But FIRST diff
        the logic: fn_801CE2BC's "frame residual" hid 3 missing vtable
        double-derefs, two INVERTED float compares, and a missing
        `case 0x13:` fallthrough (97.0→98.15 from bug fixes alone).
    Null results (don't retry): dead/unused locals and dead conversions drop
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
    inert; see task #146).

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
    (deref via the copy of a NON-r3 param) remains a cap. Supersedes the
    "param-relocation cap class" note in the triage table below.
    **Where #68 does NOT apply — peephole-ON-target units (audio TUs etc.).**
    The recipe assumes the peephole pass is propping the copy and target
    compiled WITHOUT that prop. In a unit whose target compiles peephole-ON
    (no pragmas — audio/), target's compile ALREADY did the propagation, so
    the residual there is genuine scheduler/coloring, NOT copy-prop.
    Diagnostic: check the unit's pragma state FIRST. Applying `peephole off`
    to a peephole-ON-target fn REGRESSES hard (golf-1's audio-cap A/B:
    synthAssignHandle 98.6→81.4, hwChangeStudio 98.2→82.1,
    synthGetNextChannelEvent 98.0→91.8, DoSetPitch unchanged — all reverted).

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
- **TRACTABLE — int compare/`+`-operand swaps respond to recipe #66** (a
  block-local for one operand) where the bare source flip does NOT — MWCC
  canonicalizes `cmplw`/`add` operand order regardless of source order
  (mapTextureOverrideRelease, RollingBarrel_free, objGetTotalDataSize all
  won via the local; the flips alone were no-ops). FP `fcmpo` + branch-sense
  pairs DO respond to the plain source flip (`best < v` → `v > best`,
  frustumPlanes 99.78→100) — flip when the BRANCH differs (ble vs bge),
  add a local when only REGISTERS differ.
- **CAP — FP volatile reg-number permutation** within a statement window
  (fcmpo operand pairs, lfs/stfs bursts, fdivs/fmuls chains, fctiwz). Decl
  order, temp locals, statement order, compare-direction flips all invariant
  (wctemple_update 8 forms, LanternFireFly_func0B 4 forms, arwbombcoll
  delta-order 6 forms). Signature: N same-opcode instr pairs with only FP reg
  numbers swapped. ~10 fns in the tier (dll_127_init, Curve_SampleSegmentPoints,
  exploded_seedDebrisMotion, scarab fn_8015EA48, drawTexture, pi_dolphin
  fn_8004E0FC, magiccavetop fmr) — skip on sight.
  **EXCEPTION (cracked sub-shape): decrement+clamp where the compare CONSUMES
  the fsubs/fmadds RESULT (no reload between store and fcmpo).** Write
  `f32 t = global - delta; global = t; if (t < lim) global = lim;` — the
  explicit t homes the result in f1 (the minuend's reg) matching target;
  compound `-=` and the expanded re-read both leave it in f0
  (MMP_levelcontrol_update 99.88→100). DISCRIMINATOR: if target RELOADS the
  field before the fcmpo (lfs f1,off(rN) fresh load after the stfs), the cap
  stands — verified still-capped on fn_801CEA14, dim2icicle_update,
  cclevcontrol_update, wctemple_update. Read the target asm between the stfs
  and the fcmpo to pick.
- **CAP — `addi r0,rH,lo; mr rX,r0` vs direct `addi rX,rH,lo` global-address
  materialization** (foodbag dll_82_func03, mapSetupPlayer,
  camcontrol_loadTriggeredCamAction). Initializer-decl form, statement
  position, array-decay all invariant — yet other fns (player fn_8029DB70)
  get the direct form from identical-looking C; discriminator unknown.
- **CAP — player_SeqFn (98.10) top-pair allocation order: DO NOT retry the
  cache-inline fix.** Eliminating the (int)inner cast-copy web (savegpr
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
  `li -K; and`. Both player_SeqFn residual families are allocator/codegen
  caps pending a new recipe.
- **CAP — web-split reload coloring** (reloaded pointer gets a fresh saved
  reg where target reuses the original — MoonSeedPlantingSpot_setScale;
  decl-perms and second-local splits all regress) and **reverse-order saved
  pairs** (worldasteroids_init — recipe #16's documented reverse cap).
- **CAP — materialized-mask `lis;or` for `|= 0x20000`** (warpDarkIceMines)
  — recipe #2 inverse re-confirmed; const-lift and expanded `x = x | K`
  still fold to `oris`.

## Compiler-emitted 64-bit / fixed-point math: a recognizable cap class

A function full of `__shl2i`/`__shr2u` runtime-shift helpers, `addc`/`adde`/
`subfe` long-long arithmetic, and unrolled rounding-division/reciprocal loops
(often 10×-then-7× `rlwimi` rotate sequences) is **compiler-emitted s64/fixed-
point math**. The exact unrolled sequence is near-impossible to reproduce from
clean C with current playbook recipes. When you recognize the pattern,
commit your best clean-C partial and document the residual — don't grind.
If a future recipe lands that cracks this class, it will become tractable
across every such function at once.

## No `asm { }` blocks — ever

**Hard rule, no exceptions.** Inline `asm { }` is never an acceptable match
tool on this project, even for cases the playbook previously sanctioned
(materialized-mask `li`/`lis;ori` + `and`, GQR/MSR/HID0 `mtspr` ops, `rlwimi`
bit inserts, register-order forcing via `register` decls). If clean C won't
reach 100%, **leave the partial and document the residual** — there is always
a C recipe for the divergence; we just don't know it yet. New C techniques
land in this playbook as they're discovered; asm escape hatches don't.

Previous reference commits using asm (`2e20e326`, `01400901`, `a42bb90b`) are
being reverted by the repo owner (see "Replace X flag asm with C" commits) —
do not cite them as precedent.

If a function is stuck below target because of an unknown-C divergence, the
correct action is:
1. Commit the highest clean-C partial you've reached.
2. Document the divergence (target asm shape vs your output) in the task
   notes or commit message.
3. Move on. The function will be revisited once the new playbook recipe lands.

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

**Loop induction-update ORDER is sometimes a hard cap (~1-3 instr).** Target
emits `addi ptr; addi counter; cmpwi counter; b`; clean-C array-index form emits
`addi counter; cmpwi; addi ptr` (counter bumped/tested before the pointer). This
does NOT respond to index-vs-pointer-walk OR scheduling toggle — it's allocator/
loop-form internal. Caps some array-walk loops at ~93-95%; leave partial.

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
   the last label silently miscompiles nested-region fns).
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
- `rm -f build/GSAE01/report.json && timeout 30 ninja build/GSAE01/report.json` — refresh report

### Matching-help corpus (Discord export + decomp.me scratches)

A year of decomp.me's matching-help Discord channel (`reference_projects/Discord_chat_*.csv`,
5000 messages, 989 unique scratch links) plus the fetched scratch payloads
(`reference_projects/decompme_scratches.jsonl`, gitignored — regenerate via
`tools/decompme_fetch.py --resume`) form a searchable corpus of real-world
matching attempts: someone posts a scratch with their stuck C, others
respond with the recipe that fixes it. Useful when a residual's symptoms
match something others have already solved (FP register coloring, fmadds
fusion, peephole behavior, rlwinm vs andi, fp_contract surprises, etc.).

- `python3 tools/decompme_fetch.py [--resume] [--limit N] [--delay SEC]` —
  bulk-fetches scratches into JSONL. Uses playwright (headless chromium) to
  bypass decomp.me's Cloudflare bot challenge: one initial page-load acquires
  CF cookies for the session, then API calls succeed directly. ~80min for the
  full 989 at default delay=2s. Resumable; skips slugs already present.
  Per-scratch payload: name, compiler, platform, source_code, context (decls),
  target asm, current (compiled-C) asm, score/max_score.
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
