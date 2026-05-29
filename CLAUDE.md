# SFA-Decomp Matching Playbook (MWCC 1.2.5n, EN v1.0)

Short field-tested reference for getting MWCC-compiled C to match the target
binary. Read in 60 seconds, apply in the order they appear; the later sections
are more invasive.

## Prime directive: recover plausible C, not byte-perfect asm

The goal of this project is plausible original source. A function at **80-99%
fuzzy from clean C is more valuable than a 100% byte match achieved by inline
`asm { }` blocks**. The asm-block recipes below exist for a small number of
genuine MWCC instruction-selection bugs — they are **not** the default tool
for "the diff is still red." If a residual won't yield to the one-liners and
source-form tweaks in the next two sections, commit the partial and move on.
Inline asm in production source is a code smell; we'll only keep it where a
clear MWCC compiler quirk leaves no C alternative.

Heuristic before reaching for `asm { }`:
- Is the residual a single instruction / register-allocation choice? → leave at
  partial, commit, move on.
- Is the function ≥80% fuzzy on clean C? → leave at partial, commit, move on.
- Does target's behaviour require an instruction MWCC literally cannot pick
  from any C input (e.g. specific `rlwimi` bit insert, `cmplwi` on a value
  MWCC sign-extends)? → only then is asm justified, and call it out in the
  commit message.

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
   Caps tiny flag fns ~70% — leave partial, don't grind. (november9, 80295318
   fn_80296BBC.) The asm `li;and` recipe at the bottom *can* force it but isn't
   worth it for a tiny fn — Prime Directive.

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
    fixable via symbols.txt.** objdiff content-matches the literal-pool entry by
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

12. **Model a single-bit flag as a C bitfield to get `rlwimi` from CLEAN C** —
    this **supersedes the asm `rlwimi` recipe below** for the common single-bit
    case. When target sets a flag with `li r3,1; rlwimi rX,r3,sh,mb,me` but your
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
    swapping two `int` locals, often flips the allocation to match. No asm —
    try this before any `register`/asm approach. See `fa209c270`
    (fn_8019C3A0 → 100%).
    **But SAVED-reg coloring is sometimes allocator-internal and NOT
    source-flippable — after trying decl-order BOTH ways, treat it as a hard cap
    and STOP.** On some units there's a *systematic* saved-reg permutation: target
    assigns the LOWER reg# (r27/r29) to the longer-lived / earlier variable (the
    obj/setup base), MWCC does the reverse, and it cascades through every
    instruction referencing that var. Declaration-order reorder (both directions)
    does NOT flip it. This caps every fresh function on the affected unit at
    ~74-90% — it is the dominant residual on placeholder_80220608 (zulu15:
    wcpushblock obj/player r29↔r30, wcfloortile setup r27↔r29). Don't grind it;
    the partial still banks real fuzzy%.
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
    MWCC fuses to `fmadds`. (Corrects the earlier "no fp_contract control"
    assumption behind the mtx44_mult tar pit.) CAVEAT: it only controls the
    fmadds FUSION — it does NOT fix eval-order / FP-register-allocation
    divergences. hotel7 confirmed Matrix_TransformVector still capped ~55% with
    fp_contract off (its divergence is FP-reg/eval-order, not fusion), so try it
    on a true fmadds-vs-fmul+fadd mismatch but don't expect it to fix coloring.

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
    the clamp chasing it (hotel5's logically-correct rewrite scored *lower*).
    (hotel5, fn_8001D820/fn_8001D84C ~68%.)
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
    (november12, skyFn_80088c94/skyFn_80089710.)

## Tar-pit cap class: compiler-emitted 64-bit / fixed-point math — DEPRIORITIZE

A function full of `__shl2i`/`__shr2u` runtime-shift helpers, `addc`/`adde`/
`subfe` long-long arithmetic, and unrolled rounding-division/reciprocal loops
(often 10×-then-7× `rlwimi` rotate sequences) is **compiler-emitted s64/fixed-
point math** — the exact unrolled sequence is near-impossible to reproduce from
clean C and asm-forcing it violates the Prime Directive. Treat these as a
TAR-PIT cap: deprioritize, don't grind, don't burn a session on one. (mike13,
fn_80007F78 ~2212B on 800066E0.) Spend the budget on tractable handlers instead.

## Last-resort: inline `asm { }` blocks with `register` variables

**Read the Prime Directive at the top of this file first.** Use this only when
the residual is a true MWCC instruction-selection bug (e.g. specific `rlwimi`
bit insert, register-allocation order that nothing in C controls). A clean C
function at 85-99% beats an asm-forced 100% every time on this project.
Recent over-use note: leaving 9 functions matched via `asm { extsb / lis /
addi }` looks like a win on the report but leaves source nobody would
recognise as the original — that's not the goal.

When MWCC won't pick `rlwimi` / `li +/- N; and` / `cmplwi` from any C form,
drop an inline `asm` block. The pattern:

```c
{
    register u32 m;             // declared first → gets r0 (immediate slot)
    register u32 v;             // declared second → gets r3
    register int pReg = obj;    // forces the parameter into a fixed register
    /* normal C statements that precede the bit op stay outside the asm */
    asm {
        lwz v, 0x54(pReg)
        li m, -1025              // forces the "long" form vs MWCC's rlwinm
        and m, v, m
        stw m, 0x54(pReg)
    }
    /* normal C resumes */
}
```

**Critical: declaration order chooses the register.** MWCC's allocator picks
volatile regs roughly in declaration order. To match target's
`li r3, -1025; and r0, r3, r0` instead of `li r0, -1025; and r3, r0, r3`,
swap which `register u32` is declared first. This is how `CameraModeCombat_free`
and `fn_80189BE4` were taken to 100% — same body, just reordered the two
`register` lines. See `01400901`, `a42bb90b`.

For `rlwimi` (bit insert vs MWCC's `andi+ori`) — **try one-liner #12 (model the
flag as a C bitfield) FIRST**; it produces the identical `li; rlwimi` from clean
C and is now the preferred fix. Only fall back to this asm form if the field
genuinely cannot be expressed as a bitfield member:

```c
{
    register u32 b;
    register u32 bitval;
    bitval = 1;                              // value to insert (0 or 1)
    asm {
        lbz b, 0x1d(t)
        rlwimi b, bitval, 5, 26, 26          // insert at bit position 5 (= 0x20)
        stb b, 0x1d(t)
    }
}
```

**`asm { }` blocks wreck nearby FP scheduling.** MWCC treats the block as an
opaque barrier and reschedules surrounding FP work around it. In a function
that mixes float stores with a bit-clear, an inline asm rlwimi can shift every
later `lfs`/`stfs` and tank the overall match. Use `asm { }` only in functions
that don't otherwise use FP regs, or place it adjacent to function entry/exit.

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
inlined into a big caller barely moves the symbol size). On inline-heavy TUs
(placeholder_800066E0), run this check first on any partial <90%.
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
loop-form internal. Caps array-walk loops at ~93-95%; leave partial, don't grind.
(november12, newclouds loops.)

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
- `rm -f build/GSAE01/report.json && timeout 30 ninja build/GSAE01/report.json` — refresh report

## Reference commits

| Technique | Commit |
|---|---|
| asm{} + register-order (rlwimi/li+and) | `2e20e326`, `01400901`, `a42bb90b` |
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
