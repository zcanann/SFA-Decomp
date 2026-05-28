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
   residual. Whole object-DLL units (e.g. placeholder_80220608) match best on
   scheduling-off-only.
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
    **Base-pointer hoist for saved-register coloring.** When target keeps a
    repeatedly-used base address in a *saved* register (r29-r31) across the whole
    function — e.g. it references one global table at many offsets — declare that
    base as the FIRST local (`char *base = (char *)lbl_xxxx;`) and use `base + off`
    everywhere, instead of re-deriving the address per access. MWCC then parks it
    in a callee-saved reg matching target's coloring. Took fn_8029FA24 90.7% →
    96.8% in one move (placeholder_80295318).

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

## `#pragma dont_inline on` for callees that live in the same TU

With `-inline auto`, MWCC inlines small functions into their callers within
the same `.c`. If the target binary keeps the `bl callee`, the caller will
never match. Wrap the callee:
```c
#pragma dont_inline on
void small_helper(...) { ... }
#pragma dont_inline reset
```

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

## `for (i=0; i<n; i++) { use(*p); p++; }` vs `*p++`

MWCC emits a `bdnz` countdown loop only when the increment and the
dereference are separate statements. `*p++` merges them and the loop loses
the tight `lwz; addi; cmpw; b` body that target uses. Keep `*p` and `p++`
on separate lines inside the loop body.

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

## Tooling

- `python3 tools/function_objdump.py --diff <unit> <symbol>` — per-function diff
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
