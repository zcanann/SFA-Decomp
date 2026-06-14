# SFA-Decomp Matching Playbook (MWCC, GC/2.0 main lib · 1.2.5n audio/MSL)

Lean lever-index for matching MWCC-compiled C to the target binary. Each recipe is the
actionable trigger→fix; **full detail, examples, negative-maps, and frontier analyses live in
`docs/matching_archive.md`** (recipe numbers match). Read that when a one-liner isn't enough.

## Prime directive: recover plausible C, never asm
- Goal = plausible original source. **Inline `asm { }` is forbidden — no exceptions** (even
  previously-sanctioned recipes are revoked; the owner reverts them). An 80-99% match from clean
  C beats a 100% asm match.
- A residual that won't yield: **commit the partial, document the target-vs-yours asm shape, keep
  it on the retry list.** Every fn is attemptable; "stuck today" ≠ "impossible." New C recipes
  land here as discovered; a documented partial is the seed for the next one.
- **FRESH-EYES PROTOCOL:** re-attack banked residuals WITHOUT reading the prior negative map —
  derive the lever from target asm as if the fn were new. Most "#108/#82 coloring caps" are
  MISLABELS; many fell to fresh eyes (struct fixes, dropped args, arg-eval order, widths).

## Method (do this every time)
- **Read the WHOLE target fn before diffing.** Diffs show WHERE, not WHY, and bias you to a false
  "#108 coloring" verdict. Dump full asm (`function_objdump.py <unit> <symbol>`, no `--diff`),
  note each `bl`'s real callee arg shape + field widths/compares, THEN diff.
- **Source of truth for % = `report.json` `fuzzy_match_percent`.** Force-rebuild the unit's src .o
  first (`rm` it + `ninja` it explicitly); `ninja report.json` alone can serve a stale .o.
  `--diff`/`ndiff`/`rotmap` LOCATE divergence, never certify (they mask reorders/fusion). `rotmap`
  also invents phantom "structural" regions on misalignment — eyeball the raw stream.
- **Pragma wrappers reproduce per-fn optimizer STATE**, not original source. Byte-verify
  (`md5sum` the .o) any pragma change. `reset` POPS a stack (restores surrounding state, not
  default) — model nested regions as a stack and emit each fn's *effective* state.

## High-impact one-liners (try first at 80-95%)
1. **`#pragma peephole off` + `scheduling off`** (matched with `reset`) around the fn — unfuses
   `extsb.`/`rlwinm.` dot-merges; routinely 80-95→100. Treat the two INDEPENDENTLY: `scheduling
   off` alone wins call/FP-heavy fns; add `peephole off` only for a specific `extsb.`/`rlwinm.`
   residual. A/B per-fn. Caveats: peephole-off suppresses jump tables (but dense switches keep
   both — test for `bctr`); locally re-enable with `peephole on`…`reset` for one jump-table fn
   inside a global-off region; split a multi-fn `on` region to capture asymmetric wins. Audio TUs
   compile both passes ON — never wrap them (regresses hard).
2. **`& ~0x80` not `& 0xff7f`** for single-bit clears → `rlwinm` not `andi`. Materialized-mask
   inverse (target does `li -K; and`): **`x &= ~0x80LL`** (LL suffix) — see #74.
3. **`*(void **)ptr != NULL` not `*(int *)ptr != 0`** → `cmplwi` (pointer) not `cmpwi`. `x == 0u`
   (u-suffix) forces `cmplwi` on u8/bit-extract compares. `(u32)x != 0` is INERT (folds back to
   signed); use `(void *)x != NULL`. A CSE-merge with a nearby int read can still win signed → may
   need a struct-field pointer retype.
4. **`if (v > K) v = K; return v;`** not the inverse → target's `blelr` clamp.
5. **Swap local decl order to control stack offsets / coloring.** DECL position sets register home;
   INIT position sets emission — split `int x = e;` into `int x;` + `x = e;` to place each
   independently. Address-taken locals sometimes color in REVERSE decl order — flip if needed.
6. **Lift a repeated constant to a local before multiple stores** to force CSE. EXCEPT lift only
   when the live range is call-free (a use across a `bl` forces a callee-saved FP reg + frame
   grow); inline the global when a use crosses a call — UNLESS target itself keeps it in f31
   across the call (then hoist to reproduce the save).
7. **`u8` not `char`** for byte arrays you load+assign without arithmetic (drops spurious `extsb`).
8. **Wrap dead-stored stack locals in a `struct`** when only the buffer head is passed to a callee
   (keeps the per-field stores alive). Pairs with `scheduling off`.
9. **Declare dispatchers with the FULL arg signature** when an intermediate call sits between entry
   and dispatch (preserves r3..r7,f1). Corollary: a callee may take MORE params than its body uses
   — declare the trailing dead params so the caller sets up the registers.
10. **`(f32)(u32)` cast on a u8/u16 before int→f32** forces the unsigned path (named `lbl_` f64
    magic, matching target) vs the signed `@NNN` magic. Try `(f32)(int)x` vs `(f32)(u32)x`. The
    `CONCAT44(0x43300000,...)`/`__cvt_ull_dbl` Ghidra idiom → rewrite as direct `(float)(int)x` /
    `(float)(u32)x` (drops the helper, frame shrinks). @NNN-vs-named reloc is score-NEUTRAL (#70).
11. **`extern int fn()` not `extern u8 fn()`** when target treats a byte return as int (no `clrlwi
    r3,r3,24` after the `bl`). Same at vtable-slot scale, but A/B per-fn — most u8 vtable returns
    are correct; isolate a lone regressor with a block-scope fn-ptr cast.
12. **Model a single-bit flag as a C bitfield** (`u8 x:1;` at the `rlwimi`-implied bit) → clean-C
    `li; rlwimi`. #39 extends to multiple bits at one byte offset via a bitfield-overlay struct.
13. **Reorder `case` labels to target block-address order** (read block addrs / the jump table from
    the unit's data `.s`). A dropped empty case shifts a binary-search pivot — count target's cmpwi
    values to recover the full case set and add `case K: break;`. Empty-case islands can be
    PEEPHOLE-state-bound — retry under peephole off.
14. **`int` param (not `u32`) for `(arg & bit)` flag tests** → `cmpwi`.
15. **`*(s8 *)(p + off)` not `(s8)p[off]`** to land the byte in the target/arg register directly.
    Array-index form (`(s8)arr[off]`) gives `lbz; extsb r3,r0`; deref gives `lbz r3; extsb r3,r3`.
16. **Clean-C local decl order controls volatile-register coloring** (MWCC colors roughly in decl
    order). Also: making the base a real typed PARAM (not `void*`+copy) often flips r29/r30/r31;
    `f32 m[16]` (64B) vs `Mtx m` (48B) controls frame size; hoist a repeatedly-used base address
    into the FIRST local for a saved-reg home; overlay a cluster of globals with one struct cast on
    a single base.
17. **Fold multiple early-return guards into one `||`** (with embedded assignments) for
    convergent-predicate fns. Inverse: an embedded assign in the merged guard defeats the
    adjacent-value range-fold and keeps separate `beq` tests; a merged guard whose `far` target is
    pinned by an earlier `||` term's branch survives folding (the unsigned b-over-b case).
18. **Model base+displacement indexed loads as a STRUCT member-array** (`tbl[idx].f`) → `add; lha
    disp` not `lhax`. End-pointer form `T *top=&arr[n]; top[-1].f` for the last element.
19. **Low fuzzy% + high instr-diff% = ONE dropped/folded instruction early** (often a literal `int
    x=1;` target keeps live). Make it non-foldable (assign from an adjacent call's return).
20. **Compound-assign a narrow lvalue (`*(s16*)p += K`)** not the expanded RMW (drops redundant
    `extsh`/`extsb`). `i++` vs `i = i + 1` on a `u8` counter picks mask position (use vs def).
    `(s16)timeDelta` DIRECT subtrahend truncates straight to s16 (no `(int)` node).
21. **Invert `if(c){A}else{B}` → `if(!c){B}else{A}`** to flip then/else block layout. Dispatch
    FORM: `if/else-if` chain = linear `bne`; `switch` = binary-search/jump-table — pick what
    target uses. Cloned-call-per-arm: write the call in BOTH arms literally (not a ternary arg).
22. **Wrap body in `if (cond) { ... } return 0;`** not `if (!cond) return 0; <body>` (drops an
    extra `li r3,0; b` island).
23. **`!!x` for the double-`cntlzw` non-zero materialization**; `!x` for the `==0` form; plain
    `!=0` gives `neg; or; srwi`. `break` (fall to common return) instead of case-body `return 0`
    drops a spurious cntlzw. `li 1; cntlzw; rlwnm ,31,31` = MWCC's `x <= 0` (signed) materialization.
24. **`f32 fn(f32)` not `double fn(double)`** for single-precision helpers (avoids `fmul`+`frsp`).
    `#pragma fp_contract off` per-fn controls fmadds fusion (not eval-order/coloring).
25. **FP compare feeding a BRANCH = write the plain operator** (`if (a >= b)` → `fcmpo`+`cror`); a
    MATERIALIZED float-bool (stored/returned) needs the mfcr/srwi or li-branch recipe forms. For a
    plain `bge`/`ble` clamp where `>=`/`<=` over-produces the cror, use #91.
26. **"Floor-first" clamp restructure** (`x=floor; tmp=computed; if(x<tmp)x=tmp;`) forces a fresh
    callee-saved FP reg (fixes frame + coloring).
27. **Lead an accumulation subterm with the UNARY-NEGATED operand** (`-values[0] + k*v1`) → `fneg`
    + `fadds` instead of `fsubs` (preserves a reused product).
28. **A runtime `slw` over fixed bit positions = an UNROLLED `for` loop** — write the loop, not the
    manual unroll (only when the body is ≤~4 instrs). Count-down form `for(i=N;i!=0;i--)` flips
    unroll factor/style; `(i<<2)` byte offsets stay unfolded where `i*4` folds.
29. **Callee param POSITION controls caller's L2R arg-emission order** — reorder the extern
    signature to match target's load order (one fix lifts every call site). #84/#87 are siblings.
30. **Alias `T *base32 = (T *)base;` + index** flips `lwzx`/`lhzx` → `add; lwz disp` for fixed
    displacements off a raw-pointer base.
31. **Whole-struct assignment `*dst = *src`** for paired `lwz`/`stw` blob copies (right order).
32. **`fr = conv; fr = lbl + fr;` 3-statement form** for `fadds lbl, conv` operand order.
33. **`if (cond) { body } else return 0;`** — keep the constant return in the ELSE arm.
34. **Address-taken FP outparam decl-order: first-declared gets the HIGHEST stack offset.**
35. **Typedef'd vtable fn-pointer** fixes Ghidra's `code**` double-deref (clean `lwz r12; mtctr;
    bctrl`); also fixes f64 arg-type loss.
36. **Drop redundant `(int)`/`(uint)` casts at call sites** — they inflate a param's saved-reg
    priority. Scales to whole-quad rotations, but ALL the no-op casts must drop at once (a partial
    drop shows nothing). Diagnose with per-use-class deletion probes.
37. **`(u16)` on the WHOLE OR-expression** → one `clrlwi` at the store (vs per-operand).
38. **`(x & N) ? 1 : 0` ternary** for branchy bool materialization; `(x & N) != 0` gives the
    arithmetic `neg/or/srwi` form.
39. **Bitfield-overlay struct** for byte flags at a specific offset (generalizes #12 to multiple
    bits + `rlwimi`/`rlwinm` read/write).
40. **Embedded-assign in `if()` (`if ((h = helper()) != 0)`)** avoids `stw`+`lwz` reload (keeps the
    result live in the return reg).
41. **`return (s32)floatExpr;`** emits `fctiwz; stfd; lwz` epilogue (no extra temp).
42. **Ternary `cond ? K1 : K2` into a typed lvalue** → per-arm `li; b; li; extsX` join.
43. **Comma-init `for (i=0, p=base; ...)`** → `li 0; mr p,base` (two-instr loop init).
44. **`*(u16*)&lbl`** for `lhz` when a u16 global is passed as a u16 param (vs `lha; clrlwi`).
45. **Loop-invariant single-deref into a saved-reg local** for FP constants target keeps across
    loop calls; decl order sets which const → f31/f30/f29 (first = f31).
46. **Re-derive struct field offsets from target asm, not the import skeleton** (v1.0 vs v1.1
    layout shifts). Treat stuck 60-95% partials as offset-bug suspicion before allocator-cap.
47. **sda21 direction:** sized-array extern for a small `.sdata` symbol → `@sda21`; for >8B objects
    use scalar `extern T sym;` + `(&sym)[i]`. Force the far form with incomplete `extern u8 lbl[];`.
48. *(OPEN)* WCTileIface vtbl dispatch-hoist — `lwz r12; mtctr; bctrl` hoists to statement front;
    no clean-C form found yet. Commit the partial.
49. **Switch with case-FALLTHROUGH** (`case 0: case 1: case 2: { body; break; }`) for sequential
    shared-body dispatch.
50. **Nested `outer(inner(x), y)`** keeps r3 live across calls (vs a spilled local).
51. **Chained `x = y = z = K;`** CSEs ONE constant load across stores.
52. **Ternary `(a >= b) ? b : a` clamp** for a `mr; clrlwi; stb` store shape (vs if/else split).
53. **`(s16)` cast on a compound `-=` subtrahend** drops the spurious `extsh`.
54. **Two locals = same base** when target holds one pointer in two different saved regs (only when
    visibly so).
55. **Mixed hoist**: target hoists a global to a saved reg AND re-derives it fresh in a loop —
    reproduce both placements with a block-local re-read.
56. **Delete a same-TU duplicate def** that steals a `bl`'s reloc to the canonical sibling. GUARD:
    only for NON-inlined externals (keep `extern inline` dups).
57. **Block-scope `extern` overrides** reconcile per-file extern-type disagreements when merging
    TUs (per-file form is load-bearing for codegen). Pointer-return/no-file-scope redecls are
    accepted; object/void-vs-int return redecls are rejected; dedupe identical typedef/tag redefs.
58. **Type the local to match the field width** (`u16 num = field` keeps `cmplwi`; `long` widens to
    `cmpwi`). Keep the local for CSE; just type it right. Struct-FIELD width is the same lever —
    A/B project-wide before flipping a shared typedef; launder minority sites with a cast pointer.
59. **Lift the LEADING term to its own statement before a dot/sum** to defeat commutative-FP
    reassociation (`f32 yy = a[1]*n[1]; f32 dot = yy + a[0]*n[0] + ...`). `scheduling off` does NOT
    fix reassociation.
60. **At 99.9% with `--diff` showing "identical," byte-compare before assuming a pool artifact** —
    most hide a real constant/operand/loop-bound bug. Use `cosmetic_audit.py`. Single-instr real-
    bug signatures: missing vtable deref (`lwz r12` vs `addi r12`), wrongly-guarded store
    (branch-displacement off by one store).
61. **Distinct pointer locals (not `p += K`)** to keep target's `addi rX,rX,K` base-bump. Companion:
    REASSIGN THE PARAM (not a new local) so the variable relocates to the copy reg.
61b. **Late-used scratch local declared FIRST** re-ranks param/early-local saved coloring up.
    Full-reverse-split (decl order reversed + inits separated) is the strongest battery member;
    third-web edition: move an UNRELATED short local's decl to flip a stuck pair.
61c. *(mostly →#107)* 2-var chained-deref/copy pairs — un-name the value target keeps lower (#107),
    or chained init `p = base = lbl;` for same-init copy pairs.
62. **`(int)`-cast the store base** to defeat address-CSE with a later `(u8*)p+off` call arg
    (restores the displacement-form store).
63. **Ternary `x = cond ? x : -x;`** for the `bne; b; fneg` empty-then conditional negate; for a
    conditional RETURN use `if (!(f>=K)) return;` directly. Single-use result substitutes — use the
    empty-else `if (x>=K){}else{x=-x;}` (no mfcr; in-place fneg).
64. **`int` local + `(u32)` cast in the test** for a direct saved-reg `lbz` + `cmplwi`.
65. **Allocator SKIPS a low volatile around a call → that reg is a HIDDEN live ARGUMENT.** ~half are
    genuine Ghidra-dropped call args — restore them (read target's bl r-register span / sibling
    callees). The tell is "why didn't MWCC use the obvious next reg?" NOTE: 0 structural regions in
    rotmap rules this out definitively (a dropped arg = a missing instr region).
66. **Block-local for one operand** of a swapped volatile pair / canonicalized compare/`add`
    (decl-reorder alone is inert — MWCC canonicalizes operand order).
67. **Frame-size class — diagnose by sp-LAYOUT (not call args; reg args reserve NO outgoing area).**
    (a) inner offsets identical, top differs = phantom temp-slot count (re-evaluate/collapse a
    member chain); (b) GAP between address-taken locals = a stack struct bigger than fields written
    (import-guessed array size — `u8 buf[20]→[16]` etc., the most productive sub-case); (c)
    conversion-scratch slots at different offsets = statement granularity (ternary keeps temps live
    / if-else frees them); (d) extra `_savegpr` = an extra live range (CSE'd repeated address).
    Struct-typed locals reserve their slot even when enregistered (`SND_FVECTOR d;`). `union { f32
    m[16]; f64 a8; }` 8-aligns a stack array. Probe with an address-taken `f32 probe[N]`.
68. **`#pragma peephole off`** makes pre-call derefs use the COPY (`mr r30,r3; lwz r31,184(r30)`),
    matching target — the recurring 1-2 instr "deref via copy" residual is the peephole pass, not
    coloring. Does NOT apply in peephole-ON-target (audio) units.
69. **Match the cmpwi IMMEDIATE, not just the predicate** — `<= 0` (cmpwi 0) vs `< 1` (cmpwi 1) are
    asymmetric; per-compare.
70. **@NNN-vs-named-`lbl` SDA21 relocs are SCORE-NEUTRAL** (objdiff content-matches by data bytes).
    Don't chase pool names / symbols.txt retypes; align the instruction streams — the deficit is
    ordinary codegen elsewhere.
71. **Literal float constants REMATERIALIZE per use; named `lbl_` get CSE'd** — write the literal
    when target reloads at each use; keep the named extern when target keeps it live. fcmpo operand
    order: a literal loads first regardless of side.
72. **`sum = g + (step = k * td);`** — embedded assign keeps LHS-first eval AND forces the product
    into a fresh named FP reg.
73. **dtk FALSE-RELOCATES in-range constants** — a `fn+0xNNN` reloc on a value stored to a flags
    field (addend lands mid-fn) is a literal constant; write the literal + add a `block_relocations`
    range in config.yml.
74. **`LL`-suffixed constants force MATERIALIZED-constant codegen** (`x ^= 2LL` → `li; xor`; `x &=
    ~0x80LL` → `li -129; and`; `x |= 0x100100LL` → `lis;addi;or`). Lvalue must be u32 (int widens
    signed + `srawi`). Convert ALL adjacent masks at once (partial conversion misaligns the burst).
    Bulk-sweep a recurring materialized flag word after mapping every site to its fn's fuzzy%.
75. **`union { f32 m[16]; f64 a8; }`** 8-aligns (fixes +4 offset); frame tracks the COUNT of homed
    locals (fold single-use block locals to shrink).
76. **`int key = id;`** (u16 param widened to int local) fixes `cmpw` signedness AND a volatile
    rotation in one line.
77. **`void *` params + cast-assigned typed locals** split webs / set coloring by decl order when
    same-type copies get propagated away (the cast is load-bearing). Retyping a state param/local to
    the family struct pointer is byte-neutral on most fns, flips coloring on high-pressure ones —
    A/B per fn; keep ORIGINAL arg spelling for `(char*)base+K` call args (don't `&state->field`).
78. **Triple-multiply REGROUP `A * lbl * conv` → `A * (lbl * conv)`** (Ghidra left-flattens; target
    groups const×conversion). Grep `\* lbl_\w+ \* \(f32\)\(s32\)`.
79. **Reconstruct import-dropped/mangled SWITCH CASES via jump-table decode** (auto_07 data `.s`):
    map missing block offsets → case values, transcribe bodies from target asm. Watch the
    corruption signatures (denormal-float = misread int store, dropped FILL/field reads, re-rolled
    RNG, embedded ++/-- split into statements, single-nibble constant bugs).
80. **Named-pointer-local USE-BINDING SPLIT** (`u8 *base = lbl_X;` splits body offset-uses from a
    plain call-arg use → extra saved reg + `mr` copy). Fix: launder the init `(u8 *)(int)lbl_X` AND
    spell the call's plain arg as the same laundered expr; check import-guessed array size. Sibling:
    inline a named `f32 t = *(f32*)(p+8)` deref at every use (CSE temp). Loop-invariant address
    re-derive → `#pragma opt_loop_invariants off`, or split an `int buf[N]`+`&buf[K]` into scalars.
81. **`*(f32 *)&lbl` launder on ONE of a clamp constant's two references** flips the reload/limit FP
    register pair (the fcmpo-on-RELOADED-value case). Discriminator: target reloads the field
    before fcmpo → this; consumes the arithmetic result → temp_t form. Reliable on STORE-clamps with
    a clean same-register swap; resists named-embed/no-store/computed-limit/whole-register-shift.
    Tool: `fcmpo_swap_audit.py`.
82. **FP volatile reg-permutation DECOMPOSES — classify by web kind:** symbol-CSE web → #81
    launder; two named f32 locals → decl-order swap; expression-temp pairs (conversion biases,
    fctiwz, stack reads) = the open sub-class (class-move via embedded-def or ternary-join; block→
    fn-scope promotion of the OTHER arm locals). Probe first — some reproduce standalone. Census the
    shape across `build/GSAE01/obj` before banking a singleton as retail-anomaly.
83. **Conversion-temp pool flushes at a STATEMENT JOIN with a live-var redef or memory store** (not
    a ternary assign). "fresh-ascending slots between if-clamps" → the clamps were ternary
    ASSIGNMENTS; or the two-op wrap-clamp `d = (d - 0x10000) + 1;` keeps bump mode. Co-located wins
    matter more than the frame: (a) fresh-reload launder `*(int*)((u8*)p+K)` (local/param bases
    only; global bases VN through); (b) f32-temp split for eval order; (c) direct `*(s16*)p =
    (fexpr)` (no `(int)` cast) drops the extsh.
84. **The "const-hoist-above-addr-arg" cap is largely #29** — the callee's REAL arg order puts the
    obj/pointer FIRST. Cross-caller arbitrate (majority decl wins); cast at the CALL SITE only,
    never flip the definition. Expression-operand hoist → embedded `x / (sc = lbl)`; call-arg hoist
    is open. ⚠️ Embedded-assign in a call arg whose value is REUSED by later args MISCOMPILES.
85. **Self-reassign chain `fr = conv; fr = lbl + fr; dst = fr;`** pins eval order + reg (a fresh
    temp copy-propagates away). Web-TERMINATION: shape the LAST statement to target's endpoint
    (fold the final op into the store / use store-expression form).
86. *(→#112)* `mr`/`li` setups before an adjacent `lwz`/`lbz` — `int n` not `u8 n` for a u8 loop
    bound flips emission order; the K-on-base grouping (#112) is the non-loop escape.
87. **Declare the f32 param LAST** to get prologue `mr;mr;mr;fmr` (definition-side #29; ABI-neutral).
88. **Multi-def web SPLIT (rename the post-reassign value to a fresh var)** flips a saved-FP pair
    where decl-order is inert (the rename coalesces back, zero cost). #45 decl-order still rules 3+-
    var FP groups.
89. **MIXED if/ternary clamp split** — only the clamp chain BETWEEN two conversion regions needs the
    ternary form (#83); others stay `if`.
90. **#81 launder on the SECOND of a doubled float arg** kills the pre-call hoist, keeps the `fmr`
    CSE. TRIPLED → use the LITERAL spelling. Never embed an assign in a call arg (explodes f31).
91. **Strict-compare nested ternary `*p = (v<lo)?lo:((v>hi)?hi:v);`** reproduces the cror-FREE
    `bge`/`ble` clamp (the #25 counter-caveat). Conversion operands re-execute per arm — inline
    `(f32)x` at each ternary position (named local CSEs to one blob).
92. *(largely →helper/#17/#109d)* Loop-break b-over-b = an inlined `static inline` helper return-
    join; plain-statement = #17 pinned-`||` or #109d switch. OPEN residual: the INT-compare guarded-
    ASSIGNMENT b-over-b in loop-break position (`cmpwi K; bge; b far` over statement-block arms).
93. **FbBuf/cmd-list stack-builder family:** (a) `buf.cmds = (FbCmd*)((u8*)&buf + 0x60)` re-derive;
    (b) per-branch `p = e + K;` in BOTH arms (phi); (c) v1.1 import added a missing trailing `p++`
    — drop it; (d) walker decl-order + init placement sets e/p coloring.
94. **MWCC value-tracks stack addresses through everything except CSE-temp copies and phis** (dies
    at the first call for those). Unfold a `*p` deref web with a same-value conditional second def
    (phi) or by making the walker the sole holder. A pointer store between a stack store and re-read
    kills store-forwarding → use named register locals + self-reassign.
95. **`#pragma optimization_level 0-4` IS accepted per-fn (GC/2.0)**; levels ≤3 switch the allocator
    to creation-order. `opt_strength_reduction off` is FUNCTIONAL (corrects the "opt_* ignored"
    claim — A/B any opt_* pragma before assuming inert).
96. **Counter-chain `lha; addi; sth; lha(reload); cmpwi` with a hoisted `li` = an UNROLLED `for`** —
    write the loop + `#pragma opt_strength_reduction off` (folds the bumped walker to ascending
    displacements). Descending loops fold without the pragma. Volatile-launder cracks just-stored-
    global call args (fresh `lbz`, base reused).
97. **`int local + per-use (f32) cast`** when target re-converts per statement (load CSEs, cast
    doesn't). f32→int direction: `(int)(f64)volf` re-executes `fctiwz` per site at zero cost (the
    f64 promotion changes the VN key); `(int)(f32)(f64)x` does NOT (real frsp).
98. **`#pragma opt_unroll_loops off` IS functional (GC/2.0).** s64 fixed-point: spell halvings
    through a pointer-to-local (`*q /= 2;`), wrap in opt_unroll_loops off. See #109.
99. **O0-shaped body in an -O4 unit = per-fn `#pragma optimization_level 0`** + `optimize_for_size
    on` (supplies `_savefpr`/`stmw` prologue). Peephole/scheduling state per-fn; spell param int-
    reads as `*(u32*)&x`.
100. **MSL/Rare -O0 math units:** `register`-class vars = saved regs (assigned f31/r31 descending in
    decl order); `register int e; e = (s16)(expr);` executes extsh at the def into the var's home.
    Flags `msl_math_o0_cflags` + `-O0 -opt peephole -inline auto -use_lmw_stmw on -schedule off`.
101. **dtk PHANTOM BOUNDARY symbols** — a ~50-60% fn whose missing tail is a zero-ref gap/sibling =
    a symbols.txt SIZE fix (byte-verify vs the dol; only when the absorbed symbol has zero refs).
102. **Scan-loop found-flag idiom** `found=1; goto checked;` + `found=0;` fallthrough, `int found`,
    NO pre-loop init (target has no `li 0` before the loop). Result-is-the-walker → drop the flag.
103. **Repeated branchy ternaries CSE at TREE level** — statement-split into if/else + #40 embedded
    bound assign to reproduce double-evaluation.
104. **Self-reassign accumulator chains** pin FP product groups (compute all products before the
    fadds/fsubs); carry a var's web across phases by reusing it.
105. **K&R-style def for a NARROW param** (`void f(flag,...) u8 flag; int a;`) + int prototype — the
    callee masks at each use, callers pass raw int.
106. **Volatile-STORE spelling `((int volatile *)state)[4] = state[4] + 8;`** keeps every per-
    iteration store of an accumulating slot (loads CSE, stores stay).
107. **Un-naming (the #61c crack): un-name the value target keeps in the LOWER reg** (compiler-temp
    webs color before named-local webs). Walked pointer → INDEX form (`base[i]`, SR temp colors
    lower); chained load → spell the member expression at each use (CSE keeps one load, value
    becomes an expression temp). Narrow-typed locals jump the queue — retype to `int` (keep the
    cast). FP clamps: un-name only when target holds the value in f0 (directional, per-clamp).
108. **Saved-reg assignment is CLASS-POOLED, not weight-ranked.** Single-def copies → top
    (last-created → r31); multi-def/phi → descend in creation order; params → bottom; all-const
    flags → very bottom. Use-count/first-use/loop-depth are INERT within a class. CLASS-MOVERS
    (the lever): first-def-split (a branch-consumed call result → its own var), last-def merge,
    `#pragma optimization_level 2` (creation-order alloc), block-scope per-arm re-decls, same-
    variable recycle (#119). WITHIN-class order is the genuine open frontier (rotmap first; the
    transposition penalty drowns real structural fixes — fix those, then bank the pure-rename
    residual). Cross-class interleave is perturbed fn-globally by a magic-const division /
    conversions (dose effect) — characterized, source-levers exhausted; bank-and-retry.
109. **s64/fixed-point cracks:** (a) `x <<= (n & 0xFFFFFFFF)` materializes the shift-count mask; (b)
    count-down `for(i=N;i!=0;i--)` for the RMW-halving unroll (fixed regs + per-copy `mr`); (c) two-
    web u32 address temp; (d) plain-statement `cmp; beq next; b far` = a single-case `switch` with
    `default: break;`; (e) struct-typed GPR-pair local claims its slot; (f) A/B the MP4 musyx
    CLAMP/MIN macros (nested ternaries); (g) paired hi/lo uint masks = ONE s64 variable.
109d. **Plain-statement `if(x==K){A}else{B}` with `beq A; b B` (branch-over-branch) = a `switch
    (x){case K:A;break;default:B;break;}`** (if/else folds to one `bne`). NON-loop-break only.
    Switch compares are always SIGNED (cmpwi) — unsigned/pointer operands can't reproduce cmplwi
    via switch; the unsigned b-over-b is a #17 pinned-`||` guard (then-block must hold real code).
110. **`li rY,K; mr rX,rY` (target chains a const-equal copy) = per-fn `#pragma optimization_level
    1`** (copy-prop doesn't fold the copy; O1≈O4 for small call-free loop fns). Value-diamond else-
    arm copies are O4-producible via a CSE'd laundered-expression input + named per-arm result.
111. **Member-address reassociation is keyed on the constant's SYNTACTIC ORIGIN** — spell the const
    inside a U8-ARRAY subscript (`&table->flags[(i<<2)+384]`) for `slwi; add base; addi 384`.
    Arg-eval anchor: embed a DEF inside the size/arg statement (`sz = (u16)((count - (index =
    (u16)i)) << 2)`). Apply embedded defs BEFORE an (int)-base launder (order-dependent).
112. **K-grouping picks the displacement isel:** `p = base + K; *(p + idx)` = `add base,idx; lbz
    K(rT)` (base first); `base + (idx + K)` = idx first; flat `base+idx+K` = `addi idx,K; lbzx`
    (fold-onto-index). Named `p` needs MULTI-use (single-use re-folds); symbol-array bases resist
    aliases (direct `tbl[i*4+K]`). Wide deref re-folds to lwzx — `(u8*)` launder the grouped base.
113. **The SPECULATIVE unroller (`srwi ,1; mtctr; ... andi. ,1`) is pragma-controllable:**
    `#pragma ppc_unroll_speculative on|off`, `ppc_unroll_factor_limit N`,
    `ppc_unroll_instructions_limit N`, `opt_unroll_count N`. `reset` is a SYNTAX ERROR for these —
    restore with explicit values. Factor mismatch needs factor_limit + instructions_limit TOGETHER.
114. **No-op CONVERSION NODES split VN webs at zero cost:** `(int)(f64)volf` re-executes fctiwz;
    `e*48 + (int)(long)(c*48)` blocks distributive re-factoring; `(int)((long)x * 8)` splits a
    shift's VN key. Runtime values only (constants fold); global re-reads still need `volatile`.
115. **Callee-decl PARAM WIDTHS shift the caller's WEB CREATION ORDER at zero cost** (a narrowing
    cast into a matching-width param is absorbed; into an int param it makes a persistent node).
    The first source-side lever on the #108 within-class scramble. Requires call-arg conversion
    sites (call-free leaves out of reach). Diagnose by extracting to a /tmp TU.
116. **Embedded-assign in the STORE ADDRESS `*(p = &arr[K]) = value;`** reproduces value-before-
    address emission under scheduling-off.
117. **Embedded-def ternary `t = (x < (t = lo)) ? t : ((x > (t = hi)) ? t : x)`** lands clamp bounds
    in t's callee-saved home (saved-home clamps only; regresses volatile-homed ones).
118. **POINTER-valued nested ternary** for fully-unrolled free-slot scans — the walked operand must
    be a SEPARATE dead variable from the ternary RESULT (else `mr` per arm).
119. **VARIABLE RECYCLING: reuse a dead variable's home reg** = the original reassigned that var
    (write the reassignment, not a fresh local). Works when the reuse changes liveness at the alloc
    point, OR via same-variable affinity even for disjoint webs (A/B per fn — not universal).
120. **Import-SPLIT aggregates: Ghidra splits ONE stack array into array+scalars.** Tells: a direct
    `addi` into the middle of your buffer (whole-object base); a DSE'd store block (rejoin under the
    escaping base keeps stores live); a layout order unreachable by decl permutation. Rejoin.
121. **Preheader-hoist `[int li][lfd bias+lis][f32 lfs]` = the f32 consts were IN-LOOP LITERALS**
    (literals LICM across body calls; named externs don't). Write the literal; hoist-web FP coloring
    is ASCENDING in creation order; split the conversion to hoist the bias first. False-positives:
    `opt_common_subs off` regions, mutable-global inits, min/max accumulators, outparam inits.
122. **At 99.9%, verify switch case bounds + field ownership before allocator grinding** — a dead
    empty case widens the range guard by one; a single-byte store offset after memset is the wrong
    struct member.
123. **FP-register residuals can hide WRONG CONSTANT ownership** — audit which constant each
    expression should semantically use (target keeps an earlier const in f1).
124. **`categorize_near_misses.py` buckets every <100% fn by first-diff symptom.** The compare-
    width/sign bucket is a reliable vein — audit callee return/param signedness (`cmpwi` vs
    `cmplwi`); a call/vtable result cast to int then null-checked → `(u32)x != 0`.
125. **Loop-tail guard polarity** — spell the positive continue guard (`if (i < 8) continue;`) to
    get `cmpwi 8; blt` not `cmpwi 7; ble`.
126. **Param-TYPE pool classing: a POINTER param colors into the COPY pool (high); an INTEGRAL param
    into the PARAM pool (low)** — independent of use spelling. Read target's prologue to RECOVER the
    original param type (per-fn cast noise on an int obj is then faithful). `#pragma
    optimization_level 2` can land the typed-pointer form even in call-bearing fns.
127. **`extern const f32 lbl_X;` = a store-aliasing exemption** — cross-statement load CSE without
    naming a local (a named local CSEs too but flips the FP pair). A/B per unit (check writers
    first); can CSE-overshoot a sibling fn (fix per-site with the #81 launder, don't revert const).
128. **Stack-address pointer that must be SAVED-reg + materialized LATE at first use:** `#pragma
    opt_propagation off` round the fn (stops the rematerialization that a block-scoped `&local` def
    normally suffers — keeps it a real saved-reg var) AND embed the assignment in the consuming call
    arg: `f(.., (pp = &s.x), &s.y, ..)`. Pins the `addi` to that arg's emission slot. Offset-0
    member addresses are special-cased as cheap-remat (volatile) otherwise; #84/#90 "embedded-assign
    explodes" does NOT apply when the assigned value is reused by a LATER identical call, not a later
    arg of the same call. (dimbosstonsil_render 97.5→100.)

## Reference tables & misc levers
- **Caller-side width controls extsb/extsh:** extension on the PARAM side → widen param to `int`,
  cast at use (pushes extension to use side). `s16[]` element → `extsh`; `u16[]` → `clrlwi`.
  `*(u16*)p = 0xFFFF` → `lis;addi`; `*(s16*)p = 0xFFFF` → `li -1`. The u16→s16 store-conversion
  `extsh` is NOT launderable — flip the value's type to s16 (ABI-neutral; gate with a full .o-hash
  A/B).
- **FP compare operand order picks the two `lfs` regs** — `a <= b` → `b >= a` if the loads are
  swapped.
- **`.data` symbol → `extern T lbl[];` (lis;addi); `.sdata`/`.sdata2`/`.sbss` → scalar `extern int
  lbl;` (@sda21).** Check the section in `config/GSAE01/symbols.txt`. Pass a `.sdata` string by
  address via scalar `extern char tag;` + `&tag`.
- **Don't hoist a global/.bss address when target RE-DERIVES it per use** (hoisting parks it in a
  saved reg, shifts coloring + frame). Mirror of #6/#16.
- **`for (i=0;i<n;i++){ use(*p); p++; }` (separate statements) → `bdnz` loop; `*p++` merges and
  loses it.** Inverse: `arr[i] = v` (index) when target strength-reduces to induction pointers. The
  symbol-init shape tells which: `mr rS,r0`-via-r0 = pointer-walk source; direct `addi rS,rX,lo` =
  index source. Loop bump-after-compare is the PEEPHOLE pass — peephole-off emits bump-at-top.
- **Passing a small by-value struct (GXColor) goes BY ADDRESS** — `f(..., *(GXColor*)&lbl)` loads
  the global straight into the arg slot.
- **Vtable double-deref:** `*(int *)lbl + 0x34` (no `&`) for two `lwz`s through the variable.

## Drift handling (Ghidra `FUN_xxx` don't match v1.0)
Don't fix `FUN_xxx` — add the asm symbol as a NEW correctly-named/signed function (linker matches by
name; the FUN_ floats harmlessly). `tools/drift_audit.py <unit>` + `tools/realign_skeleton.py`. A
stuck 60-95% partial is OFTEN a CORRECTNESS bug (a return/store wrongly nested in an `if`, an over-
simplified switch arm, inverted branch sense) — diff target's control flow before assuming a cap.
A tiny "4b" header can mask a big recoverable drift-stub body — check `.s` body sizes, not report
sizes.

## Foreign-compiler objects (GCC/SN ProDG — out of MWCC scope)
Signature: `mflr` BEFORE `stwu`, `andi.` for contiguous masks, `mcrxr; addme.` loops, `stmw r14`
bulk saves, creation-order alloc. Confirmed: zlbDecompress (pi_dolphin), gap_03_80006C6C (render).
Don't spend MWCC effort — flag for the owner's foreign-toolchain build-rule path. Compiler-emitted
s64/fixed-point math (`__shl2i`/`__shr2u`, `addc`/`adde`, unrolled rounding loops) → apply #98/#109.

## Build hygiene (don't break shared `main`)
- `timeout 60 ninja; echo EXIT=$?` → confirm `EXIT=0` BEFORE every commit. In A/B batteries, gate
  every variant on compile exit (a failed compile leaves the previous .o and the diff lies).
- `'extraout_*'/'in_rN' not initialized` are WARNINGS (build still exits 0). The strict-hash/CI
  target ALWAYS "fails" until 100% matched — "build green" = `ninja` exits 0, NOT hash-match.
- Edit SJIS-bearing files BYTE-WISE (python rb/wb) — known carriers: src/track/intersect.c,
  baddie/Tumbleweed.c. Anchor pragma edits to the fn definition (blind first-occurrence replace
  corrupts pragma-dense files). Clean Ghidra phantoms (`extraout_*`, `in_rN`, stray `local_N`).
- One owner per `.c` (concurrent edits → duplicate defs). NEVER `git stash` in a worktree (shared
  store) — use `git checkout -- <file>`. A `shutdown_request` ack is NOT process death — verify
  the PID is gone after a swap.

## Flipping a unit NonMatching → MatchingFor
100% objdiff is NOT flip-sufficient. Verify: (1) symbol layout (`objdump -t` offsets = symbols.txt
deltas; source fn order = address order); (2) pool claim (`objdump -h`; claim the TU's retail pool
range in splits.txt, .o pool bytes = retail's); (3) post-flip DEFAULT-target build + dol byte-
compare + md5. A local @NNN conversion-bias .sdata2 with no retail TU pool = flip held (banks the
100% anyway). Status edits are the team-lead's.

## Tooling
- `function_objdump.py <unit> <symbol>` — FULL target asm. Run FIRST (before any diff).
- `ndiff.py <unit> <symbol> [--classify] [--fingerprint REGEX]` — normalized per-fn diff (recipes =
  HYPOTHESES, not verdicts; "#108 permutation" is its least-trustworthy output). `--diff` MASKS
  reorders/fusion — never certify % with it.
- `rotmap.py <unit> <symbol>` — register-rotation mapper + structural diffs hidden under a rotation
  (eyeball the raw stream; it mis-flags phantom regions on misalignment).
- `probe_battery.py extract/run` — the /tmp probe-batch workflow (hand-fix base.c to reproduce the
  in-tree divergence first; if base.c matches but in-tree diverges, it's fn-global/context-bound —
  A/B in-tree, stop probing).
- `cosmetic_audit.py [--min-pct N]` — screen 99%+ partials for REAL byte diffs (truncates to ~3
  diffs/fn — grep all lines). `categorize_near_misses.py` — bucket <100% fns by first-diff symptom.
- `callset_audit.py` / `unrolled_loop_audit.py` / `fcmpo_swap_audit.py` / `width_audit.py` /
  `pragma_audit.py` / `pragma_minimize.py` — class-specific sweeps. Run AFTER a full `ninja` (stale-
  .o caveat). `offset_deref_scan.py` / `include_audit.py` / `extern_audit.py` /
  `forward_decl_static_audit.py` — cleanup tools (byte-gated; re-audit before applying saved reports).
- **MP4 oracle:** `mp4_asm_search.py "<pattern>" [--with-c]` — MP4 is 100% matched; find the C that
  produces any asm shape. **In-repo oracle:** grep `build/GSAE01/obj/**/*.o` disasms for a shape,
  read the matched unit's C. **decomp.me corpus:** `discord_search.py <kw>` (lower score = closer to
  match). **Retail ISO forensics** (`orig/GSAE01/*.iso`): OBJECTS.bin/.tab + gResourceDescriptors
  (0x802C6300) map DLL ids → names/units; `dll_boundary_audit.py` / `dll_boundary_resplit.py` for TU
  boundaries.
- **Byte-exact cleanup verification:** baseline = `objdump -d -j .text` of every `.o` under
  `build/GSAE01/src` (NOT `build/GSAE01/obj` = the target tree); edit; rebuild; diff; commit on zero
  diffs. After a `git pull`, OTHER hunters' commits flag their .o — confirm any flagged .o is yours.

## Reference commits
peephole-off mass fix `b7eda753` · drift add-new-fn `aedc9605`/`77438a6f` · u8-vs-char `6863ffe7` ·
`& ~K` rlwinm `782a09a8` · `*(void**)` cmplwi `a42bb90b` · lift-for-CSE `75660758` · decl-swap stack
offset `91f5f4ab` · bitfield rlwimi `a3a86c446`/`34ee540c0` · case-reorder `61dd19936` · int-param
cmpwi `1ebdcf015` · `*(s8*)(p+off)` `b42e26e71`.
