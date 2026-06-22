# SFA-Decomp Matching Playbook (MWCC, GC/2.0 main lib · 1.2.5n audio/MSL)

Lean lever-index for matching MWCC-compiled C to the target binary. Each recipe is the
actionable trigger→fix; **full detail, examples, and worked analyses live in
`docs/matching_archive.md`** (recipe numbers match). Read that when a one-liner isn't enough.

## Prime directive: recover plausible C, never asm
- Goal = plausible original source. **Inline `asm { }` is forbidden — no exceptions** (even
  previously-sanctioned recipes are revoked; the owner reverts them). An 80-99% match from clean
  C beats a 100% asm match.
- A residual that's still in progress: **commit the partial, document the target-vs-yours asm
  shape, keep it on the active list.** Every fn is matchable — "not yet" just means the lever is
  still out there waiting. New C recipes land here as discovered; a documented partial is the seed
  for the next breakthrough.
- **FRESH-EYES PROTOCOL:** re-attack open residuals WITHOUT reading the prior notes — derive the
  lever from target asm as if the fn were new. Most "#108/#82 coloring caps" are MISLABELS; they
  keep falling to fresh eyes (struct fixes, dropped args, arg-eval order, widths). Assume a clean
  source form exists and go find it.
- **A "forms explored so far" list is an INVITATION, never a verdict.** When this playbook says a
  lever was tried, that almost always means ONE low-effort attempt in ONE surrounding shape — it has
  repeatedly turned out that the "explored" lever WAS the answer all along, once paired with the right
  neighbouring change, decl order, or reframe. So: never skip a function because the notes list prior
  attempts, and never read "didn't move it" as "can't work." Re-run any listed lever with fresh eyes,
  read the FULL asm at every step, and remember a regression in one direction is itself a clue you can
  fix from another. There is no such thing as an unmatchable function here — only a lever not yet found.
- **Adding a playbook entry?** Write it with ZERO pessimism. Document the target asm shape, the
  positive lever(s) to try, and "a clean source form exists — derive it fresh." NEVER write "banked",
  "exhausted", "not reachable", "capped", "as good as it gets", "do not re-try", or "impossible" — that
  phrasing has permanently blocked real solutions before. Frame every open residual as a live target.
- **"Emergent / pressure-gated / not isolable" is ALSO a cop-out — banned as an explanation.** When an
  allocation/coloring effect won't reproduce in a minimal TU, that does NOT mean it's some mystical
  pressure phenomenon we can't pin — it means the minimal TU is MISSING the specific structural
  ingredient that triggers it, and we haven't found which one YET. The fix is to ADD ingredients
  (competing webs, a call across a live range, a phi, a second use, a specific creation order) one at a
  time until the effect FIRES, then name the EXACT trigger. Write "trigger not yet pinned — here's the
  minimal repro so far and the next ingredient to add," never "it's emergent under pressure." Every
  MWCC behavior is deterministic; the allocator runs a concrete algorithm. If you don't know the rule,
  that's a thing to reverse-engineer, not a label to apply.
- **An "impossibility" scan over OUR objs is self-confirming — prove UNachievability only against RETAIL.**
  Scanning `build/GSAE01/src/**/*.o` (our compiled source) for a shape and finding zero hits proves
  "our current source doesn't produce it," NOT "it's impossible" — our source lacking the construct is
  the BUG, not evidence. To claim a shape is unachievable you'd have to find it absent from the RETAIL/
  matched objs — but if retail HAS it, it's achievable BY DEFINITION (retail used this exact compiler),
  so the only honest conclusion is "source form not found yet." (Cost a false "O2-impossibility" once:
  the src-obj scan folded because our source lacked retail's construct; retail's own O2 fn kept it.)

## Method (do this every time)
- **Read the WHOLE target fn before diffing.** Diffs show WHERE, not WHY, and bias you to a false
  "#108 coloring" verdict. Dump full asm (`function_objdump.py <unit> <symbol>`, no `--diff`),
  note each `bl`'s real callee arg shape + field widths/compares, THEN diff.
- **Source of truth for % = `report.json` `fuzzy_match_percent`.** Force-rebuild the unit's src .o
  first (`rm` it + `ninja` it explicitly); `ninja report.json` alone can serve a stale .o.
  `--diff`/`ndiff`/`rotmap` LOCATE divergence, never certify (they mask reorders/fusion). `rotmap`
  also invents phantom "structural" regions on misalignment — eyeball the raw stream.
  GREP GOTCHA (cost a false master-key "recipe" once): when checking which register holds a value,
  ANCHOR the grep to the actual instruction + offset (`stw rX,8(r27)`), NOT a bare `stw r0`/`li r0` —
  a bare `stw r0` MATCHES the prologue mflr stack-save `stw r0,36(r1)` and a bare `li r0` matches any
  scratch, producing false "folds to volatile" reads. Always dump the FULL fn and read the actual
  store/use line, never conclude a reg-allocation fact from a loose grep.
- **Pragma wrappers reproduce per-fn optimizer STATE**, not original source. Byte-verify
  (`md5sum` the .o) any pragma change. `reset` POPS a stack (restores surrounding state, not
  default) — model nested regions as a stack and emit each fn's *effective* state.
- **A config that DROPS the headline % but introduces a needed STRUCTURAL feature (extra saved
  reg, surviving `mr`/`fmr` copy, an un-coalesced web) is GOOD NEWS — it proves the feature is
  REACHABLE. Do a FULL per-region diff before moving on; never judge on the number alone.** Worked
  example: fn_801B3DE4 (dimexplosion) — `#pragma optimization_level 1` revealed the target's 6th
  saved reg + the `mr r29,r31` base copy that O4 value-numbering folds away, at the cost of +34
  O1-inherent instrs. For a long time that read as a config-inherent trade-down. **That read was
  WRONG twice over: the `mr` was reachable at O4 first from a SOURCE lever (#131), and then — the
  real win — from ordinary typed array indexing (#135: `flames[idx].field`), which produces the
  whole allocation for free as clean 2002 C. The fn is 100% with no tricks.** Lesson: a pragma that
  surfaces a needed structural feature is a green light — it tells you a clean source form exists,
  so keep hunting the form that produces it WITHOUT the pragma's collateral cost. "Config-inherent
  residual" is a hypothesis to disprove, not a verdict. Contrast: O1/O2 creation-order alloc (#108)
  and O1≈O4 small-loop fns (#110) ARE genuine climbs — measure, don't assume.
- **Isolation-reproducible CORE vs context-bound COMPANION (triage tool, from a lead-reproduced 13-batch
  re-validation pass).** A lever that reproduces in a minimal /tmp TU is dependable — apply it on faith (the
  CORE: #3/#4/#7/#12-core/#18/#23/#25/#44/#51/#58-core/#74-core/#91/#95/#108-decl-order/#110/#113/#126/#131/
  #136/#137-caller/#143/#155/#156, plus most numbered one-liners). A finer "companion/discriminator" sub-claim
  marked "probe-confirmed" from ONE in-tree fn often carries a SURROUNDING-CONTEXT ingredient the bare lever
  doesn't reproduce standalone — verified for #37-cast, #112 three-way grouping, #114 per-use re-exec, #58
  vs-int-operand, #12 multi-bit discriminator, #15 deref-vs-index. This is NOT a downgrade: the in-tree fn DID
  work, so the triggering ingredient EXISTS — the minimal TU just lacks it. For these, A/B IN-TREE per-site
  (not blind), and when isolation doesn't reproduce, ADD ingredients until the effect fires and NAME the
  trigger — never read "didn't reproduce isolated" as "broken." Each carries its own stated boundary in-entry.

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
   (u-suffix) forces `cmplwi` on u8/bit-extract compares. `(u32)x != 0` / `x != 0u` is a WORKING way
   to get `cmplwi` (probe-confirmed it reliably emits `cmplwi`; earlier "INERT/folds back to signed"
   note was wrong). cmpwi/cmplwi only appear when the compare feeds a BRANCH; a returned/materialized
   bool uses the neg/cntlzw form (#23/#38). If a CSE-merge with a nearby signed int read still wins
   signed at a SITE, a struct-field pointer retype is the per-site lever.
4. **`if (v > K) v = K; return v;`** → target's `blelr` clamp. (For an int RETURN-clamp the inverse
   `if (v <= K) return v; return K;` emits the SAME `blelr` — probe-confirmed; either spelling works.)
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
    SOURCE-TYPE discriminator (probe-confirmed byte-exact, fn_80138908): assigning a bitfield from an
    INT source emits `clrlwi rV,rV,24` (narrow the int to the u8 container) THEN `lbz; rlwimi; stb` —
    both the clrlwi-narrow AND the rlwimi-insert. A `u8`-typed source DROPS the clrlwi (just
    `lbz; rlwimi; stb`). So when the target shows `clrlwi; lbz; rlwimi; stb`, write
    `struct { ...; u8 field:1; }` with an INT-typed source value (`s->field = intExpr;`); count the
    leading `:1` fields to land the rlwimi bit. A manual `|= mask` gives no rlwimi; a u8 source gives no clrlwi.
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
22. **Wrap body in `if (cond) { ... } return 0;`** vs `if (!cond) return 0; <body>` SELECTS BLOCK
    LAYOUT — which return is fall-through vs out-of-line, plus the branch sense (ble↔bgt). Probe-confirmed
    it is NOT an instruction-count win: both forms emit exactly one `li r3,0`, one branch, one body — no
    extra island in the simple single-path case. Pick the form whose block order matches the target.
    (A genuine 2-island case may need a `return 0` shared by multiple paths — that shape is still to be
    pinned; if you hit it, grab the real-fn structure.)
23. **`!x` for the `==0` non-zero materialization** (single `cntlzw; srwi ,5`); plain `!=0` AND `!!x`
    BOTH give `neg; or; srwi` (probe-confirmed `!!x` is identical to `!=0`, NOT a distinct double-
    `cntlzw` — if a target shows `cntlzw;cntlzw`, its source C is still to find, `!!x` isn't it).
    `break` (fall to common return) instead of case-body `return 0` drops a spurious cntlzw. `li 1;
    cntlzw; rlwnm ,31,31` = MWCC's `x <= 0` (signed) materialization.
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
    COMPANION (probe-confirmed, fn_80136E00): for a read-modify-write assembling into a NARROW GLOBAL,
    `g = (u16)g | bits;` (EXPLICIT cast on the read-back) forces the store-forward mask `clrlwi r,r0,16`
    to SURVIVE; plain `g |= bits;` / `g = g | bits;` / `bits | g` DROP it (at O3/O4 MWCC value-tracks the
    just-stored value, proves it fits, and skips the redundant mask). So when the target keeps a
    store-forward `clrlwi` on a re-read global, write the explicit `(u16)g` on the read-back. (`volatile`
    gives a real `lhz` reload instead — wrong direction.) CONTEXT-BOUND (lead+validator: the cast-vs-plain
    DIFFERENCE did NOT reproduce standalone — in a minimal TU `g=(u16)g|bits` and `g|=bits` are byte-identical,
    no clrlwi from the cast alone): the clrlwi survival is driven by fn_80136E00's exact STORE-FORWARD situation
    (a live prior store whose value MWCC must mask), not by the cast in isolation. The in-tree fn worked, so the
    triggering shape exists — A/B the `(u16)g` read-back IN-TREE per-site; don't expect the bare cast to force
    the clrlwi where there's no store-forward to preserve.
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
    layout shifts). Suspect a 60-95% partial of an offset bug before anything else — it's the
    usual culprit and a quick, satisfying win.
47. **sda21 direction:** sized-array extern for a small `.sdata` symbol → `@sda21`; for >8B objects
    use scalar `extern T sym;` + `(&sym)[i]`. Force the far form with incomplete `extern u8 lbl[];`.
48. *(IN PROGRESS)* WCTileIface vtbl dispatch-hoist — `lwz r12; mtctr; bctrl` hoists to statement
    front; the clean-C form is still out there. Commit the partial and come back fresh — these keep
    falling once the right shape clicks.
49. **Switch with case-FALLTHROUGH** (`case 0: case 1: case 2: { body; break; }`) for sequential
    shared-body dispatch.
50. **Nested `outer(inner(x), y)`** keeps r3 live across calls (vs a spilled local).
51. **Chained `x = y = z = K;`** controls STORE ORDER (it stores z,y,x = reverse) — that, not the CSE,
    is the lever (probe-confirmed: separate stores `a=K;b=K;c=K;` ALSO CSE to one constant load; the
    chain's real effect is the reversed store sequence). Write the chain to get the reverse order.
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
    `cmpwi`). Keep the local for CSE; just type it right. BOUNDARY (lead-reproduced GC/2.0 -O4,p, compare must
    feed a BRANCH per #3): the width lever bites against a CONSTANT (u16→`cmplwi`, long→`cmpwi`) and
    field-vs-field / field-vs-u16-value (u16→`cmplw`, long→`cmpw`) — but is INERT against a RUNTIME INT OPERAND
    (an `int` param or `int` local: u16 and long BOTH give `cmpw`, the int operand fixes the opcode). So only
    reach for the local-retype when the other operand is a constant or another narrow-unsigned value; against an
    int operand it does nothing. Struct-FIELD width is the same lever —
    A/B project-wide before flipping a shared typedef; launder minority sites with a cast pointer.
59. **Lift the term you want computed FIRST to its own statement, to control commutative-FP
    reassociation.** MWCC's DEFAULT for `t0 + t1 (+ t2...)` computes the LAST source term first
    (probe-confirmed: `a[0]*n[0] + a[1]*n[1]` → `fmuls a1,n1; fmadds a0,n0` — a[1]*n[1] first). So
    lifting the last term (`f32 yy=a[1]*n[1]; dot=yy+a[0]*n[0]`) is a NO-OP — it matches the default.
    To force a DIFFERENT term first, lift THAT term: `f32 xx=a[0]*n[0]; dot=xx+a[1]*n[1]` makes
    a[0]*n[0] compute first (probe-confirmed). Pick the lifted term to match the target's first fmuls.
    `scheduling off` does NOT fix reassociation.
60. **At 99.9% with `--diff` showing "identical," byte-compare before assuming a pool artifact** —
    most hide a real constant/operand/loop-bound bug. Use `cosmetic_audit.py`. Single-instr real-
    bug signatures: missing vtable deref (`lwz r12` vs `addi r12`), wrongly-guarded store
    (branch-displacement off by one store).
61. **Distinct pointer locals (not `p += K`)** to keep target's `addi rX,rX,K` base-bump. Companion:
    REASSIGN THE PARAM (not a new local) so the variable relocates to the copy reg.
61b. **Late-used scratch local declared FIRST** re-ranks param/early-local saved coloring up.
    Full-reverse-split (decl order reversed + inits separated) is the strongest battery member;
    third-web edition: move an UNRELATED short local's decl to flip a stubborn pair (it will flip).
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
    ~0x80LL` → `li -129; and`; `x |= 0x100100LL` → `lis;addi;or`). The SIGNED-vs-UNSIGNED lvalue choice is
    PEEPHOLE-STATE-DEPENDENT (lead-reproduced both modes, GC/2.0): under peephole-ON (`-O4,p` — expgfx, main
    lib, all the O4 DLL/main units) signed `s32` and unsigned `u32` `~KLL` are BYTE-IDENTICAL (`li -K; and; stw`,
    no srawi — MWCC DCEs the dead high word), so the lvalue sign is CODEGEN-NEUTRAL there; under
    `-opt nopeephole,noschedule` (the flameguard/tricky/render/audio noopt units — where #150 lives) a SIGNED
    lvalue adds a dead high-word `srawi rX,31` while the unsigned high word is constant 0 and DCE's. So: in an
    O4,p unit pick either; in a NOPEEPHOLE unit the choice is real — use UNSIGNED (u8/u16/u32, clean `li -K; and`)
    UNLESS #150's adjacent-`=0` steal makes the signed `~(u64)` form the net win (read #150). Convert ALL adjacent masks at once (partial conversion misaligns the burst).
    Bulk-sweep a recurring materialized flag word after mapping every site to its fn's fuzzy%.
    CAVEAT (WorkerB, trickySelectQueuedCommandTarget + trickyGuardFindBaddieTarget): the LL fix is
    CORRECT (target uses `li -1025; and`; codebase already uses `&= ~(u64)FLAG` elsewhere) BUT when an
    adjacent `field = 0` store immediately follows the `flags &= ~Kll`, the materialized mask's extra
    register (the `lwz`'d flags + the `li -K`) shifts allocation: the flags `lwz` moves off r3, freeing
    r3, and MWCC hoists the `0` into r3 EARLY (reuse for the store) instead of `li r0,0` LATE — a net
    regression (97.91→97.20, 95.44→94.74). The mask is reachable; the open part is forcing the flags
    `lwz` to claim the low volatile (r3, as retail does) so the 0 can't reuse it. Verify no adjacent
    const-store register-steal before committing #74; if present, the load-reg lever is still to find.
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
    before fcmpo → this; consumes the arithmetic result → temp_t form. Cleanest on STORE-clamps with
    a same-register swap; for named-embed/no-store/computed-limit/whole-register-shift variants reach
    for a different lever (those are their own puzzles, each with a tell). Tool: `fcmpo_swap_audit.py`.
82. **FP volatile reg-permutation DECOMPOSES — classify by web kind:** symbol-CSE web → #81
    launder; two named f32 locals → decl-order swap; expression-temp pairs (conversion biases,
    fctiwz, stack reads) = the most interesting sub-class (class-move via embedded-def or ternary-
    join; block→fn-scope promotion of the OTHER arm locals). Probe first — many reproduce standalone.
    Census the shape across `build/GSAE01/obj`; a singleton almost always has a sibling that reveals
    the lever, so keep looking before treating it as a one-off.
83. **Conversion-temp pool flushes at a STATEMENT JOIN with a live-var redef or memory store** (not
    a ternary assign). "fresh-ascending slots between if-clamps" → the clamps were ternary
    ASSIGNMENTS; or the two-op wrap-clamp `d = (d - 0x10000) + 1;` keeps bump mode. Co-located wins
    matter more than the frame: (a) fresh-reload launder `*(int*)((u8*)p+K)` (local/param bases
    only; global bases VN through); (b) f32-temp split for eval order; (c) direct `*(s16*)p =
    (fexpr)` (no `(int)` cast) drops the extsh.
84. **What looks like a "const-hoist-above-addr-arg" snag is usually just #29** — the callee's REAL arg order puts the
    obj/pointer FIRST. Cross-caller arbitrate (majority decl wins); cast at the CALL SITE only,
    never flip the definition. Expression-operand hoist → embedded `x / (sc = lbl)`; call-arg hoist
    is open. ⚠️ Embedded-assign in a call arg whose value is REUSED by later args MISCOMPILES — and it's a
    REAL silent miscompile, not just a mismatch (probe-confirmed: `f4((t=lbl),0.0f,t,t*2.0f)` → arg3 f3 is
    NEVER materialized (garbage reg), arg4 = `2.0*garbage`; the propagation to later args is dropped). TELL:
    MWCC emits `variable 't' is not initialized before being used` on that call — that warning IS the
    miscompile fingerprint (build still exits 0, so it's silent). If you see it after an embedded-assign-in-arg,
    the output is wrong C — back it out. (The #128 safe case differs: the assigned value is reused by a later
    identical CALL, not a later ARG of the same call.)
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
    doesn't). f32→int direction: the per-statement re-execution of `fctiwz` comes from the VOLATILE/RE-READ
    SOURCE, NOT the `(f64)` cast (lead+validator reproduced, GC/2.0 -O4,p: `(int)(double)vf` and `(int)vf` on a
    `volatile float` BOTH emit 2 `fctiwz`; a NON-volatile `(int)(double)gv` used twice CSEs to ONE `fctiwz` — the
    f64 cast is neither necessary nor sufficient). So to get per-site re-conversion, make the SOURCE genuinely
    re-read (volatile field / distinct memory loads), not the cast. `(int)(f32)(f64)x` does a real `frsp`
    (separate fact, unrelated to VN).
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
    **FP `d = a - b` then RANGE-CHECK (`if (d > hi || d < lo)`) with INLINE-deref operands (`d =
    obj->fieldA - obj->fieldB`): un-name `d` — inline the subtraction at EACH compare.** The named
    `d` colors HIGH (f3, operands grab f1/f2); inlined, MWCC CSEs to ONE fsubs but `d` becomes an
    expression temp that colors f1 while the operands take f2/f3 — exactly the target's FP regs, 0
    instr change. (fn_8010AEA8 99.41→100, CameraModeViewfinder_init 99.87→100 — both `objState->
    rotXStart - rotXEnd` style diffs.) DISCRIMINATOR: works when the OPERANDS are inline field
    reads; if the operands are themselves NAMED locals (`d = start - end` with `start`/`end` copied
    first), the named `d` form is ALREADY correct — un-naming REGRESSES it (firstPersonEnter stayed
    100 named, broke un-named). So: inline-operand subtraction → un-name the result; named-operand
    subtraction → leave the result named.
108. **Saved-reg assignment is CLASS-POOLED, not weight-ranked.** Single-def copies → top
    (last-created → r31); multi-def/phi → descend in creation order; params → bottom; all-const
    flags → very bottom. Use-count/first-use/loop-depth are INERT within a class.
    WITHIN-CLASS ORDER RULE (probe-pinned — "decl-order inert" is only HALF true): definition order DOES
    set the within-class home for REORDERABLE defs. Field-reads / up-front loads at the function top color
    FIRST-declared → HIGHEST reg (DESCENDING: `int x=s->a,y=s->b,z=s->c` → x=r31,y=r30,z=r29; reverse the
    decl order to swap the homes — verified). Call-results / spread defs color in creation-order, but the
    DIRECTION is CONSUMER-DEPENDENT (lead+validator reproduced, GC/2.0 -O4,p — do NOT blindly assume last→r31):
    three call results live across a barrier, consumed by STORES/general-use → ASCENDING (first-created→r29,
    last-created→r31); consumed as ARGS to a LATER CALL → DESCENDING (first-created→r31, last→r29 — the
    allocator biases toward the arg-reg assignment a→r3,b→r4,c→r5). So READ the target asm for the actual
    direction before predicting a reg; the call-arg-consumed case is common and flips the prediction. Either
    way they're PINNED by the call structure (you can't reorder the calls, so decl-order IS inert
    THERE — that's the only place it's inert; use #130/#107 web-decouple). #5 holds exactly: DECL sets the
    home, INIT order sets only the load EMISSION order. So for a within-class swap of TOP-LOADED/reorderable
    values, REORDER THE DECLS first (cheap, real lever); reach for #130/#107 only for call-result/computed webs.
    UNIFORM ACROSS GPR AND FP saved pools (verified): the same decl-order-descending rule governs the FP
    saved regs — #45 ("first = f31") IS this rule. So an FP-pair swap (#82/#121) of decl-reorderable named
    f32 locals held across a loop flips by DECL ORDER too; only computed/CSE'd/hoisted-conversion FP webs are
    spread-pinned (then use the FP coalesce/launder levers #81/#82). Treat GPR-pair and FP-pair residuals with
    ONE rule: reorder decls for reorderable webs, break the coalesce for spread/call-pinned webs.
    CLASS-MOVERS
    (the lever): first-def-split (a branch-consumed call result → its own var), last-def merge,
    `#pragma optimization_level 2` (creation-order alloc), block-scope per-arm re-decls, same-
    variable recycle (#119), and #131 (no-op `|=` to force a surviving same-value copy + own web —
    the source for an "un-coalesced web" the allocator otherwise folds). WITHIN-class order is the
    smallest residual (rotmap first; the transposition penalty drowns real structural fixes — fix
    those first). The old "no source levers left, set it aside" reflex has been WRONG every time it
    came up (#130, #131, #135): treat a residual as not-yet-found, and keep going — there's a lever.
    Cross-class interleave is perturbed fn-globally by a
    magic-const division / conversions (dose effect).
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
112. **K-grouping — the BASE-GROUPED `add base,idx; lbz K(rT)` form is ROBUST; the idx-first/lbzx VARIANTS are
    NOT reliably source-selectable standalone (caution, lead+validator reproduced GC/2.0 -O4,p).** Getting the
    base-grouped displacement load (`p = base + K; *(p + idx)` → `add base,idx; lbz K(rT)` — the DIMSnowHorn1
    win below) is EASY: in isolation single-use, ALL three spellings (`p=base+K;p[idx]`, `base[idx+K]`,
    `base+idx+K`) produce the IDENTICAL `add base,idx; lbz K(r)` — so any of them lands that form. The claimed
    DISTINCT variants — `base+(idx+K)` → idx-first, flat `base+idx+K` → `addi idx,K; lbzx` (fold-onto-index) —
    did NOT reproduce in isolation; the lbzx/index-fold direction needs an in-tree ingredient (a reused index
    web / reduction / pressure) not yet isolated, so **A/B per-site in-tree for the lbzx direction; don't assume
    the source grouping flips the isel by itself**. Named `p` needs MULTI-use to keep its base-bump (single-use re-folds); for symbol-array bases skip
    the alias and use the direct form `tbl[i*4+K]`. Wide deref re-folds to lwzx — `(u8*)` launder the grouped base.
    **Field-load `(T*)(base+idx)->field` (field at const K) → `add base,idx; lbz K` via grouping the
    FIELD CONSTANT onto base: `u8 *p = base + K; flags = p[idx];`** — single-use `p` is fine here (the
    constant grouping pins it; only `p = base+idx` single-use re-folds to lbzx). Both `(T*)(base+idx)
    ->field` and `p=base+idx; p[K]` re-fold to lbzx. (DIMSnowHorn1_update 99.5→99.84.)
113. **The SPECULATIVE unroller (`srwi ,1; mtctr; ... andi. ,1`) is gated at O3+ — to SUPPRESS it use
    `#pragma optimization_level ≤2`** (probe-confirmed: a byte-sum loop unrolls at O3/O4 = ~16 lbz,
    NOT at O2 = 1 lbz). The `#pragma ppc_unroll_speculative on|off` / `ppc_unroll_factor_limit N` /
    `ppc_unroll_instructions_limit N` / `opt_unroll_count N` pragmas are RECOGNIZED (no illegal-pragma
    warning) but do NOT turn the speculative unroll OFF — `ppc_unroll_speculative off` leaves the loop
    unrolled by 8 (probe-confirmed inert for suppression; it only perturbs the unroller's STRATEGY in
    some real fns, see the regress below). Use them to TUNE the factor when it IS unrolling; reach for
    opt_level≤2 to turn it off. `reset` is a SYNTAX ERROR for these — restore with explicit values.
    Factor mismatch needs factor_limit + instructions_limit TOGETHER.
    LIMIT (expgfx, model modelWalkAnimFn): the unroller's MAIN/REMAINDER SPLIT STRATEGY is NOT pragma-exposed.
    When BOTH builds unroll at the SAME factor (e.g. 8) but retail uses the GUARD-form split (`addi r9,r5,-8;
    cmpwi r5,8; ble remainder` — branch around the dead main loop when n≤8) and ours uses the CTR-form
    (`srwi n,3; mtctr` — main runs 0× for small n), NO #113 pragma flips it: opt_unroll_loops off / opt_unroll_count
    8|2|1 = INERT (ppc speculative unroller is what's active, opt_unroll doesn't touch it); ppc_unroll_speculative
    off REGRESSES; factor/instr A/B (8,256)/(8,512) = pragma-optimal, others worse. The guard-vs-ctr CHOICE is an
    unroller-internal heuristic. UNTRIED (the only remaining angle): a SOURCE pre-check restructure that biases
    the unroller to guard-form (e.g. an explicit `if (n <= 8) {remainder-only} else {main+remainder}` / an
    n-8-based bound) — assumed-reachable, not yet found.
114. **No-op CONVERSION NODES block ALGEBRAIC RE-FACTORING (the confirmed lever) — they do NOT split VN /
    force re-execution of duplicate sub-expressions (mis-attribution corrected, lead+validator reproduced
    GC/2.0 -O4,p).** WHAT IT DOES: a `(int)(long)`/`(int)(f64)` node BLOCKS distribution/re-association ACROSS
    it — `e*48 + c*48` re-factors to `(e+c)*48` (ONE mulli), but `e*48 + (int)(long)(c*48)` keeps TWO mulli.
    Use it to stop MWCC re-associating/distributing a sum or product the target keeps separate. WHAT IT DOES
    NOT DO: it does NOT split VN to re-execute duplicate identical sub-expressions — `(int)((long)x*8)` used
    twice still CSEs to ONE `slwi`; `(int)(double)gv` (non-volatile) twice still CSEs to ONE `fctiwz`. So it is
    NOT a "re-execute a conversion per use" lever — for that you need a genuinely RE-READ source (volatile
    field / distinct memory loads), NOT the cast (see #97). Runtime values only (constants fold).
115. **Callee-decl PARAM WIDTHS shift the caller's WEB CREATION ORDER at zero cost** (a narrowing
    cast into a matching-width param is absorbed; into an int param it makes a persistent node).
    The first source-side lever on the #108 within-class scramble. Needs call-arg conversion sites;
    for call-free fns pick another lever (#108 has plenty). Diagnose by extracting to a /tmp TU.
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
126. **Param pool classing — RULE PINNED (probe-confirmed): all incoming params occupy ONE pool ordered
    by ARGUMENT REGISTER (r3 → lowest saved reg, ascending; the last arg → highest saved reg); param
    TYPE is IRRELEVANT.** `mixed(int a, void *p, int b, void *q)` all live across a call → a=r28, p=r29,
    b=r30, q=r31 (the pointer p sits BELOW the int b). The copy-pool ABOVE the param pool (#108) is for
    SINGLE-DEF COPIES only — so retyping a param is class-NEUTRAL. When a param appears to "reclass," it
    is NOT the declared type; it is one of two real causes:
    (a) the param's VALUE flows into a surviving COPY, so it rides the copy class (#147 integer
    class-pull / #131) — defeat or force that copy;
    (b) within-class ORDER — retail orders the param pool relative to the local/copy pools differently
    than ours (the #108 within-class-order rule; the exact creation-order trigger is being pinned).
    Read target's prologue to RECOVER the original param type (per-fn cast noise on an int obj is then
    faithful). `#pragma optimization_level 2` can land the typed-pointer form even in call-bearing fns.
    The animobjd2 fn_8013E0D0 residual is case (b) — re-derive the clean source form fresh from the asm.
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
129. **Frame/conversion-temp inflation is often a DOWNSTREAM symptom of EXIT-BLOCK fragmentation —
    fix the return-path layout first.** Two trailing `if(c)return K;` guards before `return D;`
    emit as two separate `li r3,K` islands AND can block the conversion-temp pool from recycling
    earlier scratch slots (bigger frame). Merge to one fall-through tail: `if (guardA) { if
    (!guardB) return D; } return K;` (hoist the shared `return K` to the single tail, nest the
    distinct `return D`). Collapsed both the duplicate return island AND the frame 112→96 in one
    edit. Pair with #33 (keep the constant return in the else arm: `if(x<K){<body>}else{return E;}`
    floats the cold island out of line) and #107 for-GPR (un-name a loop-invariant member —
    `obj->field` inline at each use CSEs to one load but colors LOWER than a named local, fixing a
    volatile r4/r5/r6 carrier rotation). (DIMSnowHorn1_stateHandler0A 95.6→100.)
130. **WEB-DECOUPLING carries "#108 byte-identical-except-one-register" matches the last step to 100%.** When a value
    assigned from a NAMED local/temp lands in the wrong saved/volatile reg, RE-DERIVE it from a
    fresh MEMORY DEREF instead of the temp: `match = other;` (loop temp) → `match = (int*)*list;`
    (fresh deref of the walked pointer). This decouples the value's live-range/web from the temp,
    changes the interference graph, and flips the allocator's reg choice with ZERO other instruction
    change — reuses a different just-freed reg. CONVERSE (un-name a temp by inlining its defining
    EXPRESSION at each use, #107) also flips it. Works for re-derivable values (memory derefs,
    `obj->field`); a CALL RESULT can ALSO be web-decoupled WITHOUT re-calling — SPLIT it into a
    block-scope temp at the call site (`{u16 b = call(); var = b;}` instead of `var = (u16)call();`):
    the temp gives the call result its own short web + a `mr`-free copy into `var`, which re-classes
    `var` and flips a stubborn within-class saved-reg pair. (timeListFn_8012be84 99.74→100: a clean
    r30↔r31 swap between a global-load local and a `(u16)`-masked call result; the temp-split on the
    call result flipped both, decl-order/opt_level2/#131-|=/fresh-deref all inert first.) #131/#135
    also cover call-result-adjacent cases. VN-equal pointer copies yield here too — #131's no-op `|=` or,
    cleaner, #135's typed array index forces a surviving copy + own web. Also #115-adjacent: renaming
    ONE loop's counter to a distinct var removes a cross-loop coalescing barrier. Brute-force MANY
    spellings and grep the affected reg each build — this won dim2roofrub_update (byte-identical-
    except-r29/r31, which five prior agents thought was as good as it gets → 100%) and the
    int-permutation half of dimwooddoor (pitchSign from fresh modelVec[1] read). The old "#108
    within-class scramble has no source lever" worry keeps proving FALSE — for deref-sourced values,
    for VN-equal pointer copies (#131), and most decisively for the whole pattern once you index the
    struct as an array (#135). **There's nearly always a clean source lever; assume one exists and
    hunt the asm — you'll find it.**
131. **The front-end SAME-VALUE MERGE is breakable: a no-op bitwise op forces a surviving `mr`
    copy + a SEPARATE web (a clean-C source for "two overlapping same-value saved regs joined by a
    copy" — and #135 later found an even cleaner one).**
    ✓TRIGGER PINNED (probe-confirmed, reproduced standalone): the OR fires iff ALL THREE hold —
    (1) two pointer locals of the SAME value, (2) BOTH used (both webs live, e.g. across a call),
    (3) the OR applied to one. Baseline without the OR: two same-value pointers COALESCE to one
    base+displacement (`stw K(r31)` for both). Add `p2 = (int*)((u32)p2 | (u32)p1)` → the `|` gives p2
    a distinct value-number, blocking the coalesce → TWO webs: `addi` (real pointer) + `mr` (surviving
    copy), stores split across the two regs. Two DISTINCT merge phenomena both use the OR: (i) POINTER
    coalesce (this — same-address pointers fold to base+disp); (ii) INTEGER class-pull (#147 — a
    `prev=curveId` copy pulls curveId into the COPY class, rotating the pool; the OR keeps it in the
    PARAM class). Same tool, different mechanism.
    Two identical `state+off` (one base for
    most fields, a second for ONE field) get value-numbered into ONE web by the FRONT-END *before
    any optimizer pass* — proven by ret-patching IroCSE/IroPropagate/IroRangeProp/AddProp/VN, all
    survive; every `opt_*`/pragma/opt-level/compiler-version (1.0–3.0a5) folds it; a plain second
    pointer, `e14=e` copy, cast, phi-with-overhead, or opaque call-result all fold or add cost.
    DEFEAT IT: `e14 = state + off; e14 |= e;` (e == state+off) → emits `or r29,r31,r31` (== `mr
    r29,r31`) AND keeps e14 a distinct web, because the `|` node blocks the merge — value still
    state+off, ZERO extra instructions, no branch. Then (a) pin the reg with #108 DECL-ORDER
    (declare e14 FIRST → r29); (b) align the copy's POSITION by computing the field value to a temp
    first (`int life = (int)(K*sqrtf(spd)); e14 = state+off; e14 |= e; *(int*)(e14+0x14)=life;`) so
    the def/`mr` sits AFTER the intervening call, matching target. `&=`/`|=` both work (no-op when
    the operand equals the lvalue). Companion (#112 corollary, same fn): the per-call slot re-derive
    + add operand order — grouping the field K onto the BASE (`(char*)((char*)state + K) + idx*0x30`)
    re-derives `state+off` per call AND emits `add r28,r30` (state,off order); grouping K onto the
    INDEX (`state + (idx*0x30 + K)`) re-derives but FLIPS to `add r30,r28` (off,state) — the last
    3-byte gap. METHOD: this fell ONLY after switching from fail-fast-on-fuzzy% to a structural-
    distance metric (count real instr/reg diffs vs target asm, ignore @NNN-reloc names + subi/addi
    display) — a 96% variant was structurally CLOSER than the 98% baseline; the % hid the path.
    Read the emitted asm per variant. (fn_801B3DE4/dimexplosion: wrestled with across ~15 sessions
    → matched 100%, and then matched AGAIN even more cleanly with plain typed C, #135.)
132. **A CONDITIONAL POINTER REASSIGNMENT (phi/multi-def) is a SECOND, non-bitwise way to force the
    surviving 2nd same-value saved reg + `mr` (the same pattern #130/#131 handle).** Reassign the pointer
    in branches that already exist — e.g. the clamp arms: `if (v<0){v=0; p2=state+off;} else if
    (v>0x3c){v=0x3c; p2=state+off;}` with `p2` first-defined as a COPY of the field pointer. The
    multi-def web can't coalesce with the single-def field pointer → emits the extra saved reg + the
    `mr`. Reproduces the EXACT instruction MULTISET (proven on fn_801B3DE4: 181/181 identical). The
    web-SEPARATION needs a KIND MISMATCH across the defs: copy first-def + recompute arms (or vice
    versa) stays separate; all-copy or all-recompute (same value) COALESCES back (#108 same-class).
    SCOPE: a phi SPLITS the value at the merge — pre-merge uses bind def0's register, post-merge
    uses bind the phi register. So when the target uses ONE 2nd reg for ALL of a field's accesses
    (a "single lazy copy", e.g. unclamped-store + reload + clamp-store + later reads all via r29),
    reach for the form that gives ONE non-coalesced web used by every access — cleanest is #135's
    typed array index (plain C, 0 diff), or #131's OR. The phi shines when the 2nd reg is used in a
    post-branch region only. Census the field's accesses vs the branch and pick the matching lever.
133. **COPY-vs-COMPUTATION placement controls WHERE a same-value `mr`/`add` lands.** A plain pointer
    COPY (`p2 = p`) is COALESCER-placed → EAGER (emitted right after the source operand's def, e.g.
    at `add r31` slot-creation, 0x40) regardless of its source-line position. A COMPUTATION
    (recompute `state+off`, or #131's OR) is SCHEDULER-placed → LAZY (at its source line, after the
    intervening call). To LAZY-place a phi-entry copy (#132) without #131's OR, embed a RECOMPUTE in
    the consuming store (#116): `*(int*)((char*)(p2 = state + off) + 0x14) = v;` source-places the
    assignment, dragging the phi-entry `mr` to the right slot — but the recompute's own value (the
    CSE'd field reg) then feeds the pre-merge accesses (the #132 split). Embedding a COPY instead
    (`(p2 = p)`) still HOISTS (copies don't respect the embed). The recompute folds to a `mr` (CSE to
    the field reg) or a fresh `add` (no CSE, own reg) depending on whether the field value is already
    live — `(int)(long)x` / char* launders to break CSE didn't apply in THIS embed spot (re-CSE'd or
    rejected by GC/2.0); save them for #134's standalone-split spot, where the cast shines.
    Diagnostic: build each variant, grep the `mr`/`add` ADDRESS + which reg the field's stores use;
    a structural-distance (instr-multiset + per-access reg) read beats fuzzy% (a 99.94% E2 and a
    98.9% E1 were both 1-displacement off — same multiset, different `mr` slot). (fn_801B3DE4: phi
    E1 98.9% mr@0x40; phi+embed E2 99.94% mr@0x80 w/ 2-instr base-reg split; OR 100%.)
134. **#131's OR no-op is NOT the only 100% — a NO-OP WIDTH CAST splits the VN and is PLAUSIBLE C.**
    `slotLife = state + (int)(long)off;` gives the 2nd same-value pointer a DISTINCT value-number
    (#114-consistent, lead+validator verified: the cast makes the two address EXPRESSIONS syntactically
    DIFFERENT so they don't CSE/coalesce — NOT a VN re-execution of identical sub-exprs) → MWCC keeps it as a non-coalesced LAZY copy (the target's
    `mr r29,r31`), a single web used by EVERY access of that field — exactly what #131/#132 needed,
    with NO bitwise op. KEY: cast a SUB-OPERAND of the address sum (`state + (int)(long)off`), NOT
    the pointer variable (`(int)(long)slot` FOLDS — cast-of-copy is simplified; this is why #133's
    embed-launder failed, it cast the wrong node). The cast splits at zero cost AND yields a copy
    (value still CSEs to the field reg → `mr`, not a fresh `add`). CAVEAT: the cast ELEVATES its
    operand — `off` jumps to r31, swapping slot↔off (~99.4%, slot=r30, off=r31; lifetime already
    correct at r29). FIX with a #108 creation-order lever: re-derive `slot = state + off;` right
    after, so slot is the LATEST-created value and reclaims r31. Net two lines —
    `slotLife = state + (int)(long)off; slot = state + off;` — = 100%, byte-identical (0 instr diff),
    reads as a width cast + a pointer re-derive. METHOD: the cast gives the right MECHANISM on the
    first build (read savegpr_26 + the `mr`); the residual is then a PURE within-class register swap
    — grep the per-value reg each build and move it with decl-order/re-derive (#108), not more
    splitters. (fn_801B3DE4/dimexplosion: retired the `|= slot` no-op across ~16 sessions of "OR is
    the only way" → plausible-C 100%. The "OR is mathematically unique" proof was WRONG: it only
    covers NODE-level splits; an OPERAND-level conversion-node split is a second family — but it
    permutes the saved regs, so always pair it with a creation-order fix.)
135. **The "2nd saved reg for one field" puzzle (#131/#132/#134) is usually NOT a trick — it is
    what TYPED PER-STATEMENT ARRAY INDEXING produces for free.** DISCRIMINATOR (pausemenu): #135 fits
    ARRAY-OF-STRUCTS (`arr[idx].field`, ONE base) — do NOT apply it to STRUCT-OF-ARRAYS (parallel member
    arrays at fixed offsets, e.g. `obj+0x448`, `obj+0x948`, `obj+0x9c8` each a separate `T arr[N]`). On SoA,
    the typed `arr[i].field` form COLLAPSES the layout the target wants (regressed gameui textureFreeFn
    93→74.65). SoA CLEAN FORM DISCOVERED (pausemenu, textureFreeFn): retail uses ONE base (`r28 = lbl`) for
    ALL parallel arrays via DISPLACEMENT stores — the puzzle was MISFRAMED as "two-base" (ours has two bases =
    a BUG; retail has one). Root of ours' two bases: the source MIXES a LOCAL `u8* base = lbl` (for one array)
    with the GLOBAL `lbl` DIRECTLY (for the others) → MWCC materializes the global TWICE (local copy + global
    ref don't CSE). FIX: use the GLOBAL DIRECTLY everywhere (DROP the local `base` pointer), single-expression
    per access: `void** tex=(void**)(lbl + j*4 + 2504); *(s16*)(lbl + 2376 + j*2) = -1; lbl[1096+j] = 1;`. KEY
    MWCC RULE: a GLOBAL-symbol address ref → DISPLACEMENT `sth K`/`stb K` (one base, matches retail); a LOCAL
    pointer var → INDEXED `sthx` (wrong). So for a GLOBAL-based SoA loop the #135 local/typed-pointer instinct
    is BACKWARDS — use the bare global. RESIDUAL (open #108/#136, lands 90.92 < the 93.0 two-base baseline — so
    structurally-correct, coloring-bound — the dimexplosion good-news pattern: the one-base structure IS
    reachable, finish via coloring): (1) #136(b) counter-0-reuse — retail `mr r29,r27` (NULL-store 0 = copy of
    counter i's initial 0) vs ours `li r29,0` (not triggered by hoisted-null / `void* zero=NULL`); (2) #108
    j↔tex within-class swap — retail colors `tex` (live-across-call) HIGHER than the masked index `j`, ours
    colors j higher (single-def→higher). When retail holds a struct base in
    TWO saved regs (one for the setup stores, one for a field read back across calls), the PLAUSIBLE
    source is `T *arr = (T*)base; arr[idx].field = ...` with the index RE-SPELLED every statement —
    NOT a cached `T *p = &arr[idx]`. MWCC then (a) CSEs the consecutive setup stores onto one saved
    reg, (b) RE-DERIVES `base + idx*size` across each intervening call (the #112 "add state,off" the
    raw drafts forged by hand), and (c) keeps a cross-call-read field (e.g. a clamped lifetime reused
    in a later decay expr) in its OWN saved reg — emitting the `mr` with ZERO source tricks. This
    RETIRED the OR (#131)/phi (#132)/conv-cast (#134) on fn_801B3DE4: the body is clean
    `flames[idx].posX = x; ... flames[idx].lifetime = ...` typed C, 0 instr diff. Co-levers: (a)
    struct field WIDTHS must match the access — import said `u16 spinSpeed` but retail uses
    `extsh`/`lha` ⇒ it's `s16` (the sibling render already cast `*(s16*)&...->spinSpeed`, the tell);
    (b) clamp a RELOADED local (`int v = arr[idx].life; clamp v; arr[idx].life = v;`) NOT the field
    in place (in-place re-reads/re-stores add an instr); (c) per-fn `scheduling/peephole/
    opt_propagation off` still load-bearing (optimizer-state, not source). METHOD/LESSON: the TU
    header note CLAIMED "typed pointers re-colour, keep raw `int` strides" — that was a LOCAL MINIMUM
    that MASKED the natural typed form matching outright. **Distrust "keep it raw / keep these
    shapes" notes; A/B the typed struct-array form FIRST, before any coloring trick.** (~17 sessions
    of escalating OR/cast hacks dissolved into ordinary 2002 C once the struct was indexed as an
    array. A blind multiset-diff + per-fix re-test converged it in ~6 builds: spinSpeed s16 → 99.1,
    clamp-to-local → 100.)
136. **Strength-reduced loop COUNTER/WALKER coloring is a SOURCE lever — two clean forms, pick by
    base kind.** When the target puts the loop COUNTER in the higher saved reg and the WALKER in the
    lower but MWCC's index form `arr[i]` does the opposite, there's a clean C form that matches:
    ✓DIRECTION RULE PINNED (probe-confirmed, LOCAL/param base): the counter↔walker relative home is set
    by the SOURCE FORM, and the INCREMENT ORDER (`e++,i++` vs `i++,e++`) is INERT — only body-vs-comma
    flips the pair. BODY-computed `for(i=0;i<N;i++){ T *e=&base[i]; ...use i... }` → WALKER higher,
    counter lower (`e=r31, i=r30`). COMMA-init `for(i=0, e=base; i<N; e++, i++){...}` → COUNTER higher,
    walker lower (`i=r31, e=r29`). (Re-verified in isolation: the ABSOLUTE reg numbers are CONTEXT-DEPENDENT
    — set by whatever else is live, e.g. the bound `n` can claim r29 and push the walker to r30; match the
    RELATIVE counter↔walker order, never a literal reg number.) So: want counter-higher → comma-init; want
    walker-higher → body-computed.
    (decl-order is correctly inert here — induction webs, not top-loaded #108; the FORM is the induction-class
    analog of #108's decl-order.) SCOPE (probe-verified robust): the rule holds for a counter + one OR
    MORE walkers, LOCAL or GLOBAL base — body-form always lands the counter LOWEST with the walkers
    ascending above it. OPEN MULTI-STRIDE REDUCER-DIRECTION case (func05, asm-pinned by waterfx — this is
    NOT call-arg-eval-order/#137; the call args are ALREADY matched in both builds): with 3+ competing
    strides (e=i*28, vtx=i*64, vtxDesc=i*32, the latter two consumed as drawFn CALL ARGS), RETAIL's reducer
    orders the strides ASCENDING BY STRIDE VALUE (28→r27, 32→r28, 64→r29) while OURS orders them by
    CREATION order → the i*28↔i*64 registers SWAP. decl-order / comma-init / #136(a)/(b) all INERT (it's
    the reducer's stride-register assignment, not source decl order). ✓SOLVED IN-TREE (validator derive +
    waterfx, ripple loop 95.98→96.01, strides EXACTLY match retail 64→r29/32→r28/28→r27): RELOCATE the stride
    exprs BEFORE the gate in DESCENDING value order (64 first → highest); the reducer assigns first-created→
    highest. ★ FORM MATTERS for a GLOBAL base (the key refinement): use **OFFSET-INT locals** — `int o64 =
    i*0x40; int o32 = i*0x20;` before the gate (descending value), then `(char*)glob + o64` in the call. The
    offsets become the induction vars (base re-derived per use, NO hoisted base reg) AND control creation order.
    DON'T use the alternatives: a named-POINTER local (`char* vx = glob + i*0x40`) LOSES strength-reduction
    (CSE-confuses with the 28-stride → no `addi 64`, 95.98→89.24); a typed-INDEX (`T* vx = &arr[i*4]`) fixes the
    coloring but makes vx a walked pointer → hoists the base into 2 extra saved regs (frame +16, 95.98→92.6).
    The offset-int form is the GLOBAL-base analog of the validator's local-base relocate-lever. The RIPPLE loop
    win (96.01) is confirmed in-tree. ✓WAKE LANDED (96.05) — and it adds a key rule: the GATE CONDITION-COUNT
    flips the induction ordering DIRECTION. RIPPLE (1-condition gate `e->active`, target 64→r29) → first-created
    →HIGHEST: offset-ints BEFORE the gate, LARGEST-first (o64 first → 64→r29). WAKE (2-condition gate
    `g->active && g->f18==0`, target 32→r29/64→r28/28→r27) → first-created→LOWEST: declare the gate-ptr `g`
    FIRST, THEN the offset-ints (o64,o32) before the `if` → g→r27 (lowest), o64→r28, o32→r29 (highest). Both
    verified in-tree on func05's two loops. So #136 per-loop offset-int ordering is GATE-DEPENDENT: 1-cond →
    offsets-before-gate largest-first; 2-cond → gate-ptr-first then offsets. (READ LESSON: the wake target read
    went original-32→r29 [right] → a "retraction" to 64→r29 [WRONG — grabbed the ripple block @e4c] → resolved
    in-tree by reading the ACTUAL wake block @1054. In a multi-loop fn, confirm the CORRECT loop's addi block;
    the in-tree gate is the final authority even over a "retraction.") The
    counter is already lowest in both — it's purely the stride-register ordering among the walkers.
    GLOBAL-base caveat: comma-init on a GLOBAL base adds the #155 `lis;addi
    r0;mr` detour (the explicit `e=glob` routes through r0), so it's NOT clean there — on a global base use
    body-form for walker-high, and #136(b) counter-0-reuse / #143 typed-index for counter-high.
    (a) LOCAL/register base → comma-init walker `for (i = 0, p = base; i < N; p += stride, i++)`,
    increment order `p += stride, i++` (walker bump FIRST) to match the target's `addi walker; addi
    counter; cmpwi`. (b) GLOBAL base → keep the index form and give the COUNTER an incidental REUSE,
    because the reducer's counter/walker coloring is keyed on whether the counter's value is reused:
    a `*p = NULL` whose 0 materializes as `mr rNull,rCounter` reuses i, raising i's web priority so
    the reducer colors counter=higher (no comma-init, no extra copy) — read the target asm for the
    reuse it already has and spell it.
    ✓VALUE-0 COPY-AFFINITY MECHANISM PINNED (3 oracles + A/B + groundanimator_free in-tree close — was
    nearly mis-filed as a "compiler gap," it is NOT): the `mr rNull,rCounter` (reuse the counter's live 0
    for a stored 0 instead of a fresh `li`) is a copy-COALESCE decision with TWO source paths —
    (1) the stored-0 web is COUNTER-LIKE (itself incremented + compared, a real 2nd counter) → coalesces
    at O4, no pragma (O4 oracles PlayControl/fn_801343CC); (2) a PURE stored-0 needs the value CHAINED to
    the counter in the for-init (`for (val = counter = 0; ...)`, #43/#51) AND the fn at `#pragma
    optimization_level 2` (at O4 copy-prop FOLDS the chain back to `li`; O2 oracle tumbleweed line 153).
    The OR (#131) is INERT here — const-0 folds. DISCRIMINATOR: a fn matching retail EXCEPT the 1 mr is
    O4-shaped → use path (1) [opt_level 2 would break the rest]; a broadly-coloring-mismatched fn is likely
    a genuine O2 fn → path (2), verify the FULL fn match (opt_level 2 shifts ALL regs, #95). KEY
    DISCRIMINATOR (waterfx oracle hunt) for path (1): the stored-0 web qualifies at O4 ONLY if it's a true
    COUNTER = incremented AND COMPARED to a bound; an ACCUMULATOR (incremented but NOT compared, e.g.
    `off += 4`) does NOT qualify. OPEN VARIANTS (live targets — oracle-or-DERIVE the source, never file as
    gaps): (c) reuse an incr-NOT-compared ACCUMULATOR's 0 in an O4 fn — SPLITS into two halves:
    ✓SOLVED — the LOCAL-COPY half: `local = accum;` (PLAIN store of the accumulator VARIABLE, not literal
    `0` and not the `local = accum = 0` chain — the var-read doesn't const-fold) → `mr` at O4, in-tree-proven
    (fn_801932C8 `htOff = fallOff`). FIELD-STORE half — ✓TRIGGER PINNED (validator add-ingredients ladder,
    disproves "folds even at O4"): the fold trigger is DEEP-NEST + INNER-LOOP COMPLEXITY pressure (NEITHER alone
    folds), NOT the pre-loop position. Ladder (~12 probes, exact-reg): single / single+htOff+OR / single+FP /
    double-nested-outer-top / TRIPLE-nested-SIMPLE-inner → all REUSE `stb r31` ✓ (match retail); but TRIPLE-nest
    + (FP physics call OR a conditional) IN THE INNER loop → FOLD `stb r0` ✗. So a complex inner loop displaces
    fallOff's early materialization → it's not in r31 at the pre-loop field store. Corrected framing: "folds
    under deep-nest + inner-complexity PRESSURE; reuses otherwise." Retail KEEPS it under this exact pressure
    (`stb r23` in the triple-nested-FP fn_801932C8), so the forcing form EXISTS. OPEN (sharp 1-instr edge):
    force the nested accumulator to materialize EARLY despite the pressure. Tried+fold: ref-fallOff-first,
    `entryCount=fallOff`, volatile early use. Best via fresh incremental attack or an in-tree oracle (a matched
    triple-nested-FP fn keeping an accumulator-0 in a saved reg across a field store). (Unifies w/ #126 + Minimap
    as the O2 saved-anchor family.) (d) LOW-PRESSURE single counter-0-reuse — a tiny fn (~47 instrs) where the
    chained copy folds to `li` at O4 yet retail (STRUCTURALLY IDENTICAL, same instr count) has the `mr`
    (Minimap_release): NOT a pressure cap (identical structure = identical pressure), it's an unfound
    O4-surviving-copy source form. The chain reaches counter+LOCAL value-0; (c)/(d) need forms still to find.
    ★UNIFICATION (validator): the whole value-0 family is really TWO cases. COUNTER-TIED (the stored-0 rides
    an incremented counter/accumulator) = SOLVED (paths 1/2 + the (c) COPY half). STANDALONE-CONST-KEPT (a
    const-0 NOT tied to any live counter, that retail keeps in a SAVED reg and reuses, vs ours re-materializing
    `li r0`) = the ONE remaining open nut — and it UNIFIES (c)-field-store (`entryCount=0`), (d) Minimap
    (`null=NULL`), AND #126 (`pass=0` kept in r29). All three are "make MWCC keep a standalone const-0 in a
    saved-reg web instead of re-materializing `li` per use." Crack that one and all three close.
    ✓MECHANISM PINNED (probe-confirmed, validator + lead): the IN-LOOP standalone-const-keep is an
    OPT-LEVEL decision — O4 (graph-coloring) KEEPS a standalone const-0 stored across an in-loop call in a
    SAVED reg (`li r31,0` in the preheader, reused via `stw r31` each iter); O2 (creation-order) RE-MATERIALIZES
    `li r0` per iter BY DEFAULT. ⚠️ The "named var vs literal `0`" idea is
    a RED HERRING — at O4, `arr[i]=0`/`g=0`/`vec[2]=0;vec[0]=0` (literal) and the same via a named `int z=0;` are
    BYTE-IDENTICAL (both keep in saved r31; verified on global-scalar AND two-store shapes). So the O4-keep is
    O4-vs-O2 ALONE, not the spelling — use it ONLY for fns whose rest holds at O4.
    ⚠️ "O2 ALWAYS re-materializes a const-0" is OVERSTATED (disproven by retail): retail's debugPrintDraw is O2
    AND keeps pass=0 in saved r29. The earlier "O2-impossibility" whole-DLL scan hit SRC objs (which fold because
    OUR source lacks retail's construct) — NOT the retail objs. So a const-0 CAN be kept in a saved reg AT O2;
    retail does it; the O2-keep SOURCE FORM is a LIVE target (not a cap).
    #126 debugPrintDraw (PRECISELY CHARACTERIZED — both dbgtricky + validator read the RETAIL obj): dropping its
    `#pragma optimization_level 2` REGRESSES 93.29→88.07 (fn is genuinely O2-bound); the multi-def hypothesis is
    DISPROVEN (`pass++`/`pass=pass+1` const-prop to the same `li`; a `for(pass=0;pass<2;pass++)` 2-pass loop adds
    pass-conditional branches retail lacks → 79.40). RETAIL's actual shape: r29 is a MULTI-VALUE saved reg reused
    in creation-order across TWO SEPARATE sequential loops — `li r29,0`(pass=0, loop1) → `addi r29,r3,10`(an x1
    address in the rect block) → `li r29,1`(pass=1, loop2). So pass=0 isn't a multi-def web; it's a SEPARATE
    const-0 that lands in saved r29 because r29 is ALREADY-ANCHORED as a saved web by the competing x1 address,
    and at O2 pass=0 is created AFTER the ctx-copy (→ higher reg). OURS folds pass=0 (`li r0` ×8 in loop1) because
    the ctx-copy grabs r29 first and NOTHING anchors a saved reg at pass's position. ⚠️ The "add an anchoring
    ingredient" hypothesis does NOT reproduce (validator probed 4 forms at O2 — multi-def 0→1, simultaneously-live
    competing address, SEQUENTIAL reg-reuse mirroring retail's r29 exactly, high pressure — ALL fold to volatile
    `stw r0`). ★ THE REAL DIVERGENCE IS STRUCTURAL (validator, reading retail): retail has **2** pass-stores
    (c60, c70); OUR build emits **8** `stw r0` pass-stores. So our decomp's debugPrintDraw is structurally
    divergent — extra `gPass=pass`/`=0` stores or an unrolled/duplicated loop / different control structure —
    and the fold likely FOLLOWS from that, not from a missing anchor. LEAD (dbgtricky, structural): find WHY our
    build emits 8 pass-stores vs retail's 2, match retail's 2-store loop structure (the keep may follow). The
    2-store minimal still folds in pure isolation (necessary-not-sufficient), but the 8-vs-2 is the real source
    divergence to fix first. (dbgtricky owns the in-tree case + the retail-read.) (The chained+opt_level lever is the COUNTER-TIED
    sibling — opposite opt-level: counter-tied wants O2-chain, standalone O4-keep.) REMAINING EDGES (live targets):
    the PRE-LOOP field store (entryCount=0 folds even at O4 — pre-loop position doesn't get the saved web) and
    Minimap's counter-copy `mr` at an O4-shaped size — both precisely bounded, not caps.
    ✓REPRODUCING BED for the VALUE-1 REUSE (Validator, /tmp/vCP/p.c, curves_getPos pinpointed to ONE instr,
    152=152): source `count=0; mask=1; for(k<4){ if(...&mask...) cand[count++]=n; mask<<=1; }` FULLY UNROLLS at
    O4; on iter-0 `count++`→1 while mask is still 1 (1<<0), so retail REUSES the live mask reg (`mr r5,r4`) for
    count's new value, where ours materializes fresh (`li r5,1`). The bed reproduces ours (`li r7,1` with mask=1
    live in r6) — the reuse-able value is RIGHT THERE, MWCC just picks fresh. This is the value-1 analog of the
    value-0 reuse above (same "copy-coalesce vs fresh-materialize" decision, FORCE direction). Forms tried:
    opt_level 2 REMOVES the unroll (real loop, count via addi) — WRONG (target is unrolled O4), so the reuse must
    be forced AT O4 keeping the unroll. ✓ORACLE CONTRAST (Validator, both-objs in dll_0014): RETAIL DOES BOTH —
    `mr`-reuse in RomCurve_countRandomPoints (172 instr, higher pressure), `li`-fresh in getControlPointId_2A (87
    instr, lower pressure, OURS MATCHES). So the reuse is a REGISTER-PRESSURE-CONTEXT decision, NOT a source-
    spelling choice (~10 1-line levers all inert). This is NOT a "pressure-gated, can't crack" cop-out — it's a
    DETERMINISTIC pressure rule to reverse-engineer: the NEXT INGREDIENT is to ADD register pressure to /tmp/vCP
    (extra live values across the reuse point) ONE AT A TIME until `li`→`mr` flips, NAME the threshold (it's
    between 87 and 172 instrs of pressure), then find the source construct that pushes curves_getPos's allocation
    over it. The bed is ready; the threshold-and-nudge is the open work (a live target, lower-priority = 0.4%/fn).
    UNIFIED with the #147 copy-PULL bed (/tmp/v147/faithful.c) — same coalesce mechanism, #147 PREVENTS / value-1
    FORCES; both are pressure-gated, both have the same reverse-engineer-the-threshold path.
    (The comma-init form on a global base adds an `mr walker,r0`
    from the explicit `p = base` init, so form (b) is the matching one there.) Both are ordinary
    2002 C; choose the one whose emitted asm lands the counter high. (WorkerB:
    dll_4e/optionsMenu_applyGameplaySetting is form (b); shop_init wants form (b) too.)
    SCOPE of form (b) counter-0-reuse (pausemenu, in-repo-oracle verified): the `mr rNull,rCounter` reuse
    fires on a bare `arr[i] = NULL` DIRECT SUBSCRIPT of a STANDALONE global array (confirmed: dll_4e's
    `lbl_803A87D0[i]=NULL` → `li r29,0; mr r30,r29; stw`). It does NOT transfer to an OFFSET MEMBER ARRAY
    (SoA, e.g. `((void**)(lbl+0x9c8))[j]=NULL`) — the offset breaks the clean subscript, loses the held
    element ptr, and the reuse doesn't fire (regressed gameui textureFreeFn to 81.33). All other null
    spellings (hoisted-null, `void* zero=NULL`, comma-init, single-expr) also fail to trigger it; the counter
    MUST stay u8 (int-counter kills the clrlwi bound). The offset-member-array SoA counter-0-reuse is a
    DISTINCT OPEN sub-puzzle (the #135-SoA residual: bare-global-direct + tex-first decl lands 91.61, one base
    + displacement + counter=r27 correct, held under baseline only by this unreused null + a j/tex color —
    structure reachable, this last piece unsolved).
    OPEN SUB-CASE — INDUCTION-VAR SURVIVAL on a LOCAL base, no-reuse, short loop (flameguard, sh_staff_free
    dll_01B1 T=46 C=44): retail KEEPS the idx counter + walker (`li r5,0; addi r5,r5,4` alongside the walker
    bump), ours `opt_strength_reduction` ELIMINATES idx as redundant (walker-only) → the 2 missing instrs read
    like dropped code but are induction-var elimination, NOT #79/#139. Tried+REGRESSED: opt_strength_reduction
    off (92.48, over-applies), comma-init walker BOTH increment orders (92.61, idx still eliminated), off+comma-init
    (92.61). The LOCAL-base / no-reuse / short-count idx-survival form (the counter has no value-reuse to keep it
    alive, unlike form-(b)'s `*p=NULL` reuse) is UNMAPPED — assumed-reachable, open. (DLL "ours-short" candidates
    in the mixed-drift bucket are mostly THIS, not dropped code — count before assuming #79/#139.)
    SIBLING FORM: a DO-WHILE loop with MANUAL counter/pointer bumps in the body → rewrite as a
    `for` with comma-init increments (`for (i=0, p=base; cond; p+=stride, i++)`); the for+comma-init
    induction shape fixes the induction-variable coloring the hand-bumped do-while misses. (WorkerC:
    dll_0035 SaveSelectScreen_render 98.59→99.00.)
137. **Reorder a function's PARAM LIST to match the target's fmr/mr emission order — register-
    neutral, so always safe to try.** The ABI assigns each arg to its register by TYPE (f32→f1..,
    int/ptr→r3..) independent of DECLARED order, so reordering the parameter list (and its shared-
    header prototype) does NOT change which register any arg lands in — it only changes the ORDER
    the prologue saves them and the caller emits them. Use that to land two related residuals:
    (a) caller `fmr-before-addi` / mixed fmr+mr arg-emission order — declare the f32/ptr params in
    the order the target emits them (complements #29 caller-side; generalizes #87 beyond just
    f32-last); (b) the callee PROLOGUE param-save order — e.g. target saves light(r6) AFTER
    intensity(f31) → declare `(.., f32 intensity, void **light)`. Fully free when every call site is
    a cast (objdiff content-matches regardless of the proto); with real prototyped callers, reorder
    the shared prototype too and confirm codegen-neutral across them (it will be — same registers).
    Independently found on gameplay (WorkerA: dll_0282_barrelgener Obj_UpdateLightningCluster,
    dll_80220608_shared.h) AND math (fastCastFloatToS16 `(float x, s16 *p)`) — a broad, reliable lever.
    METHOD (recovering the natural order): when a fn's DEFINITION has its float params shoved to the
    END (`(obj,idx,kind,mode,chance,origin,flags, f32 f8val, f32 mult)`) — a recurring Ghidra
    floats-last import artifact — the CALLERS' own per-file `extern` decls usually preserve the
    ORIGINAL order (`(obj,idx,f32 f8val,kind,mode,chance,f32 mult,origin,flags)`); grep the call
    sites, take the majority caller spelling, reorder the definition + shared header to match.
    Register-neutral (within-type order unchanged) ⇒ callers compile byte-identical; full-rebuild +
    report-diff to confirm 0 regressions across all ~60 header includers. (WorkerC: objfx
    spawnDirectionalBurst/spawnBoxBurst→100, spawnArcedBurst 98.4→99.2; fx_800944A0_shared.h.)
    COROLLARY (address-of a param spills at its HOME slot): a local `T x = param; ... &x` (Ghidra's
    by-address-arg idiom) emits the spill store AFTER the prologue param-saves; writing `&param`
    DIRECTLY spills the param at its declaration-order home slot, interleaving the store between the
    adjacent param-saves (matches target) AND drops the redundant local. (WorkerC: objfx
    objParticleFn_80099d84 99.28→100 via `&extraScale`.)
    COROLLARY (WRONG-EXTERN-SIGNATURE — a CALLER-side structural bug worth ~4%, NOT coloring): a unit's
    local `extern` of a SHARED HELPER often has the float arg shoved LAST (the Ghidra floats-last import
    artifact) while the REAL definition has it 2nd/3rd. The wrong float POSITION corrupts THIS caller's
    arg-emission order (it sets up the wrong registers for the call) → a big structural loss, not a coloring
    nit. FIX: check each suspect extern against the REAL definition (grep the defining .c) and reorder the
    extern + the call args to match. HEURISTIC: when a tricky/shared-helper extern is float-last, distrust
    it — verify vs the def. (flameguard: mmp_cratercritter trickyFn_8013d8f0 — `trickyFn_8013b368(u8*,u8*,f32)`
    and `objAnimFn_8013a3f0(u8*,int,int,f32)` were both float-last; real defs are `(u8* obj, f32 vel, u8* state)`
    and `(int obj, int p2, f32 f, int p4)` → fixing externs + call arg order 92.48→96.56, +4.08.) SWEEP: grep
    other units' externs of the same shared helpers; an empty K&R proto `extern int fn();` on a float-taking
    helper is also suspect (the float's reg assignment is then unprototyped — give it the real signature).
    SWEEP REALITY (pausemenu, verified-by-score): grepping all dll externs of float-taking helpers flags
    **~85 with inconsistent float-arg positions, but those are MOSTLY FALSE POSITIVES** — the
    "real-def-obj-first vs extern-float-first" heuristic ALONE is insufficient: ~4 in 5 are EMISSION-NEUTRAL
    (target already emits float-after-obj) or REGRESS, and the "real def" itself is unreliable (drift / FUN_
    renames / multiple defs — e.g. fn_8010AC48 reorder REGRESSED 99.75→98.85). DEEPER: even a CORRECT
    ptr-first real-def does NOT predict the target's emission order — hudDrawTriangle is genuinely
    `(u8* color, f32...)` in vecmath.c yet the target emits the ptr LAST (reorder regressed 95.42→94.45). So
    real-def order is NOT a reliable signal at all; ONLY rebuild+measure is. MANDATORY RULE: apply
    PER-CANDIDATE, REBUILD + MEASURE report.json, KEEP only if the fn's % RISES, else REVERT. Do NOT blind-fix
    from the grep. The one productive SUB-PATTERN found: real-def obj-FIRST + the call passes obj as the LAST
    arg + a float-FIRST extern (narrow — only `objMove` hit: `int objMove(u8* obj,f32,f32,f32)` object.c, fixed
    in dll_00FF_magicdust 97.03→97.39 + dll_01AA_bombplantspore 98.05→98.58). Use the CALLER's existing obj
    type in the reordered extern (a `void*`/`int` obj mismatch breaks the build; register-neutral either way).
138. **Global-base WALKED array with a `mr rWalker,r0` detour → index it as a TYPED STRUCT ARRAY.**
    When a loop walks a global array and the base routes through r0 (`lis r3; addi r0,r3,LO; mr
    rWalker,r0`) instead of the target's direct `addi rWalker,r3,LO`, the clean form is
    `Entry *p = (Entry *)glob; for (i = 0; p[i].key; i++) p[i].field = 0;` (#135 typed struct
    array) — ONE walker carrying field displacements AND a direct base addi, no r0 detour. The raw
    `u8 *p` pointer walk and the `i*stride` index form both take the detour / two-walker split; the
    typed struct array is the one that lands it. This is the clean source for the global-base
    sub-case of #136 (the "global-base counter/walker" residual that looked stuck dissolves into
    ordinary typed C). (WorkerB: dll_0000_gameui GameUI_unselectAllItems, expgfx family.)
139. **A FOLDED BRANCH is a recoverable dropped-code bug — count conversion ops to find it, split
    the merged if/else back into sibling else-ifs.** When a function is INSTRUCTION-SHORT vs target
    (current < target by a block), the import often merged what were SEPARATE branches into one:
    e.g. an `if/else` picking a ratio INSIDE one outer branch folds to a single `fctiwz`/conversion,
    where the original wrote TWO `else if` siblings (each with its own conversion). DIAGNOSE by
    counting conversion/`fctiwz`/select ops in target vs current — if the target has MORE, a branch
    was folded away. FIX: split the merged inner-if back into sibling `else if` branches (re-spell
    the guards as the dev did, e.g. `else if (PULSE && frame <= lifeFraction)` then `else if
    (PULSE)`), restoring the dropped block. Sibling of #79 (asm-decode dropped code); this is the
    control-flow-fold flavor. (WorkerB: dll_000A_expgfx drawGlow restored the dropped 6th fade
    branch, 88.4→91.8.)
140. **Fixed-offset far-global `lis;addi r0;mr rN` detour → the #80 launder, when the base is a
    SAVED reg.** A far global a fn uses (as a plain call-arg AND for fixed `base+K` offset loads)
    can materialize via a temp+copy (`lis;addi r0; mr r30,r0`) instead of the target's direct
    `lis;addi r30`. When the base lives in a SAVED reg (or the fn has body calls — `_savegpr_NN`
    present), launder BOTH the init AND every plain use identically as `(char *)(int)lbl_X` (#80):
    it collapses the detour to a direct `addi r30` AND relieves saved-reg pressure, cascading away
    the downstream allocation diffs (WorkerC: dbstealerworm_update 58→8 diff regions, 96.83→97.22).
    DISCRIMINATOR: the launder is the lever for SAVED-reg / call-bearing detours. For a VOLATILE-reg
    base in a call-FREE fn it instead trades the 1-instr detour for a volatile-reg permutation —
    that's a DIFFERENT shape with its own clean form still to find, so keep the launder off there
    and hunt the volatile lever separately (dll_94/97/99 trio is the volatile shape).
141. **2D-array stores emitting displacement `sth` where the target uses indexed `sthx` → NAMED
    row-pointer reassigned per store + `#pragma opt_propagation off`.** When the target indexes every
    store of a 2D array by column (`sthx`) but MWCC reassociates your address to `base+row+col+K` and
    emits displacement `sth`, defeat the reassociation with a NAMED row pointer recomputed per store,
    pinned by opt_propagation off:
      #pragma opt_propagation off
      fbrow = (u16*)((char*)base + (row + K)); *(u16*)((char*)fbrow + col) = v;
      #pragma opt_propagation reset
    The named var defeats the reassociation (a plain grouped-cast `(char*)((char*)base+(row+K))+col`
    AND a cached `p = &row[0]` both re-fold back to `base+row+col+K`); opt_propagation off keeps
    fbrow a real var so it isn't propagated/folded away → the stores flip to col-indexed `sthx`
    (#112/#128 applied to 2D arrays). DISCRIMINATOR: opt_common_subs off does NOT raise the sthx
    count here and collaterally un-CSEs other exprs (regresses); volatile and opt_loop_invariants
    off are inert. (WorkerC: fn_80137DF8 89.86→90.81; the per-store global-pointer RE-READ in the
    remaining tail is a separate shape still being mapped.)
142. **`#pragma opt_propagation off` keeps a separate-statement LOAD at its decl point — fixes a
    load-ORDER reorder (the third distinct use of this pragma).** When the target loads a value at
    its declaration (`s16 a = obj->rotX;` → `lha`) BEFORE an adjacent operand/const (`lfs` Pi), but
    MWCC PROPAGATES the variable into a later expression (the multiply) so its load emits AFTER the
    const, wrap the fn in `#pragma opt_propagation off` … `reset`: it keeps `a` a real variable
    loaded at its decl → exact target load order. `scheduling off` is INERT here — the reorder is
    propagation, not the scheduler. This joins the opt_propagation-off family: #128 (late saved-reg
    rematerialization of a stack addr), #141 (2D-array named row-pointer not folded back), and now
    eval/load-order. (WorkerC: CameraModeForceBehind_init 97.26→100.) Companion confirmation of #110:
    opt_level 1 REGRESSES loop/call-bearing fns (O1 creation-order overhead dwarfs the chained-copy
    fix) — it's only for small call-free fns; the int-const chained fold stays open for loop fns.
143. **Global-base WALKER detour in COUNT/bdnz search loops (`addi r0; mr rWalker` vs target's
    direct `addi rWalker`) → INDEX form + count-global used DIRECTLY in the loop condition.** The
    clean C is TWO parts: (a) write the search loop as INDEX form `glob[i]` (NOT a pointer-walk
    `p = glob; p++`) — MWCC strength-reduces `glob[i]` to the target's pointer walk but inits the
    base with a DIRECT `addi rWalker`; the pointer-walk SOURCE is what forces the `addi r0; mr`
    detour. (b) Use the COUNT global DIRECTLY in the loop condition (`while (i < nGlob && ...)`) — do
    NOT pre-cache it to a local before the loop: pre-caching emits the count load BEFORE the hoisted
    base; direct use hoists it AFTER the base, matching the target preheader (`li i; lis/addi base;
    lwz count`). The count/bdnz sibling of #138 (sentinel-index) and #136 (counter/walker) — solves
    the recurring count/bdnz global-base-walker detour that #138/#140 didn't fit (savegame
    restore/saveObjectPos, nw_mammoth, Objfsa_GetPatchGroupIdAtPoint all share the `mr rN,r0` shape).
    (WorkerB: dll_0014_unk/curves_remove 98.33→100.) SCOPE: this is the UP-COUNTING `i < count`
    search-loop form. The COUNTDOWN `bdnz` variant (e.g. Objfsa_GetPatchGroupIdAtPoint) is a DISTINCT
    sub-case where the index form adds a 2nd counter and comma-init keeps the `mr` — its clean form
    is still to find.
144. **Switch CASE-FUSION controls the binary-search PIVOT TREE — keep an identical-valued case
    UNFUSED from `default` to preserve it as a distinct dispatch node.** When the target
    binary-searches with pivots (e.g. cmpwi 12 & 14) but your build collapses to a single cmpwi (13),
    the source FUSED the cases with default: `default: case 0xb: case 0xc: → X;` makes MWCC treat
    0xb/0xc as redundant-with-default and REMOVE them, collapsing the search to the one distinct case.
    FIX: un-fuse the case with its OWN (even identical-valued) body — `case 0xc: → X;` SEPARATE from
    `case 0xb: default: → X;`. That forces 0xc to stay a distinct binary-search node (cmpwi 12), AND
    keeping 0xb on the default arm supplies the lower pivot boundary (the dead cmpwi 11 that shifts
    the pivot 13→12) → reproduces retail's exact dispatch tree. Distinct from #13 (reorder) and #122
    (dead empty case). USE THIS where the dispatch TREE is the actual diff. CAVEAT from the first
    application: on andross_update the un-fuse correctly matched the 12&14 pivots, BUT retail also
    CROSS-JUMPS the identical case-0xc/default outcome blocks (2 vs our 3 blocks) — a peephole artifact
    our build can't emit — so the net was a ~1-instr regression and it was REVERTED (compact fused
    form kept). So the lever is sound for pivot-tree matching; just confirm no confounding cross-jump
    of identical outcome blocks before committing (that's a separate open shape). (WorkerC: andross_update.)
145. **A SHARED `static inline`'s LOCAL DECL ORDER is a multi-function lever — reorder once, lift
    every caller.** When many fns inline the same helper (e.g. a binary search) and all show the SAME
    volatile/saved permutation in the inlined body, the fix is decl-order (#5/#108) on the INLINE's
    locals, applied ONCE. MWCC colors the four search locals descending by decl order; matching
    retail's `curve=r8,hi=r7,lo=r6,mid=r5` just needs decl order `curve,hi,lo,mid`. (WorkerB:
    dll_0014_unk Objfsa_FindRomCurveById reorder → RomCurve_func29 99.86→100 AND +7 sibling callers
    improved, zero regressions.) Always A/B the whole-unit per-fn delta after an inline edit.
146. **#137 cross-class param reorder is broadly reliable for the `fmr-before-mr` prologue —
    confirmed across units.** When retail saves an int/ptr param BEFORE the fmr float-param saves but
    your decl puts the floats first, move the int/ptr param(s) ahead of the floats. It's register-
    NEUTRAL (ABI assigns by type+within-class order, so cross-class moves don't change any reg) and
    only reorders the prologue save sequence. KEEP the int params' relative order (so r3/r4 stay).
    (WorkerB: RomCurve_getNearestAdjacentLink 98.35→100, `(curve,excludeLinkId,x,y,z)`; RomCurve_func1B
    96.57→98.14, `(curve,preferredNeighborId,x,y,z)`.) No call sites → free; with callers, reorder the
    shared proto+sites (codegen stays byte-identical). OPEN sub-case: when the ptr param is a WALKED
    base (`p += K` in the loop) the reorder fixes the early r4 save but retail still uses r3 DIRECTLY
    for the pre-loop field loads then saves r3 lazily — splitting into a separate walk pointer
    regressed (re-coalesced); the lazy-r3 lever for walked bases is still to find.
147. **Recover a MISSING entry-time copy by INITIALIZING an apparently-dead/UB-read variable.** A fn
    that's 1 instr SHORT vs retail (T=N, C=N-1) where retail has an `mr rX,rParam` right after the
    prologue is often a loop/condition variable the dev initialized but the import dropped (it reads
    UB-uninitialized in your C, so MWCC emits no init). Add the init (e.g. `previousCurveId = curveId;`
    before a do-while that compares `previousCurveId != curveId`): the copy reappears and the instr
    count matches. CAVEAT (open): the new live-at-entry var ROTATES the saved-reg pool. ROOT CAUSE
    pinned (curves_distFn15): baseline (no init) saves `mr r27,r3` (curveId, param1) BEFORE the
    `fmr` float saves = declaration order, the #137-correct prologue. The dead-init copy makes MWCC
    keep curveId in volatile r3 through entry (binary-search + the copy both read r3) and DEFER its
    GPR save past the floats AND past outDistance(r4) → outDistance grabs r27, curveId lands high.
    So the residual is precisely a #137 param-SAVE-ORDER disruption (target: curveId,floats,outDistance;
    mine-with-init: floats,outDistance,curveId). INERT here: decl-order, `(int)`/`(int)(long)` cast,
    opt_level 2/3, opt_propagation on/off, init placement (first/after-findbyid/before-do-while),
    embedded-assign-in-call-arg `FindById(prev=curveId)`. **SOLVED (DeepDive2): the init reclassifies
    curveId from the PARAM pool (r27, low) into the COPY pool (r31, high) via the FRONT-END SAME-VALUE
    MERGE — a plain `prev = curveId` coalesces curveId into prev's multi-def web, riding it to the top
    class and rotating every saved reg. DEFEAT IT WITH #131's NO-OP OR, GENERALIZED FROM POINTERS TO
    INTEGER COPIES: `previousCurveId = curveId; previousCurveId |= curveId;` AT THE TOP of the fn. The
    `|` node blocks the merge (curveId stays a param → eager `mr r27,r3` BEFORE the fmrs) AND, being a
    COMPUTATION (#133, scheduler-placed), emits the eager `mr r8,r27` copy at the top when its source
    line is first. ZERO extra instructions — the redundant `or` is peephole-eliminated, the web split
    persists. Final residual was then the segmentIntersect call's arg-emission order (target evals the
    f32 x,y,z BEFORE the ptr args): reorder the callee sig `(x,unusedY,z,a,b,unusedW)` per #137
    (register-neutral, single caller). 100%, segmentIntersect held 100%, no unit regressions.**
    KEY REUSABLE FINDING: when a RECOVERED entry copy of a param rotates the whole saved-reg pool, the
    cause is curveId being pulled into the copy-class; the `|=` keeps it in its original (param) class.
    (DeepDive2: dll_0014_unk curves_distFn15 96.32→100, commit ca937fc9f.)
    **⚠️ PLACEHOLDER, NOT RECOVERED SOURCE: the `|= a` no-op is a COMPILER HACK (no 2002 Rare dev wrote a
    random mid-fn self-OR) — bank the 100% but mark it a placeholder, exactly as #131's OR on fn_801B3DE4
    was later retired for plausible typed-array C (#135). The real no-`|=` form still exists; forms explored so
    far (re-derive each fresh — any may be the answer): decl-order, cast, opt-level, init-placement, if-else,
    opt_lifetimes. The clean form is still out there — OPEN, live target (task #5, DeepDive1).
    This applies to ANY no-op-bitwise/VN-hack 100%: land it, mark placeholder, circle back for real C.**
    **DeepDive1 REFINEMENT (task #5): the seed VALUE is the only irreducible diff, and it is provably
    behaviorally DEAD.** Seeding `previousCurveId = ROMCURVE_LINK_ID_NONE;` (a CONSTANT, not a curveId
    copy) keeps curveId in the param pool exactly like the `|=` (no copy → no same-value merge → no
    pool rotation) → 99.56%, T=C=148, a SINGLE diff region: target `mr r8,r27` (seed = copy of curveId)
    vs ours `li r8,-1` (seed = const). The ENTIRE register allocation otherwise matches (curveId→r27,
    previousCurveId→r8, loop `mr r8,r30` all identical). PROOF the seed is dead: previousCurveId is read
    only at the do-while tail `(previousCurveId != curveId) && (nextCurveId != NONE)`; on every path the
    seed is either overwritten (`previousCurveId = nextCurveId` when a link is found) or the 2nd term
    short-circuits (`nextCurveId == NONE`) — so seed ∈ {curveId, -1, anything} yields identical behavior.
    So the dev simply happened to write `previousCurveId = curveId`, and the exact `mr r8,r27` needs that
    curveId-valued COPY to materialize WITHOUT the copy-affinity cascade — which only a non-elidable op
    on curveId achieves: the `|=` (folds to mr, 100%) or a memory recompute `curve->id` (emits lwz +
    rotates volatiles, 98.27%). The forms tried SO FAR don't yet make the faithful `= curveId` copy emit
    `mr r8,r27` without the copy-affinity cascade — that's the within-class copy-affinity lever (★ classifier),
    OPEN and not yet found (this byte-identical-except-one-reg shape has always fallen to the right reframe,
    e.g. #130/#131 — assume a clean source form exists and keep hunting). DECISION (integrity owner): KEEP
    the `|=` committed at 100% as the working PLACEHOLDER; honest hack-free fallbacks are documented —
    `= NONE` (99.56%, behaviorally identical, 1 provably-dead seed instr) and `= curveId` (96.5%, the true
    source MWCC currently mis-renders). The genuine no-hack 100% awaits the copy-affinity reframe (task #5,
    still open).
    ✓IN-TREE CONFIRMED + MISSING ISOLATION INGREDIENT NAMED (HunterB, decisive A/B on dll_0014_unk): plain
    `=curveId` = 96.544% in-tree, T=C=136, the ONLY diff is `mr r27,r3` (target, curveId→r27) vs `mr r27,r4`
    (ours) WITH a full saved-reg pool rotation (r27→r31/r28→r27/r29→r28/r30→r29/r31→r30). So the copy-affinity
    pool rotation #147's mechanism describes is REAL IN-TREE (the `|=` STAYS load-bearing — do NOT retire it), and
    the segmentIntersect-residual hypothesis is DISPROVEN in-tree (those args are NOT in the diff). ★ THE MISSING
    ISOLATION INGREDIENT (why batch-#1's minimal TU couldn't reproduce the rotation): the do-while's ~7 COMPETING
    SAVED-REG WEBS (curve/nextCurve/hitCount/…) — they're what make the curveId-pull rotate the WHOLE pool; a
    minimal TU with fewer webs doesn't rotate. So to reproduce the rotation in isolation (and then hunt the clean
    copy-affinity-DEFEATER no-hack form), ADD ~7 competing saved-reg webs across the do-while.
    ⚠️ CORRECTION (lead-verified both-objs, retracting an earlier over-promise): animobjd2 fn_8013E0D0 is NOT a
    copy-pull bed for this — its `u8* p = st;` (cases 3/4) is a WALKER INIT (`p += 4` in a 7-iter loop), NOT a
    same-value copy, so there's nothing to coalesce. Verified: ours-vs-target opcode streams are IDENTICAL except
    ours has +6 `srawi` (the #150 signed-LL form, 6 vs 0); animobjd2's obj/st param-low-vs-target-high coloring is
    PURE COLORING DOWNSTREAM of that srawi pressure perturbing the interference graph — solving #150 cleanly likely
    fixes both (diagnostic: apply the u32 form, accept the temporary 0-store-steal, check if obj/st flip to
    r30/r31). So the copy-affinity-DEFEATER must be hunted via the 7-web ISOLATION (not animobjd2). The `|=`
    placeholder is the working solution meanwhile; the no-hack defeater is a lower-priority open target.
    ✓✓ NOW ISOLATED + MECHANISM PINNED (Validator, /tmp/v147/faithful.c — disproves the old "NOT YET ISOLATED";
    the earlier failure was just <5 webs). A faithful 6-GPR-web reconstruction (inline binary search returning a
    POINTER + the do-while + segmentIntersect) REPRODUCES the rotation and matches the in-tree facts: plain
    `previousCurveId = curveId;` → curveId pulled to r31 (HIGH, whole-pool rotation = the 96.5%); `|=` → curveId
    stays r27 (LOW, the 100%). MECHANISM: plain `prev=curveId` makes the FRONT-END COALESCE prev+curveId (same
    value) into ONE web; prev is MULTI-DEF (seed + `prev=nextCurveId` in the loop) AND used across the loop (the
    `prev!=curveId` condition) → that web is HIGH-PRIORITY → colors r31 → curveId rides up → whole-pool rotation.
    The `|=` makes the seed a #133 COMPOUND-OR COMPUTATION (scheduler-placed) → the seed copy lands in VOLATILE
    r8 (`or r8,r27,r27`) and curveId stays in its own param web (r27) — no coalesce. DEFEATER BATTERY (curveId reg
    measured on the bed): KEEP-curveId-LOW = ONLY `|=`/`&=` (exact 100%, the non-coalescing register-copy seed
    `mr r8,r27`), `=NONE` const seed (99.56%, 1 dead instr), `prev=curve[0]` mem-reread (#130, 98.27% lwz seed).
    FOLD→ROTATE (all became plain coalescing copies): binary `curveId|curveId`/`&`/`(curveId)|(curveId)`/`+0`/
    `*1`/`^0`/`|0`/`(int)curveId`/register-qualify/decl-order. So the compound SELF-op `|=`/`&=` is (so far)
    UNIQUELY the exact-100% form — a genuine compiler artifact (`x|=x` isn't folded where `x|x`-binary and `x|0`
    ARE). RESOLUTION: `=NONE`@99.56% (1 provably-dead instr) is the honest hack-free best; the `|=` stays the
    accepted 100% placeholder; the ONLY remaining clean-100% path is a STRUCTURAL pressure-reduction to the REST
    of the fn (fewer competing webs / change the condition's curveId use so plain `=curveId` doesn't coalesce) —
    open, lower-priority. The BED IS REUSABLE: A/B any clean-form candidate against /tmp/v147/faithful.c instantly
    (curveId=r27 good / r31 rotated). ★ This SAME coalesce mechanism is the value-copy-affinity nut — applied in
    the INVERSE (FORCE the coalesce) it's the #136(b) value-reuse / #126 param-pull / curves_getPos `mr r5,r4`
    reuse-live-1 lever; the bed + mechanism crack one and inform all.
    **★ CLASSIFIER (DeepDive2) — split every saved-reg-permutation residual into two kinds BEFORE
    spending levers; it tells you which lever-family to reach for (both kinds are winnable):**
    **(1) CLASS-RECLASSIFICATION (TRACTABLE): a value sits in the WRONG saved-reg POOL** (param vs copy
    vs multi-def). Tells: the whole pool ROTATES (curveId param→copy pushed everything up one). Levers:
    OR/#131 (keep a copy-source in its param class), #130 deref-decouple, #126 param-type, #137 reorder.
    This is curves_distFn15, and the detour family (#138/#143/#149). GO AFTER THESE.
    **(2) PURE WITHIN-CLASS ORDER/FREE-REG CHOICE — ★ CRACKED for RE-DERIVABLE values via #107 UN-NAME
    (expgfx, CameraModeTestStrength_update 99.88→99.98): right pool, wrong slot — which of two FREE same-class
    regs.** Signature: streams BYTE-IDENTICAL except reg names; T=C; no recovered copy. THE LEVER (generalizes
    #130's #107 mechanism to a kind-2 GPR TRANSPOSITION): UN-NAME (inline the defining expression of) the value
    retail keeps in the LOWER reg — drop its `int x` decl and spell `(flags & 1)` / `obj->field` / the &-mask at
    each use. That converts it from a NAMED SAVED-LOCAL web into an EXPRESSION TEMP, which colors LOWER
    (compiler-temp webs color BEFORE named-local webs, #107's GPR clause) → the WHOLE r27↔r28 scramble (both
    values AND any call-result copy) resolves in ONE edit. (expgfx case: two bit-extract locals `m1=flags&1`/
    `m2=flags&2` used twice across calls — un-naming m1 flipped the lot.) SCOPE: applies to RE-DERIVABLE values
    (bit-extract, field read, &-mask, global/deref address); does NOT apply to NON-re-derivable values (a
    u16-from-CALL conversion — inlining re-executes/regresses; that sub-case stays open, use #130 web-decouple
    or class-move). **BI-DIRECTIONAL (expgfx, dll_01D6 dll_1D6_update 99.86→100, FULL UNIT): the lever flips
    EITHER way by web KIND — expression-temps color BELOW named-locals, so move whichever value needs to move by
    flipping its naming:**
    • target keeps it LOWER + ours has it NAMED → UN-NAME it (inline the defining expr) → expression-temp colors
      lower. (CameraModeTestStrength m1=`flags&1`.)
    • target keeps it HIGHER + ours has it INLINE/CSE'd → NAME it (`T x = expr;`) → named-local web colors
      higher. (dll_1D6 `void* p28 = *(void**)((char*)model+0x28);` → r5, leaving the inline `flags1D` at r4.)
    DIAGNOSE: of the two swapped regs, which value does retail hold LOWER vs HIGHER, and is each currently
    named or inline? Flip the naming of the one that must MOVE to match its target reg height. NOTE: decl-order
    is NOT universally inert — per the #108 WITHIN-CLASS ORDER RULE it controls the home for TOP-LOADED/
    reorderable defs (field-reads/up-front loads, first-declared→highest), so for those just REORDER THE
    DECLS. decl-order is inert only for CALL-PINNED/computed webs — and THAT is where NAMING-KIND is the
    mover. So: reorderable defs → decl-order; call-pinned/computed re-derivable values → naming-kind. RE-DERIVABLE
    values only (bit-extract/field/mask/deref); NON-re-derivable (call-result conversion) doesn't take it
    (#130 web-decouple / class-move instead). This is now a proven SWEEP TOOL for the GPR-coloring near-miss
    bucket (~35 fns at 99%+) — the kind-2 frontier is NO LONGER a wall (#130/#131 lived here; #107 name-up/
    un-name-down by web kind is the general crack for the re-derivable majority). Still open: the
    non-re-derivable call-result sub-case, and the #155 MULTI-USE global-base detour (a base held whole-fn
    can't be un-named — that needs the #155 @lo-direct-into-saved core, the convergent multiplier).
    ✅ APPLICABILITY CHECKLIST (pausemenu, verified each with a failing case) — the value to flip must meet ALL:
    (1) RE-DERIVABLE: deref/field/mask/bit-extract — NOT a param (drawHudBox w/h↔x/y are params, fail), NOT a
    call-result. (2) NOT MUTATED: a pure read, not an accumulator (MagicPlant `alpha-=k; if(<0)alpha=0` can't
    inline, fail). (3) NOT LIVE ACROSS A CALL / NOT a call ARG (THE BIG ONE): un-naming RE-DERIVES per use, so
    if a use follows a call OR the value is passed to a call, CSE can't keep one load → adds reloads → REGRESSES
    (dfptargetblock_hitDetect `obj->home` passed to resetToHome() → 99.85→98.53, fail). So #107's sweet spot =
    a re-derivable unmutated read used in a CALL-FREE stretch (expgfx CameraModeTestStrength). (5) retail keeps
    it LOWER (un-name path) or HIGHER (name path) per the bi-directional rule. (4) CLASS: ✅ CONFIRMED
    CLASS-GENERAL (expgfx verified dll_1D6's win was an r4↔r5 VOLATILE swap cracked via NAME) — the naming-kind
    trick works in BOTH the saved class AND the volatile class; **#66 (volatile) and #107 (saved) are the SAME
    mechanism** (an expression-temp colors below a named-local within whichever class the value lands in). So
    criterion 4 is DROPPED as a blocker — it's only a label (saved=#107, volatile=#66), the fix is identical;
    sweep BOTH saved and volatile re-derivable-web swaps. (Criteria 1-3+5 are the real gates.)
    ROUTING BY SHAPE — #107 is a NARROW lever, not a broad sweep (expgfx scanned 140+ DLL 99%+ fns: only ~2
    were clean #107-fits, both won). Most 99%+ GPR-coloring residuals are OTHER shapes needing EXISTING levers —
    triage the bucket by shape FIRST, don't burn #107 on non-fits: NAME-vs-inline of a re-derivable read = #107;
    WALKER/COUNTER swap (2-counter, loop-bound placement) = #136 (Carryable_updateHeld, fn_8010A104); STACK-ADDR
    decl-order rotation = #16 (smallbasket_resolveCollision); in-place-bump re-fold = #61; s16-extsh = width lever;
    FP pair = #82 (CameraModeCloudRunner); const-load POSITION = scheduling/eval-order. The PURE FREE-REG-CHOICE
    kind-2(2) — same value NAMED/typed identically in both builds, both regs free, only the SLOT differs (no
    name-vs-inline distinction to flip, e.g. groundanimator `s8 bi`, MagicPlant `alpha`) — is the residual
    #107 doesn't reach; the live target is the creation-order/neighbor-perturbation/register-pressure lever (a
    clean source form exists — the next ingredient to add is named below).
    ✦CRUX PINNED (waterfx, objhits ObjHits_CalcSkeletonResponseXZ — the cleanest kind-2(2) repro, maximally
    narrowed): it's a PURE FREE-REG LOOK-AHEAD, not creation-order or naming. PROOF: the deciding `fmr fXX,f1`
    is at the IDENTICAL instruction offset in both builds (same web, same creation point) — ONLY the reg differs.
    Two adjacent saved FP webs (a CALL-RESULT `moveLen`=Vec3_Length + a GLOBAL-scalar `zf`=gObjHitsScalarZero,
    both live across the clamp): at moveLen's creation BOTH regs are free; RETAIL picks the LOWER (f30) —
    LOOK-AHEAD-RESERVING f31 for the later-created zf — OURS picks highest-free-first (f31). RULED OUT (all RAN):
    #45 decl-swap, #130 block-temp on the call-result, #81 launder, opt_level2 (regress, O4-in-retail), neighbor-
    perturb (zf-early regress); #107 N/A (moveLen is a non-re-derivable call-result; un-naming zf is wrong-
    direction). NOT YET ISOLATED in a minimal TU (probe_battery base.c hasn't reproduced it — the minimal TU
    is missing the in-tree pressure ingredient; ADD ingredients one at a time until the pick flips, then name
    the trigger). The one oracle (boneBlendSlotLimit, model.c) has the shape but is INLINED/static (no
    standalone source to diff — find a non-inlined sibling). So the whole ~35-fn kind-2(2) bucket reduces to
    ONE answerable question: which SOURCE construct makes MWCC graph-coloring RESERVE the higher free FP reg
    for a LATER-created value (look-ahead) vs picking highest-free-first? (deterministic allocator → there IS
    a concrete trigger; reverse-engineer it.)
    ✓DISCRIMINATOR RESOLVED (waterfx in-tree read, the look-ahead CONFIRMED over a creation-order hypothesis): it
    is NOT creation-order. Retail AND ours have BYTE-IDENTICAL positions — moveLen `fmr` @0x8dc (right after the
    Vec3_Length bl), zf `lfs` @0x994 (after 2 more bls) — in BOTH builds; the global is loaded AFTER the call in
    BOTH. So a "load the global before the call" creation-order reorder does NOT match retail (retail loads it
    late too) and regressed in-tree (99.90→99.28). The validator's isolation creation-order rule (gs-first→gs
    gets f31) is REAL in isolation but OVERRIDDEN by the full fn's register PRESSURE in-tree (retail gives the
    LATER-created zf→f31; ours the EARLIER moveLen→f31). So it's an in-tree PRESSURE-driven free-reg pick (the
    rule is deterministic — the in-tree pressure ingredient that flips it is the thing to pin). NEXT: a
    STANDALONE (non-inlined) oracle with this shape; else a deeper IN-TREE pressure model — add pressure
    ingredients one at a time until the pick flips, then name the trigger. The highest-value open coloring
    target, precisely characterized; fresh-eyes / oracle target.
    DOESN'T-APPLY shapes (pausemenu, verified — recognize fast, don't burn cycles): besides criteria 2/3/1
    failures, the naming lever is ALSO inert when the swapped values are (a) CONSTANTS — naming/inlining a
    literal is identical (a const colors the same either way), so a const↔const or const↔addr swap can't be
    flipped (DR_EarthWarrior_init 0x29↔inline-addr, Sky_func03 `li 0` pairs); (b) ALREADY-INLINE-CSE'd on BOTH
    sides — both are already expression-temps at their natural height, so there's no name-vs-inline to flip; the
    swap is then the pure free-reg-choice open nut above. So the lever needs exactly ONE side to be a NAMED
    re-derivable value (un-name→lower) or an INLINE re-derivable value retail NAMES (name→higher) — a genuine
    kind-MISMATCH to flip. (Plus #66's commutative-op-with-block-localable-operand variant.)
    #134 (int)(long), re-derive — none moved these specific webs (DeepDive2 dll_0256 fn_802BB4B4 r29↔r30
    T=C=181 + conversion-bias families; WorkerA kaldachom control r28↔r29 — block-scope was the ONLY
    mover, shifted the swap to a different value). UNTRIED LEADS to attack fresh: register PRESSURE /
    neighbor liveness (find a cheap extra USE that extends a neighbor's range WITHIN the existing
    schedule — no call-move needed); perturb a NEIGHBOR web's creation order rather than the value's;
    a probe_battery A/B sweep; map which source construct makes MWCC create this value earlier. For
    THROUGHPUT: bank the clean classes (class-reclassification/detour/structural) first, then return to
    this with FRESH EYES (derive from the asm as if new) — it falls to the right reframe, as this shape
    always has.**
    OPEN family in dll_0014: the unrolled candidate-collection first-iter `count=1` materializes as
    `mr rCount,rMask` (reuse mask=1) in retail but `li rCount,1` here (curves_getPos, countRandomPoints;
    getControlPointId_2A/2B already match with `li` — the outer-loop/register-pressure context selects
    copy-vs-rematerialize). Plus systemic FP f2/f3 volatile swaps (#82) and f28/f30 hoist-coloring
    (#121 conversion-bias sub-case) across effect9/dim2icicle/arwsquadron/xyzanimator/dimsnowhorn1 —
    each a near-100 with the lever still being mapped.
148. *(CRACKED → see #149 for the source forms)* **Global-base INDEXED-array detour `base + state[K]*0x28 + off`
    — front-end EVAL-ORDER (idx-first vs base-first).** Signature across the
    newseqobj-family (newseqobj fn_80150EDC/fn_80150910/fn_801504F8, seqobj11d fn_801511E8/fn_8015165C):
    target materializes the global base FIRST into its final reg and re-derives the index after —
    `lis r3; addi r3,r3,@lo` (base→r3 direct); `lbz r0,K(state); mulli r0,r0,40; add r3,r3,r0` (entry,
    base-first); then `lwz off(r3)`. OURS evaluates the INDEX first and routes the base through a temp:
    `lbz r0,K(state); mulli r4,r0,40; lis r3; addi r0,r3,@lo` (base→r0!); `add r3,r0,r4` (idx-first) — an
    extra working reg and the `addi r0` detour. Both TUs are `-opt nopeephole,noschedule`, so this is the
    FRONT-END's operand-eval order for `base + idx*40`, NOT the scheduler and NOT peephole. Forms explored
    so far (re-derive each FRESH from the asm — any of these may be the answer once framed right): #80
    `(u8*)(int)lbl` / `(char*)(int)lbl` launder (detour byte-identical), K-grouping
    `base+(idx*40+K)` / `(base+K)+idx*40`, `&lbl[idx*40+K]`, named-base-alias local, idx-precomputed-to-local,
    #135 typed-struct-array `((Slot40*)lbl)[idx].field`, decl reorder. Best partial so far: `&arr[...]` /
    `base+(idx*40+K)` nudge +0.05%. The frontier: an eval-order forcing lever (probe_battery.py A/B in isolation;
    or find the source shape where MWCC evaluates the `+`'s LEFT operand first for a global-base + memory-load-index
    sum). Cracking ONE applies verbatim to all five — a strong fresh-eyes target. SEPARATE FP-coloring residuals
    (NOT this detour): dll_8B_func03's dominant diff is an 8-reg FP rotation f24..f31 off-by-one (#121/#82
    hoist-coloring); DFRope_Create is gRopeNodeS32ToDoubleBias conversion-bias coloring (#121).
    **CONVERSION-BIAS COLORING — REFINED SEED (DeepDive2, still OPEN).** The recurring `(f32)(int/s16)x`
    int→float conversion BIAS double (the `0x4330000080000000` magic, often a symbols.txt symbol mislabeled
    `data:string "C0"` because 43 30… = "C0") colors at the LOWEST saved FP reg (f24/f28, created FIRST) in
    RETAIL but the HIGHEST (f31/f30, created LAST) in our builds — rotating every hoisted const web by one.
    ROOT: the bias web is synthesised during int→float LOWERING (a late pass) AFTER the front-end const
    webs, so #108 "last-created → highest reg" parks it high; retail created it first. The bias is a NAMED
    `.sdata2` ref in retail vs a local `@NNN` pool double in ours — CORRELATED but #70-SCORE-NEUTRAL (data
    bytes match); not the lever, but it hints the named ref is created early (front-end) and the @NNN pool
    double late. Forms explored so far (re-derive each FRESH — any may crack it with the right framing):
    f32-local decl-order (#45, consts are hoisted
    not the locals), un-naming the product (CSEs back), LITERAL operands (fixes the bias to f28 but FOLDS
    the runtime fmul → 1 instr short, e.g. dim2icicle prod=-75*0.5), moving the const assignments INTO the
    loop after the conversion (breaks hoisting → DSE), hoisting the conversion OUT of the loop (structure
    breaks), `prod = c34v * literal` (one named one literal — and a fmuls-operand-order shift),
    #114 no-op conversion node `(f32)(int)(long)x` on the conversion input (folds).
    ✓LEVER FOUND (validator probe — the "lowered-late → source-position-inert / build-domain-only" framing is
    DISPROVEN): the bias colors by the CONVERSION's SOURCE POSITION in the loop body (probe: conversion FIRST
    in the body → bias `lfd f28`; conversion LAST → bias `lfd f31`). It is NOT inert — it's the FP analog of
    func05's strides / the creation-order family. THE LEVER: relocate the `(f32)(int/u32)x` conversion EARLIER
    among the loop body's FP ops → its bias web is created earlier → colors at a LOWER fXX (retail's f29 vs our
    f31). The prior forms missed it because they moved the CONSTS or hoisted the conversion OUT of the loop —
    NOT its position WITHIN the body. So naming the bias being build-domain (no C names it) is moot — you DON'T
    need to name it; reposition the conversion. ✓SOLVED IN-TREE (waterfx, staffFn_80170380 95.91→96.73, 0
    regressions) — and the clean actionable form (NOT blind "move to top," which REGRESSED staffFn to 84.94 by
    reshuffling all the FP ops). THE FORM: to raise the bias ABOVE a competing HOISTED const (retail bias=f29,
    const=f28 → bias must be created BEFORE the const), **INLINE the competing const and reference it AFTER the
    conversion** — swap the add to `(f32)(int)(...) + lbl_constK` so the conversion/bias is the LEFT operand
    (created first) and the const is the RIGHT (created after); AND mark the const `extern const f32` so the
    inlined const still LICM-hoists to its saved reg (f28) instead of reloading. Front-end then creates the bias
    web first → bias f29, const f28 = retail. (The const was previously a PRELOOP named local, created before the
    loop → before the bias → bias parked last at f31.) DISCRIMINATOR (per-fn verify, the lever is NOT universal):
    apply ONLY where retail's bias reg should OUTRANK a competing HOISTED const; check the bias reg + report.json,
    KEEP only if the fn RISES. ✓BOUNDARY PINNED (validator probe — when the lever is INERT): the
    conversion-position lever works when the conversion result feeds an FP MULTIPLY; it is INERT when the result
    is STORED to a global field and RE-READ for a DIVISION (cv = the divisor, not a multiply operand) — the
    STORE fixes the bias web's creation point, so repositioning the conversion can't move it (dim2icicle: bias
    stays f30, conversion-first/named-local-first fold or add a saved reg). SWEEP DISCRIMINATOR: skip
    store-to-global + re-read-for-division shapes (and the bias-LOWEST shape where the bias must be f24/f28
    created-first but is lowered late — that one's the reloc-naming part, #70-neutral on score; the conversion-
    position lever hasn't moved the stored shape YET, so its source form is still to find). The lever's sweet
    spot = bias-above-a-pushable-preloop-const,
    conversion-feeds-multiply (staffFn). PROJECT-WIDE batch (sweeping that shape). (DeepDive2: dim2icicle 99.92,
    dll_8B_func03 96.03 — both pure bias-vs-const coloring, byte-identical streams. xyzanimator_update
    100% via #127 was a SEPARATE store-aliasing reload, not this.)
    REFINEMENT (expgfx, strong evidence — narrows WHEN it bites + which C routes are explored so far): (1) the bias
    only MIS-COLORS when it's HOISTED loop-invariant into a SAVED FP reg AND competes with many hoisted
    saved-reg consts (CONTROL: hoodedZyck_update's bias sits in a VOLATILE reg → colors CORRECTLY, only the
    #70-neutral @NNN-vs-named reloc differs; fn_80095164's bias is hoisted among 9 consts/31 FP loads → late
    creation parks it f31, rotating all 9 = the loss). So a NON-hoisted/volatile bias is a non-issue; the
    target is specifically the hoisted-competing case. (2) C-naming routes explored so far (re-derive each
    fresh — any may be the answer): `(f32)(int)x`
    AND `(f32)((f64)i)` BOTH pool the bias as a LOCAL @NNN double (synthesised in the late int→float lowering
    pass, after front-end consts) — the f64 cast does NOT name it AND adds a manual `fsub` (+1 instr, the #151
    path). Two known routes to a NAMED-early bias: (a) shared `.sdata2` magic-double
    pooling = OWNER/BUILD-domain (per #151, retail's bias = named `lbl_803DF308` front-end const → f25), or
    (b) the full manual union+fsub idiom (+1 instr). A cleaner source route for the hoisted case is
    ASSUMED to exist and is the live target; the BUILD-SIDE shared-.sdata2-bias pooling (owner-domain) is one
    known path — FLAG it like the #151 flips. ORACLE PROBE RUN (waterfx, definitive): grepped EVERY
    build/GSAE01/src/**/*.o for a `lfd lbl_` bias paired with `lis,17200` → ZERO hits; every conversion bias
    our build emits from C is a LOCAL `@NNN`. So NO current C form names the bias — the named-front-end-bias
    path is BUILD-DOMAIN (shared `.sdata2` pooling, owner-side), not a source lever today. The remaining SOURCE
    targets (both live): (1) the @NNN CREATION-ORDER sub-lever for the HOISTED-CONST variant — when the
    surrounding consts hoist to saved regs (loop has calls), the @NNN bias colors LAST and the #156-reload
    lever can't reach it; find the construct that orders the hoisted @NNN bias into the retail reg (staffFn_80170380);
    (2) UNTRIED long-shot: an inlined shared-conversion helper that pools the bias once (might name it without
    the extra instr — no current obj has it, so it'd be a new construct). Don't re-run the named-bias grep — it's
    answered (absent); chase the hoisted-const creation-order sub-lever.
149. **GLOBAL-BASE INDEXED-ARRAY DETOUR (#148 CRACKED) — pick the form by USE-COUNT of the base+idx sum.**
    The detour `entry = *(T**)(lbl + idx*K + off)` is a FRESH SUM: MWCC evaluates the index FIRST (operator-
    before-leaf: the multiply/load is an operator node, the global address a deferrable leaf) and routes the
    base through r0 (`lbz idx; mulli; lis r3; addi r0; add r3,r0,rIdx` — base detour). Retail wants the base
    materialized FIRST. THREE clean source forms, chosen by how many times the `base+idx*K` sum is used:
    (a) **SUM USED ONCE (single deref) → COMPOUND ACCUMULATOR.** `T* p = lbl; p += idx*K;` then `*(p+off)`.
       Compiles to `lis;addi rP (base direct, IN-PLACE); lbz idx; mulli; add rP,rP,idx` — base-first, index at
       the use, sum reuses base. EXACT match. (seqobj11d fn_801511E8 96.3→100; the playbook's #135-family form
       for a global base that is NOT walked.)
    (b) **SUM USED 2+ TIMES (held pointer / multi-deref) → still use the COMPOUND accumulator, but it lands
       base IN-PLACE where retail keeps base→r0 + index-reuses-lis-scratch + sum-reuses-index.** The forms tried
       so far show a tight MWCC coupling for this base→r0 multi-use shape — a clean source form is ASSUMED to
       exist and is still to be found: base-first only comes from the
       compound (⟹ base in-place); base→r0 only comes from the fresh sum (⟹ index-first). The fresh sum's
       index-first REORDER is penalised by objdiff far more than the 1-register base/idx transposition, so the
       COMPOUND is the net-best (no reorder; only a 2-reg swap left). It still fixes the hoist + index register
       vs the raw fresh sum (seqobj11d fn_8015165C 95.2→96.3, newseqobj fn_801504F8 94.6→95.4, fn_80150910
       95.9→96.9). Treat the residual base↔idx transposition as the #108 within-class tail (document, move on).
    (c) **WALKED global array (loop) with the `addi r0; mr rWalker` detour → TYPED STRUCT-ARRAY INDEX FORM**
       (extends #138 to fixed-count loops): replace the pointer-walk `p = glob; ...; p += stride` with
       `for (i=0; ...; i++) ((Image*)glob)->arr[i].field` — MWCC strength-reduces to the same walker but inits
       it with a DIRECT `addi rWalker` (no r0 detour). The walker base keeps its field offset as the load
       DISPLACEMENT (`lwz off(rWalker)`), matching retail. CAVEAT: if a later block (e.g. a found-handler)
       must RE-DERIVE the global fresh, do NOT reference the same typed pointer there — it CSEs onto the walker
       and collapses the re-derive (regresses hard). Use a SEPARATE compound accumulator for that block, which
       also folds its struct+field offset into the load displacement (e.g. 0x168+4→`lfs 364`).
       (dll_0017_savegame restoreObjectPos 91.2→99.2, saveObjectPos 95.3→96.4, unsaveObjectPos 98.4→99.2.)
    METHOD: objdiff penalises an instruction REORDER (index-first) much harder than a single wrong register,
    so prefer the no-reorder form (compound / in-place) even when it leaves a base reg "wrong" — a lower
    raw-instr-distance variant can score WORSE if it reorders. The base→r0 multi-use tail (b) == the same nut
    as SaveGame_gplayAddTime (99.41% pure 2-reg base/idx eval-order swap), still open as a true #108 residual.
150. **NOSCHEDULE-UNIT single-bit AND-clear: `field &= ~KLL` (u32 lvalue AND u32 RHS) → retail's `li -K; and`;
    plain `field &= ~K` → `rlwinm`. Match retail PER-CLEAR.** In `cflags_dll_noopt` (`-opt nopeephole,noschedule`)
    units (tricky_substates, dll_00C4_tricky, …) the AND isel tracks the schedule pass: at noschedule `~K` →
    `rlwinm` (1-bit clear), `~KLL` (#74) → `li -K; and` (materialized 2-instr). Retail uses BOTH forms — e.g.
    tricky_SeqFn's stateFlags clears are li+and (source has LL); Tricky_updateSideCommandPrompts' commandMask
    clear is rlwinm (no LL) — so READ THE TARGET and tune PER-CLEAR (li+and ⟹ add LL; rlwinm ⟹ no LL). #74's
    "lvalue u32" is necessary-not-sufficient: the RHS must ALSO be u32 — `result & ~KLL` with `int result`
    sign-extends to a high-word `srawi`; cast/retype the RHS to u32. The dead 64-bit high-word (`li 0` for u32
    RHS) DCEs cleanly when the clear is STANDALONE or the `=0` store PRECEDES it → those are clean wins, LAND
    them. **0-STORE STEAL — NET-WIN PARTIAL FOUND (flameguard, tricky_flameguard.c): when a `field = 0;` store
    immediately FOLLOWS the clear, the u32 `&= ~Kll` form makes MWCC's VN reuse the AND's dead high-word `li 0`
    for the zero (materialized EARLY into r3, stealing it from flags → flags spills to r4, 0 to r3 early — the
    regression). FIX: use a SIGNED lvalue — `*(s32*)&state->flags &= ~(u64)FLAG;` — NOT the u32 form. The signed
    promotion makes the high-word a `srawi` (a DEAD value, not a reusable `0`), so the `=0` can't CSE with it →
    flags lands in r3 and the 0 stays LATE in r0 (EXACTLY retail's `lwz r3; li -K; and; stw; li r0,0; sth`).
    NET WIN despite a residual dead `srawi r0,rX,31` retail lacks (+1 instr, but fixes the flags-reg AND the
    0-position — bigger gains). Landed the 0x400 TARGET_DIRTY clears across all 3 fns: trickyFlame 93.98→94.21,
    trickyGuardFindBaddieTarget 95.44→96.25, trickyGuard 97.70→98.15 (commit on main). Spell it via the field's
    accessor: `#define CLEAR(st) (*(s32*)&(st)->flags &= ~(u64)FLAG)`.
    OPEN (the dead-srawi-free retail form, ASSUMED to exist): retail emits NO srawi and NO high-word at all.
    PROVEN via /tmp probe (mwcc nopeephole,noschedule): the u32 high-word `li 0` IS DCE'd cleanly when the `=0`
    is in a SEPARATE BASIC BLOCK from the clear (`if(realcond){clear;} timer=0;` or `clear; if(realcond){timer=0;}`
    → perfect `li -K; and; ...; li r0,0; sth`, no srawi, no steal). The CSE only fires when clear+`=0` share a BB.
    BUT retail has them in the SAME bb and is still clean — so retail's MWCC didn't CSE same-bb where ours does;
    the source nuance that suppresses the same-bb CSE is the next thing to map. Forms explored so far for a
    no-branch BB boundary (re-derive each fresh): `if(1){...}`, `do{...}while(0)` both FOLD AWAY (no bb, still
    steal); a REAL runtime branch (`if(g())`, `if(best&1)`) creates the bb but adds an instruction. A faithful
    form exists — keep hunting the construct that gives the BB boundary cost-free. ROOT CAUSE (flameguard, precisely characterized): it is a DCE-vs-CSE pass-ORDER artifact —
    retail's MWCC DCEs the dead high-word `li 0` BEFORE CSE sees it, so the adjacent `=0` has nothing to merge
    with (stays fresh+late); OUR build runs CSE first, so `=0` reuses the high-word `li 0` (hoisted early →
    steals r3 from flags). Verified retail is clean SAME-BB at FindBaddieTarget @9d0 and trickyGuard case2 @198
    (`lwz r3; li -1025; and; stw; li r0,0; sth`, no srawi). Forms explored so far for the 32-bit AND (re-derive
    each fresh — any may be the answer with the right surrounding shape): `& 0xFFFFFBFF`, `& -1025`, `& ~(u32)0x400`,
    `& (~0u^0x400u)`, XOR-mask, local-mask-var, sub-form — these emit `rlwinm` (or `lwz`+`and` for a global mask)
    in the forms tried; `best*0`/volatile/`~0xFFFF` zeros all FOLD to the same VN
    as the zero-extension 0 so far. NARROWED leads (a clean form EXISTS): (a) a `timer=0` whose 0
    carries a genuinely distinct value-number from the zero-extension 0 WITHOUT a branch; (b) a source shape that
    makes MWCC schedule DCE before CSE for this clear+store pair. `#pragma peephole on` DCEs the dead srawi → exact match, but the unit
    is genuinely nopeephole (whole-unit peephole-on REGRESSES trickyFlame 94.21→90.75 / trickyGuard 98.15→97.20),
    so the pragma is a non-faithful shortcut here — keep the signed-LL form while hunting the faithful one. Asm at
    trickyFn_80143c04 L1321 + trickyFoodFn_80142d2c. SIBLING branch-fold (empty-then `if(x>=K){}else{x=-x}` →
    retail `bne; b` vs our folded `beq`): the #63 ternary `x=(x>=K)?x:-x` emits retail's `bne; b` but lands the
    result in a fresh fp reg (`fmr`) where retail negates in-place (`fneg fX,fX`). OPEN: a clean form keeping
    the ternary result in x's own fp reg is assumed to exist — untried: #107/#108 decl/use reorder, in-place
    spelling (schedule/peephole both tried, inert).
151. **CONTROL BRANCH-FOLD on an empty-then FP CLAMP → rewrite as the STRICT-INVERSE TERNARY (#91).**
    An empty-then clamp `if (f > lo) {} else { f = lo; }` FOLDS in our build to the compact inverted
    `bgt skip; fmr` — 1 instr SHORT of retail's UNFOLDED two-branch `ble else; b skip; else: fmr`
    (front-end fold, persists at opt_level 1/2/3, noschedule unit). The lever: spell the clamp as the
    STRICT-INVERSE ternary `f = (f < lo) ? lo : f;` (semantically identical — boundary f==lo gives lo
    either way). This UNFOLDS the branch and the instruction count matches retail (grimble_stateHandlerA02
    98.72→99.09, T=C=268). Use STRICT `<` (clean `bge`, no `cror`); the non-strict `<=`/`>=` inverse adds
    a `cror` (#25). Mirror the SIBLING ternary clamp in the same fn if one already matches (grimble's upper
    clamp `f=(f<hi)?f:hi` was already a matching ternary — the lower was the folding if-else). DISTINCT
    from #150's FP-negate sibling (`bne;b` vs `fneg`) and from the value-select empty-then (fn_8017D854
    `if(r>K){}else{r=r2}`, where the inverse needs `<=`+cror — that one's clean strict form is an open lead).
    Residual after the unfold: an `fmr`/compare-sense fp-reg swap (retail `fmr f1,f0`+`ble` vs ours
    `fmr f0,f1`+`bge`) — a within-clamp FP-coloring follow-on (#82/#91), a clean source assumed to exist
    (untried: operand-order / #107 result-reg reorder). SWEEP: try the strict-inverse ternary FIRST on each
    located empty-then clamp instance (appleontree fn_8017DCD4 ×2, grimble) before any other angle.
145. **IMPORT-ARTIFACT SWEEP (the highest-yield first pass on a fresh unit): a `stwu` frame-size mismatch has
    THREE causes — two are recoverable source, the third is a coloring trap. CHECK WHICH before investing.**
    (a) **Import-UNDERSIZED matrix/array** (#67b) — a `mtx44Transpose`/4x4 op fed a `f32 m[12]` that must be
    `[16]`; the −16B frame is the tell (dll_0B_func09: mtxB[12]→[16], frame −256→−272). (b) **DROPPED function
    ARG surfacing as a write-only/dead local** — a filled-but-never-read local (identity quaternion `f32 q[4]`)
    is DSE'd, shrinking the frame; it was the `spawnObject` `extraArg` the import passed as `NULL`. Pass the
    local → reserves the slot, matches the frame, and CASCADES coloring fixes (dll_0B_func05 94.8→95.7, +0.85%
    from one arg). (c) **CONVERSION-TEMP POOL size (#83) — NOT recoverable, SKIP.** Retail keeps N more 8-byte
    `(f32)(s32)`/`(s16)` magic-conversion doubles live across calls; shows as a frame mismatch but is a
    scheduling/statement-granularity coloring diff, not an artifact (CameraModeForceBehind_update, expgfx_addremove,
    drawGlow were all this). **DISCRIMINATOR:** look at the shifted/extra stack region — an *address-taken buffer*
    accessed PAST its declared size ⇒ (a)/(b) fixable; the region being conversion magic (`lis 17200` / `xoris
    0x8000` / `lfd bias`) ⇒ (c), skip. SIBLING WIDTH LEVER (no frame change, also high-yield): **`int` locals
    stored into `s16`/`u8` struct fields emit a spurious `extsh`/`clrlwi` before the store — declare the local at
    the field's width** (expgfx_addremove: `int texS0/S1/T0/T1` → `s16`, drops the per-store extsh, 90.2→90.9;
    confirmed faithful by sibling expgfx_initSlotQuad already using s16). METHOD: scan every near-miss for `stwu`
    mismatch FIRST (classify a/b/c); then grep each fn's locals for
    write-only names (declared + assigned, never on a RHS/`&local`/call-arg) — those are dropped uses/args
    waiting to be restored. `cosmetic_audit.py`/`width_audit.py` cover the no-frame-change cases (wrong const,
    field width). OPEN residuals on the dll0b set, each a lever-still-to-find (target-vs-yours shape noted):
    (1) **chained-zero copy** `a=b=c=0` → retail `li;mr;mr`, O4 copy-prop folds to 3×`li` (curves
    preparePointCollisionFrame/updateLocalPointTransforms, dll_15_func0A, func04 `found=i`). Source already
    uses the copy form; opt_level-1 keeps it but regresses these call-bearing fns (#142) — the fresh-eyes win
    is the source shape that survives O4 copy-prop (a #131/#136(b) integer analogue). CONFIRMED-INERT for the
    LOOP-fn variant (flameguard, saveSelectSetupMenuItems `off2=off1` where off1=0 — NOT a #51 call-arg win):
    chained `off2=off1=0` (const-props through), opt_level 1 (REGRESSED 98.89→79.81, while-loop O1 overhead
    per #110/#142), #147 OR-analogue `off2|=off1` (INERT — off1 is a 0 CONST with no runtime value to split,
    and nopeephole DCE's it). So the integer analogue must work on a CONST-0 copy, which the pointer #131-OR
    and #136(b)-reuse forms don't cover — still open. (2) **#21 shared-block
    placement** (skeetla trickyFindPathRouteEntry 98.59 / trickySelectRouteEntry 98.81): retail emits `bne X; b Y`
    (both arms branch to a SHARED `entry=NULL` block placed LATE), our build emits `beq X` (the shared block lands
    EARLY, reached by fall-through). 1-instr each. Forms explored so far (re-derive each fresh — any may be the
    answer reframed): merge the if/else-if into one
    `||` guard (folds the dead `entry==NULL`); drop the early `return NULL` (that island IS in retail); nested-invert
    `if(entry!=NULL){if(...)x=NULL}else{x=NULL}`. The if/else-if baseline is closest — the lever is whatever forces
    the shared `entry=NULL` block to the LATE position (a block-layout/#21 control, not a guard rewrite). (3) **address re-derive vs CSE-hoist** (pushable_savePos): retail
    re-materializes `&gSaveGameData` per use (3×lis) reusing the offset; forcing it (form-asymmetry/launder/
    opt_common_subs-off) reproduces the exact instr MULTISET but frees the addr's saved reg → a #108 coloring
    permutation underneath. The clean win pins that one freed reg. (4) #108 within-class perms (fn_800A02DC FP
    f1/f2 swap — source-order/named-local/const/launder explored so far, the right reframe still to find;
    fn_800A0C78 buf/buf2). (5) objFn_80198fa4
    (99.975%): a 64B `f32[16]`/union sits at stack-offset 28/32, never 112 where retail puts it (only a 72B m[18]
    lands at 112) — the conv-temp wants 176; likely a #120 split where the 4x4 was adjacent to another local in
    one bigger struct (rejoin to size it onto 112).
151. **objdiff scores a fn `None` (= 0% in the unit measure, field ABSENT in report.json) when a MATCHED
    instr's reloc pairs a base-LOCAL-defined data symbol against a target-UNDEFINED external — the
    "#70 / flip-held conversion-bias" case. The fn is asm-matched; recover it by FLIP, not objdiff %.**
    dll_0032_titlescreeninit/runLoadingScreens was the whole unit's 31.67% (verified: weight the other
    fns with runLoadingScreens=0 → exactly 31.67%) yet is ~99% byte-matched (T=C=261). Root cause: the
    u32→f64 conversion bias `0x4330000000000000`. Retail's `.sdata2` SPLITS it into lbl_803E1CE8(0x43300000)
    +lbl_803E1CEC(0) referenced as one 8-byte `lfd`, and the target .o leaves lbl_803E1CE8 UNDEFINED
    (defined cross-object in auto_11_803DE500_sdata2.o). Our idiomatic `(f32)(u32)counter` pools it as ONE
    8-byte LOCAL `@54`. objdiff can't content-match 8-byte-local ↔ split-4-byte-undefined → None for the
    whole fn. CONFIRMED: removing the conversion → fn SCORES (1.99%, not None); the symbols.txt mis-tag fix
    (lbl_803E1CE8 0x3/string→0x4/float) did NOT un-None it (verified in main repo). The `(f32)(u32)` idiom
    that byte-matches the target's `fsubs` ALWAYS pools the bias locally; a manual `t - lbl_803E1CE8` (extern
    bias) references the external but emits `fsub;frsp` (+1 instr, non-idiomatic) — so keep the idiom and
    take the FLIP path (the asm matches; objdiff-content-match is the limitation). Census: same None on
    model/ObjModel_TransformVertices{WithTranslation,Linear,QuadVerticesLinear} + dll_00E2_staff/staff_initialise
    (staff's is SOURCE-fixable: its lbl_803208A0 .data array is base-DEFINED but should be `extern`).
    **runLoadingScreens flip-readiness (handoff): asm-byte-identical EXCEPT (i) the 8 flip-held bias relocs
    (@54 vs lbl_803E1CE8, content-equal) and (ii) TWO single-instr conversion-node diffs that CANCEL in
    count (T=C=261).** LANDED a clean half: a block-local `u8 alpha` in the `<0xf0` HUD branch makes
    `colorBuf.bytes[3]=alpha` a bare `stb r4` (matches retail) — but it RELOCATES the `clrlwi` from the store
    to the alpha load (`lwz r0,28; clrlwi r4,r0,24` vs retail `lwz r4,28`), net-neutral; the narrowing
    conversion is CONSERVED (store for `int` alpha, load for `u8` alpha), retail's HUD branch has it at
    NEITHER. Diff B (the mirror): retail's FIRST `gDvdErrorPauseActive != 0` test emits `clrlwi r0,r3,24;
    cmplwi r0,0` (masked), the SECOND `==0` uses raw `cmplwi r3,0`; ours masks NEITHER. A clean form for both
    EXISTS (record on these is perfect). Forms explored so far (a launchpad for the next attempt — re-derive each
    fresh, any may be the answer): A — `int`
    alpha (clrlwi at store), `u8` alpha global/block-local (clrlwi at load), `s8`/`char` byte (extsb not
    clrlwi), `*(s8*)&bytes[3]`/struct-`s8`-a-field (extsb), `u8`-drawTexture-param (draw branch still masks),
    union/array/u8*-pointer stores (all narrow); B — `int` local (signed `cmpwi`, wrong), `u32` local,
    direct-global-read both, asymmetric global-first/local-second read, truthiness (all mask NEITHER). Untried
    leads: A — find the source/struct that makes the byte the *unconverted* low slice of an int web (the
    conversion node is front-end/type-driven; a form where alpha's web is byte-typed from a NON-converting
    source); B — the in-repo/MP4 oracle for `clrlwi rX,rY,24; cmplwi rX,0` + later raw `cmplwi rY` (a u8
    flag masked on first compare, raw on second — find the producing C). DIAGNOSTICS: report.json absent
    `fuzzy_match_percent` = None (5 fns project-wide); `objdiff-cli report generate` confirms; per-fn diff
    via `function_objdump.py`/`ndiff.py`. (Flip + symbols.txt are owner/lead-domain; this is the source side.)
152. **SINGLE-BIT MASK-CLEAR: retail's separate `not`+`and` (NOT `andc`, NOT `xor`) → `opt_propagation off`
    + LOAD THE MASK INTO A TEMP ON ITS OWN STATEMENT BEFORE the `~`.** When retail clears a bit with two
    instrs `lwz mask; not r0,bit; and r0,mask,r0; stw` but our build either FUSES to `andc r0,mask,bit`
    (source `mask &= ~bit`) or emits `xor r0,bit,r0` reusing a nearby `-1` (source `mask &= bit ^ 0xFFFFFFFF`),
    the clean form is: `{ u32 m = *maskPtr; inv = ~bit; *maskPtr = m & inv; }` wrapped in `#pragma
    opt_propagation off … reset`. WHY each piece: (a) `~bit` (not `^0xFFFFFFFF`) is needed so the complement
    is a `not`/`nor` not an `xor`; (b) opt_propagation off keeps `inv` a SEPARATE value so it is NOT folded
    into the AND (folding → isel picks `andc`, a 1-instr fusion retail never uses — confirmed 0 `andc` in the
    whole target unit); (c) loading the mask into its OWN temp `m` BEFORE the `~` statement reproduces retail's
    emission ORDER `lwz; not; and` (opt_propagation off alone keeps source order, which puts the `not` BEFORE
    the mask load → an objdiff-penalised reorder, #149). The temp+pragma is plausible 2002 C and clean.
    Landed three fns in dll_000A_expgfx with ZERO collateral (the pragma is per-fn, scheduling/peephole already
    off in these units): expgfxRemove 97.2→98.87 (count went T=C, the andc was the 1 missing instr),
    expgfxRemoveAll 98.2→98.8, resetAllPools refactor +0.4. SWEEP: any near-miss whose first diff is `andc`/`xor`
    where the target shows `not`+`and` — apply the temp+pragma. (DISTINCT from #74's materialized-mask LL form,
    which is for `li -K; and` not `not; and`.)
153. **RECOVER A SEPARATE FIELD-POINTER: `T* p = &obj->field; if(*p){(*p)--; ...}` reproduces retail's
    `addi pAddr,objBase,K; lhz 0(pAddr)` where direct `obj->field` (accessed 3×) emits `lhz K(objBase)`
    every time.** When retail hoists `&struct->refCount` (or any field accessed read+write+read) into its own
    register and accesses it via `0(p)`, while our build re-uses the struct base with the field displacement,
    write the field pointer explicitly. ALSO grouped-cast the struct address the same way the sibling fn does:
    `tableEntry = (T*)((u8*)base->arr + idx*size); refCountPtr = &tableEntry->refCount;` — this matched retail's
    `add objBase,idx; addi K; lhz 0(refPtr)` grouping AND the field pointer in one edit. (resetAllPools
    86.8→89.1; the matching sibling expgfxRemoveAll already used this exact `refCountPtr` form — when one fn in
    a unit matches a struct-access shape and a sibling doesn't, COPY the matching fn's spelling.)
154. **TWO-LOOP global-array scan where retail KEEPS THE BASE in one reg, COPIES it for loop1's walker, and
    REUSES it directly as loop2's walker → `table = global; for(i=0,entry=table; …; i++,entry++){…}
    for(j=0; …; j++,table++){…}`.** Loop1 walks the COPY `entry` (so the base survives loop1), loop2 walks the
    PRESERVED base `table` directly (destroying it — fine, it's not needed after). Put the base materialization
    IN loop1's comma-init AFTER the index init (`for(i=0, table=global, entry=table; …)`) so the index `li`
    emits first (matches retail's prologue order). Took expgfx_addToTable 82.4→97.9 (pointer-walk vs the raw
    `arr[i]` offset-accumulator form that strength-reduced to an extra `add` per iteration). RESIDUAL: the
    front-end SAME-VALUE MERGE (#131) still routes the base+copy through one temp `addi r0; mr rBase; mr
    rWalker` vs retail's `addi rBase; mr rWalker` (1 extra `mr`) — see #155.
155. **THE "global address materialized into a SAVED reg via `lis r3; addi r0,r3,0; mr rSaved,r0`" (1 extra
    `mr`) vs retail's DIRECT `lis r3; addi rSaved,r3,0` is a PERVASIVE front-end residual in dll_000A_expgfx
    (renderParticles 99.1, expgfx_free, expgfx_initialise, expgfxRemoveAll, resetAllPools, addToTable all hit
    it) — a clean source form is ASSUMED to exist, NOT yet found.** Diagnostic: retail materializes the LOW
    half of a `lis;addi` global address DIRECTLY into the destination saved/volatile reg (often REUSING the
    `lis` temp: `lis r3; addi r3,r3,0`); ours computes into `r0` then copies. The FIRST global a fn materializes
    usually goes direct (e.g. `runtime` → `addi r31,r3,0`); SUBSEQUENT standalone globals (`gExpgfxStatic…`)
    take the `r0`+`mr` detour. It is tied to the walker/value's COLORING (in expgfx_initialise retail colors the
    walker into the low volatile r3 and the loop-invariant `0` into saved r29; ours swaps them → the `mr`).
    Forms explored so far (re-derive each FRESH — a low-effort pass that "didn't move it" is NOT proof; any of
    these may be the answer once the surrounding shape is right): `register` keyword, init-statement reorder,
    decl-order swap, `#80` `(T*)(int)lbl` launder, `#pragma peephole on/off`, `#pragma opt_propagation off`.
    LEADS to
    attack FRESH: find the in-repo/MP4 oracle C that emits `addi rSaved,r3,0` direct for a standalone global
    into a saved reg (grep matched `.o` for `addi r2[0-9],r3,0`/`addi r3[01],r3,0` with a global reloc, read its
    source); model it as the #131 same-value/front-end materialization and look for the operand-level split that
    keeps the addi targeting the destination; perturb a NEIGHBOR web's creation order so r0 isn't the free temp
    at the materialization point. This is the single highest-leverage open nut in the unit (gates 6+ fns).
    **PARTIAL CRACK (the #143 INDEX FORM): for a global WALKED in a loop (`p = glob; *p=…; p++`), rewrite as the
    INDEX form `glob[loopCounter] = …` (drop the pointer + its `++`) → MWCC strength-reduces to a walker inited with
    a DIRECT `addi rSaved`, KILLING the r0+mr detour.** Took expgfx_free 95.6→97.2 (mr count 2→0, T=C).
    ✓ISOLATED (validator + lead, probe-confirmed) — the index form RELIABLY makes the base go DIRECT:
    confirmed for single-walker, multi-walker (2 globals → both direct), WITH-call (no unroll), WITHOUT-call
    (unrolled by 8), AND non-unit stride (struct array, stride 8 → `addi rWalker,8`, base still direct). The
    pointer-walk source (`p=glob; p++`) is what forces the r0 detour; the index form is the crack and it is
    NOT base-specific. So the documented real-fn regressions (expgfxRemoveAll kept mr+`slwi;add`,
    renderParticles→`lhzx`, onMapSetup→0%) are NOT the base materialization failing — the base STILL goes
    direct. They are COLLATERAL load/store isel the index form perturbs when the walker is NOT cleanly
    strength-reducible: a non-strength-reducible stride → `slwi;add`, a conditional/single use → `lhzx`. So the
    precise win is: index form on a walker whose stride strength-reduces (unit or clean fixed stride) AND whose
    uses are unconditional → clean 1-instr base fix. For non-reducible-stride / conditional-use walkers, the
    index form fixes the base but shifts the load/store isel, so pair it with a stride/use spelling that keeps
    the original isel (the narrow remaining frontier). A/B PER FN, grep `mr.*r0$` to confirm the base mr drops
    AND watch the load/store opcode; this is the strongest #155 lead — try it FIRST on any base-mr fn with a
    `glob[i]` walker.
    ⚠️ IN-TREE BOUNDARY (HunterA, expgfxRemoveAll store-index 98.83→96.72 REGRESSED — refines the "RELIABLY makes
    base direct" isolation claim above): under MULTI-WALKER + INNER-LOOP STRENGTH-REDUCTION COMPETITION the index
    form does NOT make the base direct — the lone explicit `glob[i]` LOSES the SR competition to the competing
    pointer-walks, so it stays UN-reduced as the #149 index-FIRST detour (`slwi i; addi r0,r3,@lo; add walker,r0`,
    base STILL via r0) AND adds an instr. So the clean-base-direct result holds ONLY for a SOLE/simple-counter loop
    (the isolation shape); the expgfx detour fns (removeAll/resetAllPools = outer+inner loop + 3 competing walks
    with `poolActiveMasks` r/w INSIDE the inner loop so it can't be index-formed; onMapSetup = 6 unrolled walkers;
    getSlot = nested) are NONE of them sole-counter. For multi-walker fns the OPEN CORE is the deeper lever: make
    the global walker base materialize `addi rWalker,r3,@lo` DIRECT while KEEPING the pointer-walk (no restructure)
    — still to find. So: store-index form = SOLE/simple-counter store loops only; multi-walker = the deeper lever.
    **WHY IT'S LIMITED (confirmed by reading retail onMapSetup): retail's loop is an UNROLLED pointer-walk
    (`addi rWalker,r3,0` DIRECT, then disp stores `0(r),4(r),8(r)…`, walker += 8) — i.e. the SOURCE form is already a
    correct pointer-walk and the ONLY diff is the front-end materialization (direct vs r0+mr). The #143 index form
    REWRITES the loop and BREAKS the unroll (→0%). The #138 struct-array / #149 compound-accumulator reframes also
    DON'T apply — poolSlotTypeIds is a FLAT s16 array walked, not a struct array and not a fixed-stride single index.
    So for FLAT-ARRAY POINTER-WALKS IN UNROLLED LOOPS (onMapSetup, initialise, renderParticles) the base-mr is the
    PURE #155 front-end materialization — the source reframe is still out there waiting (the addi simply must target
    the walker reg directly instead of r0). NEXT: read retail's prologue reg-alloc order and find the construct that makes the
    walker reg the addi destination (it's the SECOND+ lis;addi into a saved/walker reg that detours; the first is
    direct). Bank as fresh-eyes-return; the #143 crack only covers NON-unrolled single-walker loops.**
    **OTHER CLUES (dll_000A_expgfx deep-dive):** (1) the bug is BROADER than globals — it's a general "materialize a
    saved-reg value via VOLATILE TEMP r0 then `mr`/copy" vs retail's DIRECT-into-saved. Also hits `extsh r0,r3` then
    copy (vs retail `extsh r24,r3` direct into the saved reg, addremove resourceTableIndex). (2) The FIRST
    standalone-global-into-saved in a fn materializes DIRECT (e.g. `runtime` → `addi r31,r3,0`); SUBSEQUENT standalone
    globals take the r0+`mr` detour — so it's allocation-state-dependent (after the first lis;addi, r0 becomes the
    "free" temp the allocator grabs). This points the fix at perturbing the allocation state at the 2nd+ materialization,
    NOT at the global's spelling. (3) Also explored here: the staticData-base reform (derive the globals from a struct
    base) — it removes the `mr` but the reloc change (gExpgfxStaticData+off vs the standalone gExpgfxStaticPool* symbol)
    costs MORE than the mr saves (expgfx_free 95.6→92.5), so the standalone-global reloc looks load-bearing for now. A
    clean source form exists; the "first-direct/rest-via-temp" asymmetry is the freshest lead.
    ✅ CORRECTED DISCRIMINATOR (expgfx, matched-fn oracle — the COUNT hypothesis above is WRONG): MWCC readily
    materializes MANY globals DIRECT into saved regs (oracle: partfx_updateFrameState = 19 DIRECT `addi rSaved,r3,@lo`;
    cloudaction_update = 6, re-materializing one global into r29 4× direct). It's NOT "1st direct, rest detour" — the
    real discriminator is ACCESS PATTERN: a SCALAR global (`gX=…`) or CONSTANT-OFFSET access (`gStruct.field`,
    `gArr[K]` const K) → ALWAYS materializes DIRECT (even multi-use, re-materialized by name each use). A RUNTIME-
    INDEXED / WALKED base (`p=gArr; p[runtime_idx]` / `p->f; p++`) → the r0+`mr` DETOUR (the runtime index/walk forces
    the base through a reg via r0). So the #155 detour CORE is narrowly the RUNTIME-base case ONLY; scalar/const-offset
    are already direct. (Explains task-21: dfsh global-direct REGRESSED = `gArr[runtime_idx]`; modellight WALKS.) The
    open core = "make a RUNTIME-INDEXED/WALKED global base materialize `addi rWalker,r3` direct" — the by-name oracle
    doesn't cover it; hunt a matched fn that materializes a RUNTIME-indexed base direct. ⚠️ RECONCILE: flameguard's
    dll_7B base[0x128] is a CONSTANT offset yet DETOURS — contradicts "const-offset = direct"; the extra factor is
    likely the CONDITIONAL first-use (`if(...) base[0x128]=…`) routing base through volatile r3 for the guarded store.
    So a 2nd sub-trigger may be CONDITIONAL/guarded-first-use, not just runtime-index — open, worth pinning.
    THREE-CASE SCOPING (expgfx) — #155 splits cleanly; one case still has its lever waiting to be found:
    (1) SCALAR / const-offset global → ALWAYS DIRECT (no fix needed). (2) SINGLE-USE array walk (one access/iter,
    e.g. expgfx_release `mm_free(gPoolBases[poolIndex])`) → #143 INDEX FORM `glob[i]` gives the DIRECT walker —
    SOLVED (confirmed in a matched fn; this is the #143 win). (3) MULTI-FIELD struct walk (`entry->f1; entry->f2;
    …; entry++`, e.g. modellight) → the live target. Forms explored so far (re-derive each fresh — any is a
    candidate answer): pointer-walk → base-init detours
    `addi r0,r3; mr rWalker`; index `glob[ch].field` recomputes base+ch*size per field 4×/iter;
    hybrid `entry=&glob[ch]` per iter. The forms tried so far route base-init through r0; a clean source form that
    keeps it direct is ASSUMED to exist — it's an allocation-state shape, exactly the kind the kind-2 frontier got
    #107, so a fresh reframe (or an allocation-perturbation discovery) will land it. Cases 1+2 are
    done; case 3 is the live one. FINAL CONFIRM (expgfx, modellight): the materialization-order perturbation
    (moving base-init up-front before its neighbor inits, keeping the pointer-walk) REGRESSED 98.81→96.28 AND
    the base STILL detoured — so base-above-neighbors is the WRONG perturbation. KEY UNTRIED-DEEPER lead for the
    fresh-eyes return: modellight has TWO r0-routed webs — the base (`addi r0,r3; mr r31`) AND a masked value
    (`clrlwi r0,r0,24; mr r29`, the `activeMask & 0xff` also routes via r0+copy). flameguard's dll_7B +0.55 came
    from perturbing ONE web's neighbors. DEFINITIVE READ (expgfx, modellight — case-3 SPLITS into two sub-shapes):
    retail `li r29,0; li r30,0; lis r3; addi r31,r3; lbz 0(r31)` vs ours `…; addi r0,r3; mr r31,r0; lbz 0(r31)` —
    the neighbor defs (r29/r30) are ALREADY BYTE-IDENTICAL to retail; the SOLE diff is the base materialization
    (direct `addi r31,r3` vs `addi r0,r3; mr r31`). So on modellight there is NOTHING to perturb (neighbors match;
    source init-reorder doesn't even change the EMITTED order — MWCC emits neighbors-first then routes the base via
    r0 regardless). This is the PUREST #155 residual: identical source/O2/emission-order, MWCC just picks
    r0-scratch+copy for the global-base-into-walker at O2 where retail picks direct. Forms explored so far on the
    source handle (re-derive each fresh): launder / index / hybrid / init-reorder / neighbor-order; O3/O4 fix the
    base but regress globally. So case-3 =
    TWO sub-shapes: (a) NEIGHBOR-ORDER-DIFFERS (flameguard's dll_7B +0.55 materialization-order perturbation
    applies — neighbors not yet matching); (b) NEIGHBORS-ALREADY-MATCH (modellight — sole diff is the raw base
    addi-direct-vs-r0-detour). Sub-shape (b) is the rawest O2-allocator-choice shape and the highest-value
    target; the fresh-eyes return needs a NEW handle on the base-init reg selection itself (a clean source form
    exists — beyond neighbor perturbation).
    **MAJOR REFRAME (flameguard, dll_7B_func03) — a chunk of the ★#147 "kind-2 byte-identical-except-one-reg
    within-class-ORDER" residuals are #155 DETOURS IN DISGUISE, not generic coloring.** When a kind-2 swap has
    one of the two swapped regs being a GLOBAL BASE, check its materialization: if base goes `lis r3; addi r3,r3,@lo;
    mr rSaved,r3` (detour) where retail does `lis r3; addi rSaved,r3,@lo` (DIRECT), THAT detour is what forces
    base→the-wrong-saved-reg and pushes the neighbor (&buf/entries) to the other reg = the "swap." So the lever is
    the #155 direct-materialization (above), NOT a coloring trick — reach for the detour lever rather than the
    ★#147 coloring leads on it.
    DIAGNOSE every kind-2 swap for a global-base detour FIRST. CASCADE-REDUCER (real, faithful, +partial): the
    #5/#108 SPLIT-DECL-INIT — a `T* x = obj->field;` at the top materializes x's web BEFORE base, inflating the
    cascade; split to `T* x;` + init right before first use → base's web is created first → smaller cascade
    (flameguard dll_7B 98.86→99.21, pushed). The CORE swap is still gated on the #155 direct-materialization.
    Forms explored so far on dll_7B's detour (re-derive each fresh — any may crack it): #80 launder, decl-order
    swap, early local copy (copy-prop folds), #128 opt_propagation off. CONVERGENCE: flameguard (dll_7B kind-2) + expgfx
    (modellight modelLightChannels_applyGXControls, task #21 detour sweep) hit the SAME open sub-variant —
    global-into-saved-reg-via-scratch+mr → wants direct `addi rSaved`. Cracking THIS ONE #155 direct-materialization
    lever is the convergent multiplier: it unblocks both the detour hard-variants AND the kind-2 within-class-order
    frontier. Highest-leverage open C-side target. SUB-LEVER — MATERIALIZATION-ORDER perturbation (flameguard,
    dll_7B 99.21→99.41, +0.55 cumulative): when a #155 detour competes with a stack-addr/local web, PLACE the
    global's neighbor (the other saved-reg web's def) to MATCH retail's emission order — e.g. move
    `entries = buf.entries` to immediately after `base = global` so BOTH materialize up front (before the variant
    block), matching retail's order → progressively REDUCES the coloring cascade even while the core detour
    persists. (Pairs with the #5-split decl-init.) The CORE detour stays: base's first use is the CONDITIONAL
    store `base[K]=…` (variant if/else) → MWCC materializes base into volatile r3 for the store + `mr` to saved,
    retail materializes @lo DIRECTLY into the saved dest and stores via it. Forms explored so far on the core
    (re-derive each fresh — any is a candidate): decl-order swap, #80 launder, opt_propagation off, local-copy.
    The @lo-direct-into-saved is the live core (find it via the oracle source-form or a deeper reframe — it exists).
156. **LOOP-INVARIANT FP CONSTANT / `(s32)<global float>` ARG → mark the global `const f32` and INLINE it at
    the use (NOT a cached named local).** When a loop passes a loop-invariant float constant (as a fcmps/fmadds
    operand) or a `(s32)<loop-invariant global float>` arg, retail HOISTS the load (and the float→int fctiwz) into
    a SAVED FP reg ONCE in the preheader, then materializes per-iter (`stfd fSaved; lwz rArg` for the int case, or
    just reuses the saved reg). Three source forms, only ONE matches: (a) a NAMED f32 LOCAL `f32 m = lbl; … (s32)m`
    → MWCC fully hoists to a GPR (gives the int a GPR home, wrong — regresses); (b) PLAIN inline `(s32)lbl` (global
    NOT const) → recomputes the lfs+fctiwz EVERY iteration (no hoist); (c) **`extern const f32 lbl;` + inline
    `(s32)lbl`** → the `const` enables cross-iteration load-CSE so MWCC hoists into a SAVED FP reg (matching retail's
    f28/f31), and inlining (vs a pre-declared local) gets the FP web CREATION ORDER right — the const's web is created
    at-use AFTER the conversion-bias web, landing the saved-FP pair in retail's order. This recovered 2 missing FP
    saved regs (f27/f28) AND the hoisted fctiwz on pauseMenuDrawStatus_801274a0 (92.4→95→96.5). GENERALIZES #71/#127:
    `const` is the lever for "retail CSE-hoists a loop-invariant float into a saved reg but our build recomputes/GPR-
    hoists." Co-lever: a `f64 tmp` intermediate splits a chained `(double)…*A*B` so the LAST constant (B) loads LATE
    (at the second `*`) into the arg reg, not hoisted early — matched pauseMenuDraw's x-calc (96.7→96.9). (pausemenu.c.)
    GENERALIZED to f64 consts (dll_0000_gameui boxDrawFn_8012975c 94.18→98.48: `f64 c0/c1/c2 = lbl;` → `extern const
    f64 lbl;` + inline). **DISCRIMINATOR (hit-or-miss — A/B it):** inline+const HELPS when the named locals color
    CONSECUTIVE (f27/f28/f29) but retail SPREADS them (f27/f30/f31 with the conversion-bias/computed webs interleaved)
    — i.e. retail creates the const webs AT-USE, after the bias/computed webs. It REGRESSES when retail keeps the
    HOISTED named-local form and the consecutive coloring is already closer (dll_0000_gameui fn_8012C000 94.9→89.1 with
    6 consts inlined — retail wants them hoisted, f26-f31). Read retail's preheader: consts loaded together at the top
    → keep named locals; consts loaded spread/at-use → inline+const. boxDrawFn (2 consts each in 2 short loops) spread →
    inline won; fn_8012C000 (6 consts, one big loop) hoisted-together → inline lost.
    METHOD NOTE — **objdiff largely NORMALIZES stack-displacement immediates**: a frame-size/stwu mismatch that ONLY
    shifts every `N(r1)` offset by a constant is NEARLY score-neutral (pauseMenuDraw frame 336 vs retail 176 cost ~0).
    The frame is worth fixing ONLY when the buf/local size change lands the conv-temp offsets on retail's EXACT values
    (pauseMenuDrawStatus buf[0x50]→[0x38] hit retail's 224 frame AND its 64/72/80 conv slots, +0.15). Don't grind frame
    size for its own sake; chase real opcode/reg diffs. (Import-undersized/oversized arrays #67/#145 still matter for
    the STRUCTURAL features they unlock — just not for the raw offset cascade.)
157. **IMPORT SWAPPED a callee's PARAM ORDER (int/float groups reversed) → recover from the canonical decl + reorder
    the call.** pausemenu.c imported `drawRect` as `(int w, int h, f32 a, f32 b)` but the real def (track/intersect.c)
    is `(f32 sx, f32 sy, int x, int y)`. The call `drawRect(0x280,0x1e0,lbl,lbl)` and `drawRect(lbl,lbl,0x280,0x1e0)`
    pass the IDENTICAL registers (ABI assigns by type: ints→r3/r4, floats→f1/f2) — but the correct float-first decl
    makes MWCC EMIT the float args first (`lfs f1; fmr f2,f1; li r3; li r4`) matching retail, vs the wrong decl's
    `lfs f1; li r3; li r4; fmr f2` (#137 emission order). Register-neutral, so always safe. METHOD: grep the function's
    REAL signature across the repo (`grep "void drawRect" include/ src/`) — local per-file externs are often the
    floats-last import artifact; the canonical header/def has the true order. (pauseMenuDraw 96.9→97.3.)
    OPEN residuals on pausemenu (clean forms ASSUMED to exist): (1) **fn_8011EF50 call arg-emission order** — retail
    emits the const float args (f1=lbl_803E1E3C, f3=lbl_803DBA38) BEFORE the u16 args (a,b,c); ours emits a,b,c then
    f1,f3. Signature is FIXED (tricky.c defines it u16,u16,u16,f32×4) so #137 reorder is unavailable; the eval-order
    lever for the REMAINING args after the CSE'd computed ones is unfound (appears in every pauseMenuDraw case + status).
    (2) **case-4 inner switch (6/8/10/default) dispatch tree** — retail binary-searches with 3 bge pivots (cmpwi 8/6/10
    + range-bound bge to a skip block); ours collapses to 1 bge. default-FIRST is correct (default-last regressed 97.3→
    95.9); the #13/#144 lever to add the bound checks is unfound. (3) lbl_8031BB90 k-loop walker base `addi r0; mr r6`
    detour (volatile-reg base, call-free loop — the #140 volatile sub-case, index form regressed). (4) i/j and the
    #108 within-class saved-reg permutations (decl-order/swap inert). (5) fn_80127F24 is byte-identical except an
    i↔loop2-x r27/r28 swap (reverse creation-order #108; func-scope shared `s16 x` got 97.95→98.03, decl-order inert).
158. **`s16var = (int)(floatExpr);` emits a SPURIOUS `extsh` before the `sth` — drop the `(int)` cast.** When
    storing a float-derived value into a narrow (s16) lvalue, the explicit `(int)` cast creates an int node that
    MWCC narrows to s16 with an `extsh` BEFORE the `sth` (which already truncates) — a redundant instruction. Writing
    `s16var = floatExpr;` (or `s16var = -(floatExpr);`) lets the float→s16 store emit `fctiwz; …; sth` directly (no
    pre-store extsh), matching retail. The subsequent `(s16)s16var` compare still reuses the stored reg with ONE
    extsh (correct). KEEP the `(s16)` cast on the READ/compare (`if ((s16)s16var > 0xff)`) — removing THAT regresses
    (it's the real signed compare). Only the `(int)` on the float→s16 STORE is spurious. (headdisplay drawArwingHud
    97.86→98.61, two `arwingHudAlpha = (int)(…)` alpha stores.) Generalizes the #20/#53 narrow-store extsh family to
    the float-conversion case. OPEN on drawFn_80125424 (the unit's other fn, 92.66→94.24 via #156 inline+const wave
    consts): a MISSING `extsh r0,r26` on `(f32)alpha` (s16 alpha kept in a saved reg — retail re-extends it, ours
    tracks it as already-extended from the clamp and skips; value-range-tracking diff, clean form unfound); the
    strength-reduced induction init `mr rK,rCounter` (retail copies i=0 into the i*0xd48 / i*0x7d0 reduced vars) vs
    our `li 0` (#136/#110 — opt_level 1 unavailable, call-bearing fn); a waveAmp↔wave f27/f28 FP swap (#82/#121);
    and the #108 GPR rotation. All assumed to have clean forms, not yet found.
159. **RECOVER AN EARLY-RETURN / BLOCK-SKIP BRANCH retail emits when a later block is provably UNREACHABLE on
    this path — the general family; ELSE-RETURN SPLIT is one variant.** Retail emits extra front-end branch(es)
    (`b skip; ...; b end`) that our build FOLDS to a fall-through; the fix is a `return;` placed where retail
    skips a provably-unreachable later block (semantically free → ZERO behavior cost). TWO confirmed variants:
    (A) ELSE-RETURN SPLIT (guard-wrapped body) — below; (B) RETURN-TO-SKIP-MUTUALLY-EXCLUSIVE-BLOCK: two
    SEQUENTIAL mutually-exclusive ifs (`if(active!=0){fade-up} if(active==0){fade-down}`) where retail exits
    (`b end`) after the first block rather than falling through to the second's check — add a `return;` inside
    the first if after its body (the second block provably can't run on this path). (flameguard: dll_02B3
    vortex_update 98.65→100, return after the fade-up clamp.) Both = "spell the early-return retail uses to
    skip a block that can't execute on this path." VARIANT A: When
    an `if (cond) { ENTIRE tail }` wraps the whole function tail (cond-false ⟹ fall through to the end = an
    implicit return) and the target has 2 extra branches our build collapses, split the guard into
    `if (cond) { HEAD } else { return; } TAIL` — HEAD = the part up to where retail emits the branch pair,
    TAIL = the rest, moved OUT of the if. SEMANTICALLY IDENTICAL (the else-return gates TAIL to cond-true
    exactly as the wrapping-if did) but the else-return makes MWCC emit retail's UNFOLDED
    `b skip-else; else: b end(return); skip-else: TAIL` layout instead of folding to a single fall-through.
    The split point = where retail emits the branch pair. This is the #21/#22/#33 family applied to a
    guard-wrapped body — DISTINCT from #150/#151's empty-then clamp fold. DIAGNOSE: a nopeephole/noschedule
    unit that's T=C+2 (or +N) with the missing instrs being consecutive `b`s after a shared block ⟹ pure
    source-structure block-layout artifact; trace the full CFG to confirm the branches are dead/redundant
    (block-layout, not real code), then apply the identity. METHOD: the wrapping-if ≡ if/else-return identity
    reproduces it at ZERO behavior cost. This is the branch-target/block-layout structural bucket's core lever
    — the #151-FREE fns in that bucket are real 99→100s. (flameguard: dll_029C arwarwingbo_update 98.86→100,
    whole unit 10/10 = 100%, flip-ready.)
    SCOPE (pausemenu, verified by score — #159 is variant-A/B SPECIFIC, NOT a generic branch-fold cure): the
    categorizer's "branch-layout" bucket is mostly NOT #159 (many are extsb/lfs/extsh diffs mislabeled), and
    even genuine `bXX;b` vs `bYY` folds only yield to #159 when they ARE variant A (guard wrapping the function
    TAIL) or variant B (two sequential MUTUALLY-EXCLUSIVE ifs). Three OTHER fold shapes RESIST (don't waste
    time forcing #159/#21/#63 on them): (1) MID-FUNCTION guard `if(x!=K){body}` where an inner block FOLLOWS
    the body (not the tail) → #21 inversion is INERT (MWCC normalizes); (2) LOOP jump-to-condition (retail's
    test-first `while`/`for` emits `b cond` first, ours is `do-while`) → do-while→while ADDS the `b` but
    REGRESSES because MWCC's LICM places the loop-invariant consts in the preheader AFTER the `b`, retail has
    them BEFORE (LICM-preheader ordering, separate open puzzle); (3) integer CLAMP `if((u32)x>=K)x=K` →
    ternary/empty-then/inverse-ternary all REGRESS (the folded if-form is retail-closest, #63). So match the
    EXACT variant (tail-wrap or mutually-exclusive-sequential) before applying — the hit-rate on the generic
    bucket is low.
160. **CUSTOM INTERPROCEDURAL STATIC-LEAF REGISTER-ABI — the obvious source levers have been explored; a
    clean form EXISTS (the original Rare source compiled to this) and is the live target — keep hunting.** When
    retail's STATIC leaf helper uses a non-standard ABI — borrows the caller's SAVED regs (e.g. stream ptr
    in/out r20, r21/r22) and RETURNS values in VOLATILES (r10/r12/r15) with NO memory writes — that is MWCC's
    interprocedural register coordination, and the standard C/pragma levers do NOT trigger it (expgfx,
    model modelBoneTransforms_next/modelApplyBoneTransform, evidence-based): (1) struct-return
    `static BoneDelta nx(...)` returning {x,y,z,p} → MWCC GC/2.0 returns a 16-byte struct via a HIDDEN POINTER
    (writes 0/4/8/12(r3), caller passes a stack buffer) — NOT register-return; and the target's `nx` is
    `dont_inline` (real `bl`), so MWCC can't inline-eliminate the buffer → no coordination. Keep-the-call AND
    return-in-registers are mutually exclusive under struct/pointer returns. (2) #99 `optimize_for_size on` +
    `optimization_level 0` REGRESSED (12.1→6.07) and did NOT produce the target's `stmw r14` — the stmw is a
    CONSEQUENCE of the fn using r14-r31 (18 saved regs, which only happens once the custom coordination fills
    them), NOT from optimize_for_size; so #99 is the wrong lever for THIS prologue. OPEN (assumed-reachable,
    per the prime directive — the original Rare source DID compile to this): the source/config form that makes
    MWCC apply interprocedural register-coordination to a real-`bl` static leaf is the next thing to map. LEADS:
    other opt-level/inline-threshold combos that might enable the coordination; whether a tiny return (return
    only p, x/y/z via a different mechanism) partially triggers it; the in-repo/MP4 oracle for a matched fn
    with a static leaf returning in volatiles. The lever is a different shape than struct-return/#99 — those are
    explored, so aim the fresh look elsewhere (the coordination is reachable).
161. **PRE-LOAD byte/halfword fields into locals BEFORE a sequence of volatile GX-FIFO (or other volatile)
    STORES → MWCC hoists the loads into retail's BATCHED-load pattern (hunter in-tree-confirmed, drawGlow
    92.2→92.9).** When a draw/emit fn writes several narrow fields to a volatile FIFO (`*(vu8*)fifo = obj->r;
    *(vu8*)fifo = obj->g; ...`), the volatile stores are emission-pinned in order, but retail BATCHES the source
    `lbz`/`lha` loads up front. Lift each source field into a plain local FIRST (`u8 r=obj->r, g=obj->g; s16
    u=obj->u; ... ; *(vu8*)fifo=r; *(vu8*)fifo=g; ...`) — the non-volatile loads then hoist/batch ahead of the
    store burst, matching the target. Pairs with the width levers (#58/#20: type each local to the field width so
    the load is a bare `lbz`/`lha`, no extsb/extsh). Residual narrow-store `clrlwi`/`extsh` on the volatile
    stores themselves is a peephole-OFF artifact in nopeephole units (peephole-on removes it but regresses the
    fn) — leave it. Sibling of #6/#45 (lift-to-local for hoisting) for the volatile-store-batch case.

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
60-95% partial is OFTEN just a CORRECTNESS bug (a return/store wrongly nested in an `if`, an over-
simplified switch arm, inverted branch sense) — that's great news, it's fixable: diff target's
control flow first, and the rest usually falls into place.
A tiny "4b" header can mask a big recoverable drift-stub body — check `.s` body sizes, not report
sizes.

## Foreign-compiler objects (GCC/SN ProDG — out of MWCC scope)
Signature: `mflr` BEFORE `stwu`, `andi.` for contiguous masks, `mcrxr; addme.` loops, `stmw r14`
bulk saves, creation-order alloc. Confirmed: zlbDecompress (pi_dolphin), gap_03_80006C6C (render).
Don't spend MWCC effort — flag for the owner's foreign-toolchain build-rule path. Compiler-emitted
s64/fixed-point math (`__shl2i`/`__shr2u`, `addc`/`adde`, unrolled rounding loops) → apply #98/#109.

## Paired-single (`psq_l`/`psq_st`) = INLINE-ASM ONLY in CW GC/2.0 — ✅ USER-AUTHORIZED inline asm (narrow exception)
PROVEN (dbgtricky, gate-tested): MWCC GC/2.0 has NO paired-single INTRINSICS — `__PSQ_L(...)` compiles to
`bl __PSQ_L` (a call to an undefined function, NOT the `psq_l` instruction); the compiler binary exposes only
the `psq_l`/`psq_st` MNEMONICS for the inline-asm assembler. Every matched paired-single fn in the repo is
inline asm (e.g. mtx.c `asm void PSMTXCopy(...){ nofralloc; psq_l f0,0(src),0,0; ... }`; model.c GQR setup is
`asm{ mtspr GQR6,v }`). So a fn whose target uses `psq_l ...,W,GQR` (s16/u8→f32 dequant, the GQR-quantized
load) is reachable ONLY via inline `asm{}` (the intrinsic path is confirmed dead — DON'T re-test `__PSQ_L`).
✅ USER-AUTHORIZED (owner decision, overriding the ban for THIS case): use INLINE ASM for the paired-single
`psq_l`/`psq_st` case — match the codebase convention (mtx.c `asm void f(){ nofralloc; psq_l f0,0(src),0,0; ... }`,
model.c `asm{ mtspr GQRn,v }`). This is FAITHFUL (the repo + the original source already do paired-single this
way), NOT a ban violation. IN-SCOPE PS targets (verify each has psq_l/ps_* in the target before diving):
lightmap **fn_8005D3B4 38% / updateVisibleGeometry 83%**, and model.c **ObjModel_TransformVertices{Linear 372B,
WithTranslation 388B, QuadVerticesLinear 692B} — all 0%, UNIMPLEMENTED** (extern-declared + called, no
definition → write the missing defs from the target asm; confirmed psq_l/psq_lu/ps_madds). Method: decode the
target's psq_l stream + ps-SIMD ops (the disassembler may misrender them as VSX), find the GQR setup (a caller,
an init fn, or in-fn — `mtspr GQRn` inline asm authorized too here), write the inline-asm form matching the
target, byte-verify. ⚠️ NOT paired-single (verified, asm exception does NOT apply): **modelBoneTransforms_next
29% + modelApplyBoneTransform 12% = the #160 integer interprocedural-register-ABI** (ptr in/out r20, outX/Y/Z
returned in volatiles r10/r12/r15, caller `stmw r14; mr r20`) — 0 PS instructions; validator/owner-domain, not
asm-eligible. ⚠️ NARROW: this exception is paired-single ONLY — the general inline-`asm{}` ban STILL HOLDS for
everything else (no other exceptions; the owner still reverts non-paired-single asm).

### ✅ PROVEN RECIPE (mechanical — fn_8005D3B4 38→100, ObjModel_TransformVertices{Linear,WithTranslation,QuadVerticesLinear} 0→100 each, model.c +5.74%)
⚠️ TOOLING — CRITICAL: the default objdump / `function_objdump.py` MISDECODES Gekko paired-single as modern
POWER9 VSX (`psq_l`→`lq`, `ps_madds`→`xsmsubmsp`/`xxsel` garbage) — you CANNOT transcribe from it. Use
`build/binutils/powerpc-eabi-objdump -M gekko -drz --disassemble=<fn> build/GSAE01/obj/main/<unit>.o` — the
`-M gekko` flag gives the correct `psq_l`/`ps_*` decode (or decode from the `e0`/`f0`/`10` opcode bytes).
FORM — FULL `asm void`, not a C+asm hybrid: the hybrid (`register f32` + `asm{ psq_l }` blocks + C fmadds)
plateaus ~89% because inline-asm blocks are SCHEDULING BARRIERS (can't interleave loads/fmadds like the target's
scheduler → wrong FP alloc). The full function `asm void Fn(register u8 *m1, ...){ nofralloc; psq_l ...; ...;
blr }` (mtx.c convention) controls exact reg-alloc + scheduling → byte-match. STEPS (proven, ~mechanical):
(1) `-M gekko` dump; (2) `asm void` wrapper with `nofralloc`, HARDWARE reg names, rename args r3→m1.. by the
prologue, SDA refs by symbol name (MWCC auto-emits `@sda21`), `lis r,sym@ha; addi r,r,sym@l` for ADDR16, `bl
symbol` for calls, insert loop labels at `bdnz` targets; (3) build → byte-match. waterfx generated the 173-instr
Quad fn PROGRAMMATICALLY (regex arg-rename + label-insert) → first-build 100%, zero hand-errors. GQR config is
runtime state (set by existing matched OSContext/THPDec/setGQR) — not your concern for the byte-match.
⚠️ VEIN IS MINED — NOT a broad batch (dbgtricky byte-scan + per-fn verify, project-wide): fn_8005D3B4 was the
ONLY genuine missing-psq_l-BODY function (now 100%); the model.c ObjModel_TransformVertices trio were the only
0%-unimplemented PS cluster (now 100%). NO other genuine psq_l-BODY gaps exist: render.o's raw-byte "14 missing"
were DATA false-positives (float tables matching the psq_l opcode), and every other unit (track_dolphin 8=8,
lightmap 5=5, math 1=1) already MATCHES its psq_l. The DISCRIMINATOR that matters: a genuine asm case = TARGET
has `psq_l fX,K(rDATA),W,GQR` BODY loads / ps-SIMD where OURS has the manual `lis 17200; xoris 0x8000` conversion
(fn_8005D3B4's shape). NOT a case: psq_l/psq_st from `r1` (auto FP save/restore — both builds have it; the diff
is coloring, e.g. updateVisibleGeometry 83% = f26-f31 + frame = #82/#67, validator-territory — do NOT brute-asm
it, that abuses the exception to mask a coloring fix). So the recipe above stays for any FUTURE psq_l-BODY fn,
but there is no current batch to grep — the vein is worked out.

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
compare + md5. A local @NNN conversion-bias .sdata2 with no retail TU pool = flip held (the 100%
is yours to keep). Status edits are the team-lead's.

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
  .o caveat). `include_audit.py` / `extern_audit.py` /
  `forward_decl_static_audit.py` — cleanup tools (byte-gated; re-audit before applying saved reports).
- **MP4 oracle:** `mp4_asm_search.py "<pattern>" [--with-c]` — MP4 is 100% matched; find the C that
  produces any asm shape. **In-repo oracle:** grep `build/GSAE01/obj/**/*.o` disasms for a shape,
  read the matched unit's C. **decomp.me corpus:** `discord_search.py <kw>` (lower score = closer to
  match). **Retail ISO forensics** (`orig/GSAE01/*.iso`): OBJECTS.bin/.tab + gResourceDescriptors
  (0x802C6300) map DLL ids → names/units; `dll_boundary_audit.py` / `dll_boundary_resplit.py` for TU
  boundaries.
- **Cleanup verification (match-% only):** the ONLY gate is `report.json` `fuzzy_match_percent` —
  capture a per-function baseline, edit, force-rebuild the unit's `.o` + `ninja report.json`, and
  confirm no function dropped below baseline. Byte-identity is NOT required: renames, struct
  consolidation, duplicate-function removal, and other source restructuring are all fine as long as
  the match % holds (a fn at 100% stays 100%). Don't byte-compare `.text` or chase md5 stability.

## Reference commits
peephole-off mass fix `b7eda753` · drift add-new-fn `aedc9605`/`77438a6f` · u8-vs-char `6863ffe7` ·
`& ~K` rlwinm `782a09a8` · `*(void**)` cmplwi `a42bb90b` · lift-for-CSE `75660758` · decl-swap stack
offset `91f5f4ab` · bitfield rlwimi `a3a86c446`/`34ee540c0` · case-reorder `61dd19936` · int-param
cmpwi `1ebdcf015` · `*(s8*)(p+off)` `b42e26e71`.
