# MWCC GC/2.0 `.sdata2` pool ordering — the complete rule

Derived 2026-07-17 by direct probe against `build/compilers/GC/2.0/mwcceppc.exe` under real DLL
cflags (`-O4,p -inline auto -fp hardware -fp_contract on`, no `-sdata2 0`). Probe sources and the
driver live in the session scratch (`probe/p1.c` .. `probe/p10.c`, `probe/mw.sh`).

## The rule

A TU's `.sdata2` pool is a concatenation of **per-function-definition groups, in source (parse)
order**. For each function *definition*, in the order its body is parsed:

1. every FP literal the body needs that **does not already exist** in the pool is appended, in the
   function's internal codegen order;
2. then the function's **conversion-bias atoms** are appended (after all of that function's own
   literals — never at their first-use position).

Atoms are deduplicated **TU-wide, first creator wins**. The two bias atoms are distinct and are each
created by the first function that needs *that* type:

| bytes | meaning | codegen tell |
|---|---|---|
| `43300000 80000000` | **signed** int -> float bias | preceded by `xoris rX,rY,0x8000` |
| `43300000 00000000` | **unsigned** int -> float bias | no `xoris` |

> Note: this is the opposite of the labelling in `scratchpad/biascensus.py`, which tags
> `...80000000` as "u32" and `...00000000` as "s32". The byte values above are what the disassembly
> proves; treat the script's names as arbitrary tags.

## ★ The corollary that cracks the "anon-ordering anomaly"

**The pool is completely INVARIANT to inlining** (P9 vs P9b) and to linkage (P10). A group is created
at the function's *definition* point, period.

The disappearing `.text` is a **two-stage** effect — get the division of labour right:
1. **MWCC always emits the out-of-line body of a `static`**, even when it inlined it at every call
   site, and even when it is never called at all (P5). The `.o` always has the function.
2. **`mwld` dead-strips it at link** once nothing references it. So it is absent from the DOL, and
   therefore absent from the dtk-split "retail" `.o` we diff against.

⇒ **The retail `.text` is NOT the list of pool groups.** A fully-inlined `static` helper owns a pool
group at its definition position but has no function in the DOL. (Verified end-to-end: crrockfall's
recovered `crrockfall_isPlayerInRange` is present in our `.o` and absent from the linked DOL, which
still checksums `main.dol: OK`.)

★**Practical consequence for the gate:** an "EXTRA in ours" function in an `.o`-level comparison is
*expected and correct* for a recovered ghost helper. Gate on `ninja build/GSAE01/ok` + `report.json`,
never on `.o` symbol-set equality.

**DISCRIMINATOR — how to spot a ghost group.** An atom that is
- pooled *ahead of* the first `.text` function's own atoms, or
- pooled *between* two `.text` functions' groups but first-used only by a *later* function,

is not an ordering mystery: it is an **inlined `static` helper defined at that point in the file**.
The later functions merely *reuse* the atoms (dedup, first creator wins). Read the ghost group's
values in order — they are the helper's literals in the helper's own parse order, and they will
appear as one contiguous inlined cluster somewhere in a caller's body.

## ★ Literal *numbering* order INSIDE one function's group

The group rule above says a function's new literals are appended "in the function's internal codegen
order". That order is **not** the order the `lfs`/`lfd` instructions come out, and the difference is
exactly what strands an otherwise-finished pool. The `@NNN` anon-symbol index in a `-drz` dump *is*
the numbering order — read it directly instead of guessing from emission.

Derived 2026-07-17 by probe (`probe/q*.c`, `probe/w*.c`, `probe/y*.c`, `probe/z*.c`; driver
`probe/mk.sh`). Four rules, in precedence order:

1. **Across statements: source order** — but if MWCC *sinks* a statement (its result is only consumed
   later), the numbering follows the **sunk** position, not the written one.
   `y=2.0f*x; o2=3.0f*x; o3=4.0f*x; o1=y;` pools `3.0, 4.0, 2.0` — `y=2.0f*x` sank to just above
   `o1=y`, and its literal sank with it.
2. **Within one statement, no calls: pre-order DFS of the *canonicalised* tree.** Commutative
   operators put the constant operand first, so `x*3.0f + 2.0f` canonicalises to `2.0f + 3.0f*x` and
   pools `2.0, 3.0` (this is the doc's old `x * 100000.0f + 20.0f -> 20, 100000` result).
   Division is not commutative: `(2.0f*x)/3.0f` pools `2.0, 3.0`.
3. **★ Literals inside a CALL's argument subtree are numbered AFTER every other literal in the same
   statement**, outermost-first by nesting depth. `ff(2.0f) + 3.0f` pools `3.0, 2.0`;
   `ff(2.0f)*3.0f + 4.0f` pools `4.0, 3.0, 2.0`; `ff(ff(2.0f)+3.0f)+4.0f` pools `4.0, 3.0, 2.0`.
4. **`if` / `?:` arms are numbered BEFORE the controlling condition** (then-arm, else-arm, cond).
   `y=2.0f; if (x>3.0f) y=4.0f;` pools `2.0, 4.0, 3.0` while *emitting* `2.0, 3.0, 4.0` — a genuine
   inversion of numbering vs emission, confirmed by `@7=2.0, @8=4.0, @9=3.0`.

**⇒ The diagnostic.** An atom that pools *earlier* than an atom it is *emitted after* is not noise and
not a ghost: rules 3 and 4 are the only two constructs that invert numbering against emission. Read
which one fits and you have recovered the original statement shape.

5. **★ A sunk statement is `IroPropagate`, and the mechanism tells you what blocks it.** Rule 1's
   "if MWCC *sinks* a statement" clause is not scheduling (these DLLs compile `-opt noschedule`) — it
   is **copy/expression propagation**: a local whose *sole* use is later has its whole defining
   expression propagated down to the use site, and its literals number at the **sunk** position.
   Proven by `-opt nopropagation`, which restores the un-sunk numbering exactly.
   ⇒ **The blocker is aliasing.** An operand loaded from an `extern`/global cannot move across an
   intervening call, so the statement stays put. This is why a pool can look plausible while the
   source still spells `extern f32 lbl_*` and **rotates the moment you literalise it** — the shim was
   doing the pinning. Levers that restore the un-sunk order (probed under `-O4,p -opt
   nopeephole,noschedule`): `volatile` local, a second use of the local, `*(f32*)&local = expr;`,
   `#pragma opt_dead_assignments off`. ★All four cost `.text`, and a plain non-`const` named local
   does **not** work here (it const-props straight back — this is a *different* failure from the
   literal-hoist regression the named local does fix). If none is free, the statement genuinely was
   not sunk in retail and an operand was a real memory reference — re-read the shape, don't force it.
   Worked case: `dll_0049_cameramodecombat.c::CameraModeCombat_update`, `zoom = (f32)(s32)(9000 -
   diff) / 9000.0f;` immediately above an `interpolate()` call — pools `35, 0.04, 9000` as a literal
   and `9000, 35, 0.04` (= retail) as an extern or under `opt_propagation off`.

### Worked confirmation — effect20 (`dll_002D_effect20.c`, pool `803E0310..04D8`), 2026-07-17
Retail pools `0.005f, pi, 32768.0f` but **emits** `pi (+0x780), 32768 (+0x7a4), 0.005 (+0x7e0)`.
Source with a `angle`/`trigVal`/`radius` temp per statement pools `pi, 32768, 0.005` — statements are
independent, so rule 1 applies and no spelling of the expressions can fix it (all of
`3.1415927f*(f32)iv/32768.0f`, `(3.1415927f*(f32)iv)/32768.0f`, hoisted `const` locals and decl-inits
are inert; a `const` local is const-propagated and its literal is created at the *use*, not the decl).
Rule 3 is the only fit: the angle expression must sit **inside the `mathCosf()` argument** while the
`0.005f` factor sits outside it, so that `0.005f` numbers first and `pi`/`32768.0f` — as call-argument
literals — number last, while still *emitting* pi first because the call is evaluated first:

```c
cfg.velocityX = (0.005f * (f32)(s32)randomGetRange(100, 0x96)) *
                mathCosf(angle = (3.1415927f * (f32)(s32)intVal) / 32768.0f);
cfg.velocityY = (0.005f * (f32)(s32)randomGetRange(100, 0x96)) * mathSinf(angle);
```
456-byte pool byte-exact, `.text` unchanged at 33024/33024.

## ★ TRAP: objdiff `.text` 100% does NOT mean the linked bytes match (`@sda21`)

`lfs f1, sym@sda21(rX)` is a **relocation** in the `.o`: the base register and displacement fields are
both zero until `mwld` fills them. Two loads that differ only in *which* `@sda21` symbol they name —
`.sdata` (r13) vs `.sdata2` (r2), or two different pool atoms — can therefore be scored **100%
identical** by objdiff and still move the DOL.

effect20 read `.text 100.0000 (33024/33024)` with `gEffect20SpawnScrollA = gEffect20SpawnScrollA +
0.001f;` **and** with `gEffect20SpawnScrollA += 0.001f;`, yet only the compound form links:
MWCC canonicalises a commutative `+` constant-first (rule 2), which swaps the two loads —

| | retail / `+=` | `x = x + k` |
|---|---|---|
| | `lfs f1, gScrollA@sda21(r13)` | `lfs f1, 0.001@sda21(r2)` |
| | `lfs f0, 0.001@sda21(r2)` | `lfs f0, gScrollA@sda21(r13)` |

— same `fadds f1,f1,f0`, same fuzzy score, 4 different instructions in the DOL. **A pool claim must be
gated on `ninja build/GSAE01/ok`, never on the unit's fuzzy percent.** Corollary: use the compound
form for any accumulator whose RHS mixes the accumulator with a constant.

## ★ The bias is a GROUP TERMINATOR — the strongest boundary discriminator

Re-probed 2026-07-17: a function's conversion biases are appended after **all** of that function's
literals, even when the conversion is codegen'd in the *middle* (`gA = x*2.0f; gB = (float)n;
gC = x*3.0f;` pools `2.0, 3.0, sbias`, **not** `2.0, sbias, 3.0`), and with both bias types present
(`2.0, 3.0, sbias, ubias`). The next function's literals then follow the bias (`... sbias │ 5.0`).

⇒ **An atom that sits AFTER a group's bias belongs to a LATER group. No exceptions.** This reads
group boundaries straight off the bytes, and it is often the only way to separate a ghost's extent
from its caller's: ghosts and callers share atoms by dedup, so the first-use "owner" map cannot.

Worked example — `dll_0271_drakorhoverpad.o`, pool `803E6A38..6AA0`:
```
6A38 2.0 │ 6A3C 0.0  6A40 10 │ 6A44 5.0 │ 6A48 1.0
6A4C 300 │ 6A50 0.01 │ 6A54 pi │ 6A58 32768 │ 6A5C pad │ 6A60 SBIAS │ 6A68 UBIAS
6A70 -1.0 │ 6A74 -2.0 │ 6A78 0.8 ...
```
`-1.0` is referenced by **only** `drakorhoverpad_update` (at its `+0xc00`), yet it pools *after* the
biases that appear to terminate update's group. The naive reading ("update owns `pi..UBIAS` and
`-1`") is therefore impossible. The bias rule forces the correct one: `{300, 0.01, pi, 32768, SBIAS,
UBIAS}` is **one ghost group** — a static defined between `func0F` and `update` that does both a
signed and an unsigned int->float conversion, inlined into `updateMain` (which is what first-uses
300/0.01). `update` is defined *after* it, so update's `pi`/`32768`/bias uses are plain **dedup
hits**, and update's own group is just `{-1.0}`. Without the bias rule this unit reads as an
unexplainable rotation.

## Probe matrix

`H` = `static float helper(int n){float f=(float)n; if(f<0.0f)f=0.0f; if(f>300.0f)f=300.0f; return f*4.0f;}`
(literals `0.0, 300.0, 4.0` + a **signed** bias). `A` uses `100000.0, 20.0`; `B` uses `7.0`;
`C` calls `H` and uses `350.0`.

| # | TU shape | resulting pool | verdict |
|---|---|---|---|
| P1 | `H, A, B, C` | `0.0 300 4.0 _ sbias │ 20 100000 │ 350` | H's group leads the pool, at its parse pos |
| P2 | `A, H, B, C` | `20 100000 │ 0.0 300 4.0 _ sbias │ 7.0 │ 350` | group moves with the **definition** |
| P3 | `A, B, H, C` | `20 100000 7.0 │ 0.0 300 4.0 sbias │ 350` | ditto |
| P4 | fwd-decl `H`; `A, B, C, H` | `20 100000 7.0 350 │ 0.0 300 4.0 _ sbias` | position = **body**, not the declaration |
| P5 | `A, H(never called), C` | identical to P2 | ★ uncalled static still emits `.text` and still pools its group — pool position is decided at parse, use is irrelevant |
| P6 | `H(sbias), A(ubias), C` | `4.0 _ sbias │ 100000 _ ubias │ 350` | ★ **kills the alignment-bucket hypothesis**: 8-byte biases interleave *between* groups, they are not bucketed to the front |
| P7 | `H(ubias), A, C(sbias)` | `4.0 _ ubias │ 100000 350 sbias` | reproduces crrockfall's exact shape |
| P8 | `A(uses 4.0), H, C` | `100000 4.0 │ 0.0 _ sbias │ 350` | dedup: **first creator wins**; H's group shrinks to `{0.0, sbias}` |
| P9 | `H, C` under `-inline off` | `0.0 4.0 sbias │ 350` | identical to `-inline auto` |
| P9b | `H, C` under `-inline auto` | `0.0 4.0 sbias │ 350` | ★ **pool is invariant to inlining** |
| P10 | `H` non-static, `C` | `0.0 4.0 sbias │ 350` | linkage is irrelevant; only definition order matters |

### Hypotheses tested and REFUTED
- **Alignment bucketing** (8-byte atoms emitted as a leading subpool): **dead** — P6.
- **First-use order across the TU**: **dead** — crrockfall's `1.0` is first-used at `update+0x1d0`,
  before `0.0` at `+0x1e4`, yet `0.0` pools 0x20 bytes *earlier*.
- **Bias placed at its first-use position**: **dead** — P1..P10 all append it after the group.
- **Textual parse order *within* one expression**: **dead** — `x * 100000.0f + 20.0f` pools
  `20, 100000` (P2/P8). Within a function the order is codegen order; "parse order" only holds
  reliably *across* statements.

## Worked confirmations against retail

### crrockfall (`dll_016A_crrockfall.o`, pool `803E46E8..4734`)
`.text` order: `fn_801ACCFC, getExtraSize, getObjectTypeId, free, render, hitDetect, update, init,
release, initialise`.

```
803E46E8 0.0 │ 46EC 4.0 │ 46F0 300.0 │ 46F4 pad │ 46F8 UBIAS   <- ghost group (mwld-stripped fn)
803E4700 100000 │ 4704 20.0                                    <- fn_801ACCFC
803E4708 1.0                                                   <- crrockfall_render
803E470C 350 │ 4710 250 │ 4714 100 │ 4718 120 │ 471C 255 │ 4720 -0.15 │ 4724 pad │ 4728 SBIAS
                                                               <- crrockfall_update (+ its own sbias)
803E4730 127.0                                                 <- crrockfall_init
```
Everything from `4700` on is exactly first-use-in-`.text`-order. The head group is a **static
predicate helper defined at the top of the file**, inlined once into `crrockfall_update` at
`+0x340..0x38c` — visible as one contiguous cluster using `0.0f`, then `4.0f`, then an unsigned
`(float)u8` conversion, then `300.0f`, in exactly the pool's order. In the current source that
cluster is hand-inlined at `dll_016A_crrockfall.c:260-284` (`int inRange; ...`).

### hoodedzyck (`hoodedzyck.o`, pool `803E2B18..2B7C`)
**Two** ghost groups ahead of `fn_80156DA0`'s own group:
```
2B18 0.0 │ 2B1C pad │ 2B20 UBIAS                        <- ghost group #1
2B28 -65535 │ 2B2C 32768 │ 2B30 65535 │ 2B34 -32768     <- ghost group #2 (an angle/s16 wrap helper)
2B38 10.0 │ 2B3C 5.0 │ ...                              <- fn_80156DA0
```
Proof they are ghosts: ghost #2's atoms are first-used by `hoodedZyck_updateB` in the order
`32768(0x23c), -65535(0x248), -32768(0x250), 65535(0x25c)` — a *different* order from the pool, so
`updateB` cannot be their creator.

### drearthwarrior (`dll_0257_drearthwarrior.o`)
Ghost group at `803E8310..8320` (`0.02, 2.0, 0.5, 0.75, 32768.0`), parsed between `fn_802BC830`
(group ends `830C`) and `fn_802BCA10` (group `8324..8338`); first-used only by the *later*
`stateHandler03`/`stateHandler02`. A second ghost sits below `82E8` (`fn_802BCA10` first-uses `82E0`,
which is lower than the first `.text` function's `82E8`). The census's "8310 is lower than 8324"
anomaly is exactly this rule.

## Practical consequences
- **Do not read a pool as a per-`.text`-function map.** Count groups, not functions. A group with no
  `.text` owner ⇒ recover an inlined `static` helper defined at that point.
- This is *not* a merge/redraw signal. A ghost group is one TU's own helper; it does not imply a
  second TU. The merge tell remains a **shared atom** across carves.
- To land such a pool, the refactor is: hoist the hand-inlined cluster into a `static` helper defined
  at the ghost's position and call it. Inlining is pool-invariant (P9), so if MWCC re-inlines it to
  the same bytes the `.text` is preserved by construction and the pool falls into place. Let `mwld`
  strip the out-of-line copy — do not fight it with pragmas (`always_inline` was inert on crrockfall).
- **Fn order must be fixed first** (census law). crrockfall's source order was completely different
  from retail's; the reorder is byte-neutral but the pool cannot be read until it is right.
- Bias atoms are per-type and TU-wide; a second bias in a carve means a second *type*, not a second
  TU (already in the census).

## ★ `.text` discriminates LITERAL vs NAMED-CONST DEF — the hoist is the tell

Pool bytes cannot tell a literal from a `static const` def: both put the same 4 bytes at the same
slot. **`.text` can**, and the discriminator is one observable:

| spelling | compare canonicalisation | load placement |
|---|---|---|
| plain literal `2.0f` | **const-first** (`fcmpu frA=const`, either source order) | **hoisted to the head of the basic block that dominates all its uses** |
| `f32 k; k = 2.0f;` (non-const local) | **none** — `frA` = the syntactic LHS | at the use, *only when written as the RHS* |
| `static const f32 g = 2.0f;` + **`*(f32*)&g`** | none — `frA` = the syntactic LHS | **at the use**, always |
| `static const f32 g = 2.0f;` + bare `g` | const-first | hoisted — **and it emits TWO atoms** (the def *and* a re-folded literal) |

⇒ **If retail materialises a constant at its use and canonicalises the compare const-first, it is a
named `const` def read through a cast-deref — no other spelling produces that pair.** The literal
hoists; the non-const local loses the canonicalisation. This is the `.text`-level twin of Rule B: a
cast-deref const *is* a memory reference, so it reproduces exactly what the `extern f32 lbl_*` shim
was doing — which is why the pre-respell source matched while every literal spelling rotates.

★**Corollary — the hoist is the whole bug, the operand order is a symptom.** A hoisted literal stays
live across an intervening diamond, so it *interferes* with the condition's constant and is pushed one
register up (`f0`->`f1`), which swaps the two `fcmpu` operand fields even though the semantics are
identical. Fix the placement and the registers fall out; do not chase the operand order directly.
★**Cheap probe**: a 6-line standalone `.c` under the unit's real cflags reproduces this in <1s. Do it
before sweeping the real unit — the real-file loop is ~4s a variant and decl-order sweeps are inert.

### Worked confirmation — drakorhoverpad (`dll_0271_drakorhoverpad.c`, pool `803E6A38..6AA0`), 2026-07-17
The bias rule's worked example above is correct and lands byte-exact on the first compile. Two ghosts,
both defined between `setScale` and the `#pragma dont_inline on` window (i.e. between `func0F` and
`update`, as the bias forced):
- `drakorhoverpad_initPathCurve(obj, p)` — group `{300.0f, 0.01f}`: the `initCurve(...,300.0f,...)` +
  `Curve_AdvanceAlongPath(...,0.01f)` attach, inlined into `updateMain`'s activate arm.
- `drakorhoverpad_nodeWobbleSin/Cos(slot, angle)` — group `{pi, 32768.0f, SBIAS, UBIAS}`: the per-node
  bob `2.0f * ((f32)(u32)node->tangentMag * mathSinf(pi * (f32)(angle<<8) / 32768.0f))`, **duplicated
  verbatim at 12 sites** in `update`. It is the file's only source of BOTH biases (signed `angle<<8`,
  unsigned `tangentMag`) — which is exactly why the bias pair sits in *its* group and `update`'s own
  group is just `{-1.0f}`. The Cos twin adds no atoms (dedup) and so is invisible to the pool.
- ★**Take the SLOT, not the node** (`DrakorCurveNode** slot`): retail re-reads the node pointer either
  side of `mathSinf` (an intervening call kills the CSE). A `DrakorCurveNode*` param is evaluated once
  at the call site into a saved reg and costs `.text`. This is the caller-holds-it test from the
  parameter rule, resolved the *other* way: the caller does **not** hold it across the call.
- ★**`gDrakorHoverpadPi`/`gDrakorHoverpadAngleScale` were referenced by NOTHING once literalised** —
  a pool atom with zero users tree-wide is the strongest ghost tell there is (an *uncalled* ghost).
  Here they had users, and the users' clusters read the helper's body straight off.
- Post-literalisation repairs: `limit = limit + K` -> the accumulator-first form is **wrong** here
  (`K` is the const def, so no canonicalisation to undo — keep `limit = limit + *(f32*)&g`); `*= 0.5f`
  on an alias-opaque `*(f32*)p` **reloads** instead of reusing the CSE'd local (a cast-deref store is
  alias-opaque), so keep `cur * half` with a non-const `f32 half` local.

Claim `.sdata2 [0x803E6A38, 0x803E6AA0)`; pool **byte-exact (104 B)**, all 29 retail functions
byte-exact. Gated in an origin clean-room on `ed0550d779`: `main.dol: OK`, complete_units **842 ->
843**, matched_data 1179495 -> 1179599 (**+104 B**), complete_code +7176, **matched_code FLAT**
(2414780).

## ★ THE PARAMETER RULE — reassigning a param forces the ARG to materialise at the call site

When MWCC inlines a helper, an argument that is used **exactly once and never written** is not
evaluated at the call at all: `IroPropagate` substitutes the argument *expression* into the body and
the load lands wherever the body happens to need it. Retail's shape is often the opposite — the arg
is loaded first, into its own register, and stays live across the body's early code.

The switch is whether the parameter is **an lvalue the body assigns to**:

| helper body | codegen at an inlined call site |
|---|---|
| `return tbl[(timer >> 1) & 3];` (param read once) | arg load **sunk into the body**, folded into the use, reusing `r0` |
| `timer = (timer >> 1) & 3; return tbl[timer];` | arg load **emitted at the call**, held in its own reg across the body |

A written parameter cannot be propagated (its value is no longer the caller's expression), so MWCC
must give it a home and fill it before the body runs. Cost: **zero instructions** — the assignment
folds into the existing shift/mask.

⇒ **The tell:** ours computes the argument late and reuses the scratch register; retail computes it
first and parks it in a *different* register across intervening code. That register split is the
signature — a rotated arg register is not a colouring cap, it is a propagated parameter.

★This is the counterpart of the granularity rule. Shrinking the ghost cannot reach it (the body's own
locals are re-coloured after inlining, so decl-order sweeps inside a ghost are inert), and neither can
any call-site spelling: `int t = st->timerFA; f(t);` and `u16 t = ...;` are both propagated straight
through. **The lever lives in the callee's parameter list, not in the caller and not in the pool.**

### Worked confirmation — ktrex (`dll_0250_ktrex.c`, pool `803E67B0..6854`), 2026-07-17
**Two** ghosts, and the second one owns a *single* literal — proof that a ghost group can be one atom
wide and still be the only thing standing between a finished pool and a rotated one:

```
803E67B0  02080104                      <- ghost #1: ktrex_getLaneMaskForTimer (a LOCAL ARRAY IMAGE)
803E67B4  0.1                           <- ghost #2: ktrex_hasLaneLerpOvershot (ONE atom)
803E67B8  0.0 │ 67BC 50.0 │ 67C0 0.3    <- ktrex_spawnRandomEnergyArc
803E67C4  ...                           <- exactly first-use-in-.text order from here on
```
- Ghost #1's group is a **`u8 laneMasks[4] = {2,8,1,4}` init image**, not a float — `.sdata2` holds
  non-float data, and an atom is only a float if every access is `lfs`/`lfd`. Here `lwz`+`stw` to a
  stack slot proves a memory copy of a local array template. First-used by `update` (`.text` +0x331C,
  the second-to-last function) yet pooled at the **head** ⇒ a genuine inversion ⇒ ghost.
- Ghost #2 was the last unknown: `0.1f` pools *second* but `spawnRandomEnergyArc` (the first `.text`
  function to touch it) emits it **third**, after `0.0` and `50.0`. Rules 3/4 cannot reach it — the
  three atoms are in *separate statements*, and `0.1f`/`0.3f` are both arguments of the **same**
  `lightningCreate` call yet are split around `0.0`/`50.0`. Only a group boundary explains it. The
  ghost is the `u8`-returning lane predicate hand-inlined in `stateHandlerA02` (`u8 result;` + `goto
  haveResult`, the crrockfall `int inRange;` signature) — `(laneLerpT - laneFrac) > 0.1f` with the
  operands swapped on `timerFA & 1`. It owns `0.1f`; `spawnRandomEnergyArc`'s group is then plainly
  `{0.0, 50.0, 0.3}` in emission order, and the whole 164-byte pool falls out byte-exact.
- ★**Both ghosts sit above `.text` fn0** (`shouldAdvanceArenaPhase`), which pools **no atoms** and is
  therefore transparent — a group boundary can hide behind an atom-less function, so "the first
  `.text` function" is never a safe anchor for where the pool head belongs.
- Post-literalisation repairs, one per class, all three from the tables above:
  `point1[1] = point1[1] + 50.0f` -> **`+=`** (the `@sda21` trap: const-first canonicalisation swaps
  the two loads at fuzzy 100); `bobPhase != 0.0f` -> a **non-const `f32 zero` local** (retail keeps the
  placement *and* the field-first compare — the literal hoists, `static const`+cast-deref regressed
  `init` too); and the parameter rule above for `update`.

Claim `.sdata2 [0x803E67B0, 0x803E6854)`; pool **byte-exact (164 B)**, all 40 retail functions
byte-exact (relocs resolved, branches normalised). Gated in an origin clean-room on `d34db1bf46`:
`main.dol: OK`, complete_units **850 -> 851**, matched_data 1179875 -> 1180039 (**+164 B**, 97.4471 ->
97.4610), complete_code 1429316 -> 1444424 (49.8374 -> 50.3642), **matched_code FLAT** (2413564).

★**Gate hygiene note.** A per-function `.text` comparator MUST normalise branch targets to
fn-relative offsets: a recovered ghost adds a function to *our* `.o` and shifts every later function's
address, so raw `-drz` output diffs on every `b`/`bl`/`beq` operand. Un-normalised, this unit read
"7/40 identical, 21 regressions" when it was in fact **36/40 with 16 real instructions**, and the
three genuine bugs were buried under ~600 lines of phantom diff. Resolve pool atoms *and* named
`.sdata2` symbols (`gKTRexLaneThreatHalfWidth` = `POOL+0x8C`) to pool offsets on both sides too, or
byte-identical functions read as broken.

## ★ NAMED CONST DEFS sit at their DECLARATION position — and need EXTERNAL linkage to survive

A file-scope `const` **definition** is not a codegen anon: it is data the front end emits, and it is
**not** deduplicated against the literal pool (collectible carries `40400000` twice — once as
`sCollectiblePathWord[0]`, once as an anon `3.0f`). Two rules govern it, both probed on dimsnowhorn1:

1. **Position = the declaration's position in the file**, interleaved among the function groups exactly
   like a group of its own. Defs are **not** bucketed to the head of the pool. collectible's defs lead
   its pool only because they are declared above every function; a def written *below* the last
   function pools *after* the last function's group.
2. **An unreferenced `static const` is dropped entirely** — MWCC emits nothing. To reproduce a def
   that no `.text` references, it must have **external linkage** (`const f32 gFoo = 0.0f;`), which the
   front end must emit whether or not anything uses it. (`__declspec(section ".sdata2")` is equivalent
   here and unnecessary — plain external-linkage `const` already lands in `.sdata2`.)

★**THE DIAGNOSTIC — a duplicate value is PROOF of a def.** Literals dedup TU-wide, first creator wins,
so **one value can never occupy two anon slots**. An atom whose bytes equal an atom already in the
pool is therefore *not* a literal and *not* a ghost's literal: it is a **const def**, and its slot
tells you which line of the file declared it. Combined with rule 2, an atom that duplicates an earlier
value **and has zero users tree-wide** is an external-linkage `const` whose only use was
const-propagated away — exactly the "bare `const` re-folds and emits TWO atoms" row of the
literal-vs-named-const table, seen from the pool side.

### Worked confirmation — dimsnowhorn1 (`dll_0256_dimsnowhorn1.c`, pool `803E8230..82C0`), 2026-07-17
The pool is bracketed by a def at each end and holds one ghost in the middle:

```
803E8230  01010101                  <- DEF: static const u32 sDIMSnowHorn1PathFlags[1] (declared at top)
803E8234  0.0 │ 8238 0.013 │ 823C 0.9        <- stateHandler0B
803E8240  ... 826C │ 8270 SBIAS               <- stateHandler0A (+ its bias, appended after)
...
803E82A4  0.14 │ 82A8 -4.0                    <- fn_802BB4B4
803E82AC  -30.0 │ 82B0 -20.0                  <- GHOST: DIMSnowHorn1_updateOverridePos
803E82B4  10000.0                             <- DIMSnowHorn1_update
803E82B8  0.17                                <- DIMSnowHorn1_init
803E82BC  0.0                                 <- DEF: const f32 gDIMSnowHorn1ZeroOffset (declared at BOTTOM)
```
- The **head** atom `01010101` is non-float (`lwz`+`stw` to a stack slot, then `addi rN,r1,8` passed as
  an out-param — a memory copy, not an `lfs`). It is first-used by `init`, the second-to-last
  function, yet pools at the head. It is **not** a ghost's local-array image: MWCC will not inline a
  helper whose local's address escapes into a call, so such a ghost would stay in `.text`. It is a
  file-scope def, and `init` simply reads it (`int stk = sDIMSnowHorn1PathFlags[0];`) — the
  `collectible` spelling.
- The **tail** `0.0` duplicates `803E8234` ⇒ by the diagnostic above it cannot be a literal ⇒ def,
  declared below `initialise`, external linkage (a `static const` there compiled to nothing).
- The **ghost** is forced by a rule-1 inversion that no spelling of `update` can reach: `10000.0f`
  (an `if` condition at `update+0x270`) is *emitted* long before `-30.0f`/`-20.0f` (arguments of a
  `Matrix_TransformPoint` at `update+0x59c`), yet pools *after* them. Separate statements, so rules
  3/4 do not apply and rule 1 demands source order — the only fit is that the `-30/-20` statement
  belongs to an **earlier group**. Hoisting the trailing model-override block (`v`/`matrix` locals +
  `setMatrixFromObjectPos` + `Matrix_TransformPoint`) into a `static` defined between `fn_802BB4B4`
  and `update` gives `update` the group `{10000}` and lands the pool byte-exact on the first compile —
  the helper's address-taken locals are no obstacle here because they never escape *its* frame.

144-byte pool byte-exact, all 39 retail functions byte-exact, `.text` unchanged.

## Landed

- **dimsnowhorn1** (`dll_0256_dimsnowhorn1.c`), 2026-07-17: 31 `extern f32 lbl_803E82*` /
  `gDIMSnowHorn1Gravity` shims -> literals; recover the pool's two **const defs** (head
  `static const u32 sDIMSnowHorn1PathFlags[1] = {0x01010101}` read at `[0]` by `init`, tail
  external-linkage `const f32 gDIMSnowHorn1ZeroOffset = 0.0f` below `initialise`) and one **ghost**,
  `DIMSnowHorn1_updateOverridePos` (the trailing `setMatrixFromObjectPos` +
  `Matrix_TransformPoint(matrix, 0.0f, -30.0f, -20.0f, ...)` block, hoisted above `update`; it owns
  `{-30, -20}` and leaves `update` holding `{10000}`). Claim `.sdata2 [0x803E8230, 0x803E82C0)`; pool
  byte-exact (144 B), all 39 retail functions byte-exact. Gated in an origin clean-room on
  `d34db1bf46`: `main.dol: OK`, complete_units **851 -> 852**, matched_data +144 B, complete_code
  +10576, **matched_code FLAT**.
- **ktrex** (`dll_0250_ktrex.c`), 2026-07-17: recover **two** ghosts —
  `ktrex_getLaneMaskForTimer` (owns the `u8[4]` lane-mask init image at the pool head) and
  `ktrex_hasLaneLerpOvershot` (owns the single `0.1f` atom, hand-inlined in `stateHandlerA02`) — plus
  the parameter rule on the first, `+=` on the arc y-offset, and a non-const `zero` local in `render`.
  34 `extern f32 lbl_803E67*` shims -> literals. Claim `.sdata2 [0x803E67B0, 0x803E6854)`; pool
  byte-exact (164 B), all 40 retail functions byte-exact. Gated in an origin clean-room on
  `d34db1bf46`: `main.dol: OK`, complete_units **850 -> 851**, matched_data 1179875 -> 1180039
  (+164 B, 97.4471 -> 97.4610), complete_code 1429316 -> 1444424 (49.8374 -> 50.3642),
  **matched_code FLAT**.
- **sctotembond** (`main/dll/SC/dll_01BB_sctotembond.c`), 2026-07-17: ghost
  `sc_totembond_beginOrbGame(obj, state)` = the whole `START_ORBS` event block, hand-inlined into
  `update`; group `{-130.0f, 30.0f}` (the `spawnGameBitOrbs` radius arg, then `spawnTimer`) pooled
  ahead of `spawnGameBitOrbs`'s own `{pi, 32768, sbias}`. Defined above the file's `#pragma
  dont_inline` window so it re-inlines byte-identically. Plus 11 `extern f32 lbl_803E5*` -> literals
  and a named non-`const` `f32 zero` local in `update` (inline `0.0f` hoists to the front of the
  compare; retail loads the field first). Claim `.sdata2 [0x803E5638, 0x803E5664)`, pool byte-exact
  (44 B). Clean-room on `c164ff5698`: `main.dol: OK`, complete_units 815 -> 816, matched_data +44 B,
  **matched_code FLAT**.

- **effect20** (`dll_002D_effect20.c`), 2026-07-17: recover `case 0x7a3` as a call-argument shape
  (rule 3 above) + `+=` on the two scroll accumulators (the `@sda21` trap above) + claim
  `.sdata2 [0x803E0310, 0x803E04D8)`. Pool reproduced **byte-exact** (456 B). Gated in an origin
  clean-room on `6e9e1719a4`: `main.dol: OK`, complete_units **800 -> 801**, matched_data_percent
  97.1592 -> 97.1968, complete_code_percent 43.1365 -> 44.2880, **matched_code FLAT**.
- **crrockfall** (`dll_016A_crrockfall.c`), 2026-07-17: fn reorder to retail `.text` order
  (byte-neutral) + hoist `crrockfall_isPlayerInRange` (the ghost) above `fn_801ACCFC` + respell all
  11 `extern f32 lbl_803E4*` / `gRockfallGravity` / `gRockfallScaleDivisor` shims to plain literals +
  claim `.sdata2 [0x803E46E8, 0x803E4734)`. Pool reproduced **byte-exact**. Gated in an origin
  clean-room on `476b2f4d80`: `main.dol: OK`, complete_units **774 -> 775**, complete_code
  1104044 -> 1105904, matched_data 1173295 -> 1173371 (+76 B = the 0x4C pool), **matched_code FLAT**.
## ★ `-O0` / `cflags_dll_noopt` numbering is BYTE-IDENTICAL to `-O4,p` — there is no separate `-O0` rule

Everything above was derived under `-O4,p`. The DLL "noopt" units (`cflags_dll_noopt` = `-O4,p`
**plus** `-opt nopeephole,noschedule`; used by `curves.c`, `voxmaps.c`, `pad.c`, all the `DIM`/`SC`/
`SH` DLLs, etc.) were suspected to pool by a different, "interleaved" rule. **Probed 2026-07-17
(`probe/mwboth.sh`, `probe/t1.c`, `probe/dd.c`) — they do NOT.** The `.sdata2` pool is bit-for-bit the
same under `-O4,p` and under `-O4,p -opt nopeephole,noschedule` for every construct tested:

| probe | `-O4,p` pool | `noopt` pool | verdict |
|---|---|---|---|
| `t1.c` (sink `o1=y`; `if`-arm; call-arg; commutative `x*10+11`) | `4 2 3 5 7 6 9 8 11 10` | **identical** | rules 1–4 all hold |
| `dd.c` (declspec `.sdata2` def `3.0` + a later literal `3.0`) | `3.0(def) 7.0(def) 5.0 3.0 7.0` | **identical** | literal does **not** dedup against a def under either |

The peephole and scheduling passes run **after** constant-pool assignment, so turning them off cannot
move an atom. Treat the entire document above as the `-O0` rule verbatim: per-function-definition
groups in source order, TU-wide literal dedup (first creator wins, **never** against a named def),
bias as group terminator, named defs at their declaration position, and the sink/`IroPropagate`,
call-argument-last, and `if`/`?:`-arm-before-condition numbering rules. **The `-opt` sub-flags
(`nopeephole,noschedule,nopropagation,…`) change *`.text`*, not the pool order.**

### The curves "interleave anomaly" is const-defs, not a numbering effect
`main/curves.c` (pool `[0x803DE658,0x803DE69C)`, 15 atoms) reads as impossible under per-function
grouping: `Curve_BuildSegmentLengthTable` is the **first** `.text` function and the **only** user of
`0.1f`, yet `0.1f` pools at slot 9 — *behind* coefficients (`4.0/2.0/3.0/-3.0/-6.0/1/6`) first-used by
functions 7–11. Resolved by the rules above, no `-O0` magic required:

- The **11 leading atoms** (`0.0, 4.0, 2.0, 3.0, -3.0, -6.0, 1/6, 1.0, 0.5, 0.1, 6.0`) are a
  **memory-ref const-def block** declared ahead of the first function, so they pool in declaration
  (= address) order, *before* any function-group literal. `0.1f` is one of these defs, referenced by
  `BuildSegmentLengthTable` through a forward memory-ref — it is **not** a `BuildSegmentLengthTable`
  literal, which is the whole reason it is not at slot 1.
- The **tail** is ordinary per-function-group material appended after the def block:
  `SampleSegmentPoints`'s int→float conversion **double** (slot 11), then `Curve_AdvanceAlongPath`'s
  `20.0f` literal (slot 12), then two more defs `-5.0`/`-2.0` (slots 13–14).
- **Verified end-to-end (`probe/curves_v2.c`):** 11 `__declspec(section ".sdata2") f32 lbl_… = v;`
  defs at the top (address order) + `#pragma explicit_zero_data on` for the `0.0f` (else it sinks to
  `.sbss2`) + two bottom defs for `-5.0`/`-2.0` reproduces the retail pool **byte-exact (0x44 B)** on
  the first compile.

### ★ Open cap on curves `.text` (why the byte-exact pool does not yet LAND)
The pool is exact but `.text` is not, and it is the *coloring*, not the numbering, that blocks it:

- **`Curve_EvalBezier` genuinely needs the memory-ref** — all-literals (`k = 3.0f`) diverges by ~14
  instructions because a literal cached in a local is **rematerialised/propagated** at each use, while a
  memory-ref (`k = lbl_…`) is alias-opaque and stays cached. So Bezier must read a **named symbol**.
- **`Catmull`/`Hermite`/`BSpline` need LITERAL coloring** — all-literals matches **12/13 functions
  byte-perfect** (only Bezier off). A plain memory-ref to the def swaps a register pair (e.g. the
  longer-lived `2.0` vs single-use `4.0` in `Curve_EvalCatmullRom`; `bare-const` fixes the coloring to
  **0 diff** but emits the def *and* a re-folded literal — two atoms).
- **The impasse:** a single retail atom (e.g. `3.0`@`0x664`) is read by Bezier (named memory-ref) *and*
  Catmull (literal coloring). Literals do **not** dedup against defs (probe `dd.c`/`share2.c`), and a
  memory-ref cannot name a literal anon, so the two cannot be made the same atom by any straight
  spelling. The remaining route is the **linker-coincidence / ghost** path: keep Bezier on an *extern*
  shim (resolved by `symbols.txt` to the pooled address) and let the literal-coloring functions'
  anons land at exactly those addresses via a front-of-file ghost that first-creates the 11 leading
  values in address order — untested here; this is the "few atoms' placement" gap. `curves_v2.c` (pool
  exact, `.text` 129 diff-lines over 6 fns) and the all-literals baseline (`.text` 12/13, pool in
  func-group order) are the two endpoints.

## ★★ Global-bias-redraw — why flipping a shared-pool unit to Matching moves the DOL

Derived 2026-07-17 against **seqobj11e** (`main/dll/seqobj11e.c`, pool `[0x803E27F8,0x803E2898)`,
0xA0 = 40 words, all atoms globally-bound `g` in the dtk carve). This is the shape the mission called
"global-bias-redraw": the unit's `.sdata2` is **byte-identical** to retail in the `.o`, fuzzy reads
**100.0000**, yet flipping `NonMatching→MatchingFor` **breaks `main.dol`**. There is NOT one mechanism
here — there are **two independent sub-mechanisms**, and only one of them is a "bias" issue at all.

### The setup (how to recognise the class)
`seqobj11e` sits in a **dtk-oversplit merge region**: its `.text` (`0x80152040..80152EC0`) is followed
by `mikaladon` then `magicplant`, and `magicplant`'s carve references atoms **inside** seqobj11e's pool
(`lbl_803E286C`, `lbl_803E2894`) and inside mikaladon's (`lbl_803E28A0..28A8`). Those cross-carve refs
are why dtk marks the whole pool `g`(lobal) and why the source **defines** the shared atoms as
`__declspec(section ".sdata2") f32 lbl_803E28XX = v;` (a named export magicplant/mikaladon can link to,
resolved by symbols.txt absolutes). **Note:** the READONLY vs WRITABLE `.sdata2` flag is a **red
herring** — dtk *always* marks the carve `.sdata2` READONLY, and **every** MWCC-compiled `.o` (matched
siblings included: mikaladon, kooshy, newseqobjgroup) emits `.sdata2` as **WA/writable**. The flag does
not decide anything.

### Sub-mechanism #1 — mwld dead-strips an UNREFERENCED named `.sdata2` global (FIXABLE)
seqobj11e's pool holds two adjacent `0.0f` atoms: `lbl_803E2864` (**dead** — 0 relocs from any carve)
and `lbl_803E2868` (live, 2 refs). When the retail **asm carve** provides the pool, the dead atom
survives (it is interior to one indivisible section blob). When **our compiled `.o`** provides it, mwld
**dead-strips the unreferenced named global**: `lbl_803E2864` vanishes, `2868`/`286C` slide up 4 bytes,
and an 8-aligned bias below re-pads — the linked pool comes out shifted from a **byte-identical `.o`**
(the classic "objdiff reads 100, DOL moves" trap).

- **Proven deadstrip, not value-coalesce:** giving the dead atom a *unique* value (`123.5f`) still
  strips it → liveness is the trigger, not duplication.
- **Proven not the section flag / not `const`:** per-atom `const` leaves the section WA and still
  strips; all-atom `const` **re-folds** referenced atoms into new anon literals (pool grows 0xA0→0xA8)
  and *still* comes out WA. matched siblings (mikaladon) are WA with zero dead atoms and link fine.
- **THE FIX — `#pragma force_active on … reset` around the def block** holding the dead atom (the
  effect15/dimsnowball idiom). It marks the unreferenced def no-deadstrip; the `.o` stays byte-identical
  and the linked pool comes out **byte-exact**. Triage rule (from the pool-claim playbook): a **−N**
  linked-size delta from a byte-identical `.o` = dead-strip ⇒ `force_active` fixes it; a **+N** delta =
  extra content ⇒ forcing makes it worse.

### Sub-mechanism #2 — the "extra unsigned magic" is a REAL SECOND TU (needs a redraw, not a spelling)
With #1 fixed, the pool is byte-perfect and the **entire** residual is **exactly two `.text`
instructions** — both in the trailing function `fn_80152B90`:

```
retail : lfd f1,-15464(r2)   ; 0x803E2898  (a SECOND unsigned bias, 43300000 00000000)
ours   : lfd f1,-15592(r2)   ; 0x803E2818  (the unit's first unsigned bias)
```

The retail carve **imports** `lbl_803E2898` (`*UND*`, an 8-byte ubias living at the very top of the
*next* unit's pool) and `fn_80152B90` loads from it; every earlier function loads the ubias at
`0x2818`. **A single TU dedups conversion biases TU-wide, first-creator-wins ([[POOL_ORDER]] rule), so
one TU can mint the unsigned bias exactly once.** Two ubias atoms therefore **prove two TUs**:
`gcRobotPatrol_updateWhileFrozen` (mints `0x2818`) and `fn_80152B90` (mints `0x2898`) are in **different
translation units**. dtk drew the `.text` carve boundary at `0x80152EC0` (mikaladon), but the real TU
boundary falls **earlier** — `fn_80152B90` (and its inlined signed-conversion ghost that mints the
`0x2870` sbias, whose emission-vs-pool inversion already flags a group boundary) belong to the
**mikaladon** TU. Our single compiled TU cannot reproduce the second ubias by any def placement or
spelling — dedup forbids it. This is exactly the "two compiler magics no def placement can reorder"
case the pool-claim playbook banked as archaeology; the correct read is **not** "unfixable" but
**"TU-boundary redraw"** (the arw-quartet / scshgroup class).

**The landing recipe (untested here — costed, not yet executed):** split the carve so
`fn_80152B90` + its ghost move into a `mikaladon`-group wrapper that `#include`s them ahead of
`mikaladon.c`, repartition `splits.txt` `.sdata2` at `0x803E2870` (TU-A `[27F8,2870)`, TU-B
`[2870,28AC)`), keep `seqobj11e.c` (TU-A) ending at `mikaladon_updateWhileFrozen`, and apply the #1
`force_active` fix in TU-A. Bystander cost is favourable: this region is currently `mikaladon`(complete)
+ `seqobj11e`(NOT complete) = **1 complete**; a successful redraw yields `seqobj11e`(TU-A) +
`mikaladongroup`(TU-B) = **2 complete** (**+1 unit**, no matched_code/data loss), because TU-B merely
absorbs the already-matched mikaladon plus the trailing seqobj11e functions.

### The general diagnostic for the class
1. Flip to Matching; if `main.dol` fails from a **byte-identical `.o`**, dump linked `.sdata2` symbols
   (`objdump -t main.elf`) and compare atom **addresses** vs the byte layout.
2. A dead named global that **vanished** (successor atoms slid up) ⇒ **sub-mechanism #1**, fix with
   `#pragma force_active`.
3. A residual that is a handful of **bias `lfd`/`lfs` loads** pointing at a **different** bias address
   than retail (retail imports it `*UND*` from the neighbour's pool) ⇒ **sub-mechanism #2**, a second
   TU; count the biases (N ubias / M sbias in the carve = N/M distinct minting TUs) and redraw the
   boundary so the trailing functions mint their own magic.
