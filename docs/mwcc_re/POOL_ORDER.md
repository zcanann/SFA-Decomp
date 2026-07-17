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

## Landed

- **crrockfall** (`dll_016A_crrockfall.c`), 2026-07-17: fn reorder to retail `.text` order
  (byte-neutral) + hoist `crrockfall_isPlayerInRange` (the ghost) above `fn_801ACCFC` + respell all
  11 `extern f32 lbl_803E4*` / `gRockfallGravity` / `gRockfallScaleDivisor` shims to plain literals +
  claim `.sdata2 [0x803E46E8, 0x803E4734)`. Pool reproduced **byte-exact**. Gated in an origin
  clean-room on `476b2f4d80`: `main.dol: OK`, complete_units **774 -> 775**, complete_code
  1104044 -> 1105904, matched_data 1173295 -> 1173371 (+76 B = the 0x4C pool), **matched_code FLAT**.
