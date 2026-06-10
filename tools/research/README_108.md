# #108 dose-inversion minimal harness (research)

e14.c — the canonical E14 shape (params + 2 call-crossing copies + 2
multi-def webs): colors params r25-r27 (bottom), copies r31/r30,
multi-defs r29/r28 (E1 descending creation).

e14_div.c — same with ONE magic-const division (`md2 = p3 / 7`): the
interleave FULLY INVERTS (params r29-r31 TOP, copies/multi-defs sink to
r28-r25). A const-folded `600 / 7` control stays canonical — the dose is
the RUNTIME division's IR, not the source text.

Compile (GC/2.0, unit flags):
  build/tools/wibo build/compilers/GC/2.0/mwcceppc.exe -nodefaults -proc gekko \
    -align powerpc -enum int -fp hardware -Cpp_exceptions off -O4,p -inline auto \
    -maxerrors 1 -nosyspath -RTTI off -fp_contract on -str reuse \
    -opt nopeephole,noschedule -lang=c -c e14_div.c -o e14_div.o
Read the `mr r2N,r3/r4/r5` prologue lines for the coloring.

Open questions (next session):
1. ONE f32 conversion did NOT shift this harness (sub-threshold?) — find
   the conversion count threshold here; the campaign saw 1-2 convs = one rank.
2. The timer probe is dose-INSENSITIVE entirely — diff its web structure
   against e14 to find the arming condition's precise form.
3. The one-law hypothesis: is target ALWAYS E1-canonical with doses, and
   every "rotation" fn a case where OUR IR carries a different dose than
   the original's (same instrs, different IR-internal census)? If so the
   fix per fn = find the import construct whose IR differs (CONCAT44
   blobs, division spellings, conversion node counts) without changing
   the instruction stream.


## Round-2 results (carrier taxonomy, this window)

| construct | first-param reg | dose |
|---|---|---|
| (none) / const-folded `600/7` / big-const / 1-4 f32 convs / variable `p3/p2` divw | r25 | ZERO |
| `p3 % 7` (modulo-by-const expansion) | r28 | partial (3 ranks) |
| `p3 / 7` (magic-const div expansion) | r29 | FULL inversion |
| `(unsigned)p3 / 7u` | r29 | FULL inversion |
| HAND-EXPANDED `/7` (s64-mul spelling, same mulhw) | r28 | partial — DOSE IS SPELLING-MODULABLE |

Conclusions: (1) the dose carrier is the DIVISION-BY-CONSTANT STRENGTH-
REDUCTION IR specifically — not divisions (divw=0), not conversions (0-4
all zero on this harness), not big consts; (2) the modulo expansion and the
hand-expanded s64-mul spelling carry PARTIAL doses — the dose rides
IR-node kinds the front-end creates for the expansion, and respelling the
same computation changes it WITHOUT changing the instruction stream
(mulhw still emitted); (3) therefore the parked rotation fns carrying
`/ CONST` or `% CONST` may be fixable by dose-tuning respells (hand
expansion, modulo->div+mul-sub rewrites) that move OUR interleave to
target's — the next session should pick a real banked fn with a division
(cnthitobjec_init's /3 mulhwu!) and battery the respells against its
target coloring.


## Round-3 scoping result (decisive negative)

A scan of 15 banked rotation fns found ~ZERO magic-div carriers in their
streams (one variable divw = zero-dose). THE BANKED ROTATION INVENTORY IS
NOT DIV-DOSE-DRIVEN — the dose mechanism explains E14-class inversions but
the real fns' rotations are pure within-pool ORDER divergences in dose-free
functions. The research must attack the order law directly: why does target
color n_rareware by E1-creation but timer by decl-order when both are
dose-free? Candidate next probes: graft each specimen's exact web list onto
the minimal harness and binary-search the construct that flips the law.


## Round-4: graft probes hit the known wall

Grafting n_rareware's web structure (loop + 3 call results + final consume,
with and without the FP-arg call) onto a minimal TU colors NEAR-CANONICALLY
(fmt/wid at r30/r31) — it does NOT reproduce the real fn's inversion
(fmt/wid at r26/r25). Consistent with the campaign's standing rule: the
within-pool order divergence is fn-/TU-context-bound and NOT reproducible
in minimal probes (the #113 probe-trap, order-law edition). All further
order-law experiments must be IN-TREE A/B on the real fns; the harness is
only valid for the dose mechanism (rounds 1-2).


## Round-5: in-tree order-law experiments on n_rareware (initLoadingScreenTextures)

- `#pragma optimization_level 2` wrap: 86.69 -> 82.41 NET-NEGATIVE (the isel
  damage exceeds the coloring gain, as predicted; O2-as-the-fix is dead).
- TU position (fn moved to file top): byte-identical 86.69 — TU position is
  INERT on the order law (matches the probe-battery's no-cross-fn-leakage).
Remaining queued: per-arm block-scope decls; preceding-fn content variations
in-tree; the construct-census bisection (stub bodies one at a time as the
#115 method prescribes — header-decl bisection found that class's perturber).


## Round-6: decl-width bisection + prefix-stub (n_rareware)

- TRUE SDK widths for GXGetTexBufferSize (u16,u16,...): 81.47 — WORSE than
  the import's all-uint decl (86.69). The all-int/uint flat decl outscores
  SDK truth here (either the original used a local prototype, or the u16
  promotions cost more than the coloring gains).
- GXGetTexObjFmt int-return: identical; Width u16-return: worse (85.9).
- PREFIX-STUB (runLoadingScreens emptied): byte-identical 86.69 — no
  cross-fn leakage in-tree either.
CONCLUSION after 6 rounds: the order-law discriminator lives in the fn's
OWN text at the IR level (web-creation order), unreachable by decl widths,
TU position, neighbors, pragmas, or O-levels. The remaining axes: per-arm
block-scope re-decls (#108's shrine1CE lever, untested on this specimen)
and accumulating more 100%-matched specimens whose C is known (MP4-oracle
the GX-result shape: find a matched fn with 3 sequential call results
feeding a consume call and read its locals' declaration pattern).


## Round-7: the MP4 matched corpus IS the order-law oracle

THPSimpleDecode (MP4, 100%-matched) has 3+ distinct call-result saves at
r26,r27,r25 (non-E1!) and its C is readable: the decl block is
`u8 *var_r29; s32 *var_r30; s32 temp_r27; s32 temp_r26; s32 temp_r25;
s32 var_r28; s32 i;` — the matching authors literally named locals after
their registers, and the DECL ORDER produces the coloring: the two loop
walkers (var_) declared first take r29/r30; the call-result temps (temp_)
descend r27->r26->r25... in a creation-order-within-class pattern, with
var_r28 (a multi-def join var) seated between. METHOD extracted: for any
rotation-banked fn, (1) grep the MP4 matched corpus for the same WEB SHAPE
(the regex batteries in this round's commits: distinct mr-result runs,
walker counts), (2) read the matched fn's decl ORDER + naming classes
(var_ multi-def vs temp_ single-def vs sp stack), (3) transplant the decl
ordering pattern onto the SFA fn. This is the inp_value precedent
('rotation dissolved when source matched upstream forms') turned into a
general procedure. Scanner one-liner in commit message; candidates with
the n_rareware shape: SetMtx (E1-descending), THPSimpleDecode (mixed),
HuAudSndGrpSetSet (30,31,26,27 — another readable mix).


## Round-8: shape_match.py + the 2-web rosetta

tools/shape_match.py finds EXACT prologue-skeleton matches instantly
(infotext's (mr r30, lwz r31, lwz r31, lwz r30) -> 7 perfect SDK hits).
The rosetta (VISetPreRetraceCallback): TWO named locals — `int interrupt;
T oldCallback;` decl'd in that order, the r31 local SECOND with SPLIT init,
the param never copied. Transplant test on infotext: split-init alone inert
— the missing piece is the EXTRA LIVE named local (the rosetta's
`interrupt` is a call result used later; infotext's import names no second
value). Next: identify which of infotext's values the original named
(candidates: the lbl compare bound per #71-inverse, a GameBit result) and
A/B each as a live named local + split-init combination.
