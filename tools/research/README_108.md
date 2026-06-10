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
