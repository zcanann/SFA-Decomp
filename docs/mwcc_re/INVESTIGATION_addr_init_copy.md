# Investigation: address-init `mr` (temp+copy vs direct addi) — GC/2.0 DLL units

**Symptom.** Target: `lis rX,hi(sym); addi rHOME,rX,lo(sym)` — the table/base address
lands directly in the variable's home. Ours: `lis rX; addi r0,rX,lo; mr rHOME,r0` —
an extra move (+1 instruction, T=N C=N+1). Everything else in the function matches.

**Known blocked functions (all -O4,p nopeephole,noschedule DLL units):**
dll_92/94/97/99_func03 (99.55), dll_63_func03 (99.74), SnowBike_init (99.66),
nw_mammoth_update (99.62), renderParticles (99.10), shield_update (99.48),
subtitleBuildLineTable (99.56), optionsMenu_openGeneralPanel, movieLoad.

**Trigger (validated on dll_94 by deletion):** the copy appears iff a BASIC-BLOCK
BOUNDARY (any conditional) sits between the address init and the variable's first
use. Deleting the intervening `if` diamond makes the addi target the home directly.
First-use-in-same-BB cases (cclightfoot_update tbl, dll_93_func03) coalesce fine —
that path is IroPropagate (local/per-BB, kills the copy in-BB).

**What does NOT fix it (all tested):**
- spelling: plain decay, `(u8*)`, `(u8*)(int)`, `&arr[0]`, `(u8*)&arr`, `+ 0`,
  scalar-extern `&sym` (goes SDA and breaks), `register`.
- int-typed base + `(u8*)base` at uses: kills the mr on dll_94 but perturbs the
  volatile store-webs (net fuzzy loss); on dll_63 doesn't even kill it.
- pragmas: opt_propagation/opt_lifetimes/opt_common_subs/opt_dead_assignments off,
  peephole on (-opt noschedule alone), -O4 vs -O4,p. None coalesce the copy.
- decl reorder, moving the init after the diamond (moves the lis/addi = mismatch).

**Why it should coalesce and doesn't:** per Coloring.c (recovered), the copy dies iff
its move descriptor has desc+0x24 bit1(+bit2) and class match (Color_Coalesce
0x508c10). The flags are set UPSTREAM during web/move building — that code is NOT
yet recovered (LEVERS.md "still upstream"). Our compiles never set the flags for a
cross-BB address-constant copy (checked: zero instances of the direct form before a
branch in 151 built DLL objects), while every retail DLL has them. The retail
originals therefore either (a) had a source shape that avoids the front-end temp
entirely, or (b) the eligibility test depends on something we haven't recovered.

**Next step (the real unlock):** read the web/move-building code that sets
desc+0x24 (RegisterInfo.c 0x4d0150 area / the move-list builders feeding
0x5e9b00/0x5e99c4/0x5e98f4). One decoded predicate likely unlocks ~10 functions at
99.4-99.8. Until then: BANK this class; don't chase it with spellings.
