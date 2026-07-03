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

## Update (decode session 2): where the coalesce lists come from
- `gCoalesce1` (0x5e99c4) is POPULATED IN CFunc.c (assert TU 0x5bb310), append site
  0x4f4e26-0x4f4e39, during function-entry object setup (asserts at lines 0x5c7-0x5c9).
  The GUARD is `value->kind (+0x2) == 1` (0x4f4e20) — only kind-1 values (embedded-desc
  register candidates, per RegInfo_Desc's dispatch: kind1 -> desc at value+0x2a) get a
  coalesce cell. Other head-writes: 0x4e924c (same TU region), 0x4f11ab, 0x55cc37 (CInline
  band). gCoalesce0 (0x5e9b00) bulk-set at 0x4f0b96 from a 0x4f0e90 call result.
- desc+0x24 bit1 is NOT set by any immediate `or` in the binary; RegInfo_Desc lazily
  bzero-allocates descs (kind 0/2) so bit1 defaults to 0 — the bit must arrive via the
  kind-1 embedded desc contents (value+0x2a+...) set during value creation in CFunc/CodeGen.
- desc+0x24 bit1 is CLEARED (`andb $0xfd`) + 0x80 SET at 0x4f9eb7/0x4f9f4f/0x4f9fd6 inside
  the stack-slot assigner (0x4f9e30, cursor global 0x5dfcdc, limit 0x5dfcd8): a value that
  receives a MEMORY HOME becomes permanently un-coalesceable. This confirms the mr-class
  question is decided at VALUE CREATION (kind byte + embedded desc), i.e. in the front
  end when it builds the address-init temp — next read: what sets value+0x2 to 1 vs 0/2
  for compiler temps vs user locals in CFunc.c/CodeGen.c.

## Update (decode session 3): the CodeGen temp pool and why bit1 dies
- 0x43629f (CodeGen.c) = the pooled-temp allocator: walks pool list 0x5ddc98 for a
  free (desc+0x24 & 0x20 clear) same-type temp and claims it; else allocates a fresh
  value {tag(+0)=5, kind(+2)=1, type(+0xe)}, bzero-allocs the 0x2a-byte desc, copies
  an 0x18-byte template from 0x43e470() into desc+0x8, ids it via counter 0x5ea19a,
  sets 0x20 (claimed), then CALLS THE SLOT ASSIGNER 0x4f9e30 — which clears bit1.
  The andb $0xdf sites in CodeGen (0x4337a6 etc.) release temps back to the pool.
- Consequence: pooled CodeGen temps are never coalesce-eligible; the mr dies (when it
  dies) via IroPropagate/VN, not Color_Coalesce. The retail direct `addi rHOME` for the
  cross-BB address-init therefore means the retail IR had ONE def (AddrConst -> home)
  with no intermediate temp at all — the divergence is in the FRONT-END LOWERING of
  the initializer (when does an assignment RHS get a pooled temp vs. target the LHS
  web directly), i.e. CExpr/CFunc assignment lowering, not any RA pass. Next read:
  the assignment lowering call path into 0x43629f (who requests the temp for a
  decl-init of an address constant, and under what condition it is skipped).

## Update (decode session 4): the class is not compiler-version dependent
- Compiled dll_94 with GC 1.3/1.3.2/1.3.2r/2.0/2.0p1/2.5 (same flags): EVERY version
  emits `lis; addi r0; mr rHOME` for the cross-BB address init. Our own build of the
  same construct with a same-BB first use (dll_93) emits the direct `addi r31` — so
  the front-end always makes the temp and only the in-BB fold deletes it.
- Since no MWCC emits the retail shape for this source+CFG, either (a) the retail
  source used a construct we have not conceived, or (b) the retail DLL POST-PROCESSING
  (the DLL-format converter/linker) RELAXED `lis rX; addi r0,rX,lo; mr rD,r0` into
  `lis rX; addi rD,rX,lo` — a classic address-materialization relaxation, consistent
  with the class appearing exactly and only at relocated address materializations.
  Checking the DLL conversion tooling for a relaxation pass is the next (and likely
  final) step for this class; if confirmed, the fix is in tools/configure, not source.

## Update (decode session 5): relaxation hypothesis REFUTED - it is source-level
- Scanned all 1852 retail DLL objects: the `addi r0,rX,lo; mr rD,r0` temp+copy shape
  SURVIVES in 14 retail sites (e.g. Tumbleweed.o debugPrintDraw: lis/addi r0/mr r27
  for debugLogBuffer@ha/lo, mid-function, right after a bl). Our builds have 61.
  So there is no blanket post-processing relaxation; the retail compiler emitted BOTH
  forms and the distinction is in the source/position.
- Pattern in the data: every DIRECT-form retail site examined (shield_update,
  SnowBike_init, nw_mammoth_update, dll_92/94/97/99_func03, subtitleBuildLineTable)
  has the address init as (one of) the FIRST statement(s) at function entry; the
  temp+mr survivor (debugPrintDraw) is a MID-FUNCTION init after a call. Our compiler
  produces the direct form at entry ONLY when the first use is in the same BB
  (dll_93); entry + cross-BB use gives temp+mr on every MWCC version tested.
- Open question is now sharp: what does the retail entry-position init look like in
  source such that the fold survives across the following branch? Candidates left
  untested: the init being part of the PROLOGUE-adjacent parameter/local setup that
  CFunc lowers differently from statement-position assignments (the 0x4f7e14 paths),
  e.g. a local whose initializer is lowered during function-entry object setup
  rather than as a body statement.

## SOLVED (session 6): the direct form comes from an INLINED HELPER PARAMETER
- Proven on staff_initialise (dll_00E2, now 100%): move the entry-position code into
  a `static inline` helper taking the pointer as a PARAMETER and call it with the
  address constant: `static inline void body(s16* p, ...) {...}` +
  `body((s16*)lbl_803208A0, ...)`. After CInline, the argument's address
  materialization IS the parameter web's single def — `lis rX; addi rHOME,rX,lo`
  direct, across any number of BB boundaries. Decl-init (`s16* p = (s16*)lbl;`) and
  a pointer-RETURNING inline helper were also tested: both still produce temp+mr —
  only the parameter path skips the pooled CodeGen temp.
- Corollaries from the same session (all probe-validated on staff_initialise):
  * A flat N-trip walker loop auto-unrolled by factor F leaves the ORIGINAL counter
    as `li rC,0` + a merged `addi rC,rC,F-1` bump inside the ctr body (35-trip,
    unroll 7 -> kept `addi r5,r5,6`). Writing the hand-unrolled nest eliminates the
    counter; write the FLAT loop and let IroUnrollLoop do it.
  * Passing the counter as a call argument (`i = 0; body(tbl, i)`) both orders the
    entry as `li rC,0` BEFORE the lis/addi and keeps the caller's `i` web spanning
    the whole inlined body — which blocks the const-fold of a later SR derived-IV
    init (`mr rOFF,rIV` survives instead of `li rOFF,0`). Param order (ptr, int)
    sets the volatile homes (ptr=r4, int=r5 here); (int, ptr) swaps them.
- ACTION for the banked functions (dll_92/94/97/99_func03, dll_63_func03,
  SnowBike_init, nw_mammoth_update, renderParticles, shield_update,
  subtitleBuildLineTable, optionsMenu_openGeneralPanel, movieLoad): wrap the
  function body (or its head) in a `static inline` helper receiving the table
  address as a parameter.
