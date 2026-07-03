# web_dump.gdb — per-web Select/fallback tracer

Companion to `validate_select.sh`. Breaks on Color_Select's assignment
(0x50899e) and the reserved-reg fallback (0x5089c4) and prints, for every
colored web: class, web index (+0x10), static degree/nadj (+0x18), and the
chosen register. Driver entries (0x508680) delimit per-class passes.

    gdb -batch -x tools/mwcc_re/web_dump.gdb --args \
      build/tools/wibo build/compilers/GC/2.0/mwcceppc.exe <FLAGS> -c <unit.c> -o /tmp/out.o

Read the output as: `F idx=.. nadj=.. reg=..` lines are saved-register
(fallback) assignments in stack-pop order — the r31-descending sequence.
Diagnosed on mmp_moonrock_update: a saved-pair mismatch vs retail is decided
by (web index, static degree) pop order; function-scope decl order shifts a
named local's web index (first decl → highest), block decl order does not.
The vreg-numbering rule that fixes cross-scope index gaps (e.g. def idx38 vs
list idx35 with target wanting def < list) is still undecoded — that is the
next unlock for the reg-perm family.

## Confirmed numbering rule (probe-validated, GC/2.0 -O4,p noopt)

Three controlled probes (3-4 call-crossing locals, permuted decl vs assignment
order) pin the rule: **web index = DESCENDING in declaration order** (first
declaration → highest index), across nested block scopes too (block decls slot
in sequence after the enclosing decls). Assignment order does not move indices.
Fallback (saved-reg) pop order then follows (index, park-round): r31 to the
first-declared web of the highest park round, descending.

Validated consequences:
- crrockfall_update: exhaustive 24-permutation search over its 4 decl-inits —
  the committed order is already optimal (9 regions); all others are worse
  (10-33). The residual web is a SPILL-ROUND split (idx 62 vs sibling idx 33),
  outside decl control.
- invhit_update (idx 86), hoodedZyck_updateB (spilled turnRaw reload):
  same spill-split class.
- mmp_moonrock_update: cross-scope gap (fn-scope def idx 38 vs block list
  idx 35) — fn-scope decls always outrank block decls, so unreachable by decl
  reorder.

=> The remaining reg-perm near-misses hinge on the SPLIT-WEB numbering inside
SpillCode.c (0x57c290 band): what vreg number a spill-split web receives, and
therefore where it pops. Decode that and the family at 99.6-99.98 closes.

## Volatile-class pop order (confirmed on objseq, GC/2.0 noopt)
A-line streams show volatile FPR/GPR classes pop in strictly DESCENDING web
index (LIFO of creation), taking the lowest register free of colored
interfering neighbors. The remaining near-miss register pairs
(RomCurveInterp f2/f3, gunpowderbarrel fsubs dest, moonrock r27/r28,
appleontree f4/f0) all hinge on ONE neighbor's live range differing at a
specific pop. Next tracer upgrade: print each web's def PC (walk the web
descriptor for its first pcode ref) so indices map to instructions; then
the differing neighbor is directly identifiable and its source construct
can be targeted.

Recovered-but-parked source structures (verified against target shape):
- RomCurveInterp: `segmentT = segment; segmentT += (t - times[s+2]) / (...)`
  reproduces fsubs f31 seed + fadds accumulate; adopt once f2/f3 flips.
- inpInit zero-fill: CTR-4 loop, 2x16 stw groups with kept +64 bumps and a
  live counter joined to the zero-constant web (class-A join).

Additional verified-but-parked reconstructions (register-rotation gated):
- Lightfoot_UpdateButtonTimingChallenge: `w` is u16-typed (readback gains the
  target's clrlwi r26 def-mask) but adopting it rotates the whole saved bank
  by one (v/params shift); pair with the rotation fix.
- DRlaserturret_handlePromptChoice: both diff sites imply one extra live
  volatile web in the target (countValue web r4 spanning to the vtable-chain
  site); the occupying web is unidentified — first target for the val-pointer
  correlation workflow.
- RomCurveInterp: magic-double web (idx 35, nadj 8, shared with the two scale
  conversions) must be created before the while-loop's times load (idx 34);
  creation point is constant-pool materialization, not statement order —
  needs the vreg-numbering disasm (IroLinearForm band).
