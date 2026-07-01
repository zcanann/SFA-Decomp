# Investigation: three recurring 1-2 instruction residues blocking ~10 near-matches

Status: **open** — each behavior reproduced from multiple functions; no source-level
lever found yet. Candidate functions listed per class so a future compiler-RE pass
(Coloring.c / IroLinearForm disasm) can validate against real cases.

## A. Constant-register reuse: `li rD,K` vs `mr rD,rS` (rS already holds K)

Target reuses a register that already holds the same constant; ours re-materializes.

- `curves_getPos` (dll_0014_unk): unrolled iteration 1 emits `mr r5,r4` (count=1
  reusing mask==1). Ours: `li r5,1`. All spellings of `count++` / `mask` types /
  init order / manual peel failed; `(1 << k)` inline defeats the unroll shape.
- `ObjModel_Load` (model.c): `li r30,0; mr r28,r30` — the texture-offset induction
  var init reuses i's 0. Ours: `li r28,0`. Natural `[i*4]` indexed form creates the
  IV but permutes saved-reg colors (SR web created first instead of last).
- Same family: `mapLoadBlock` (shader), `fn_80026928` (model, `off54 = off4`),
  `sc_totembond_update` (`availableCount = orbIndex = 0` — chain folds to two li's;
  VerifyDir-style ternaries DO produce li+mr, but no branch exists here),
  `RomCurve_countRandomPoints`, `RomCurve_findProjectedCurveFromStart`.
- Working theory: the reuse is emitted by a VN/peephole-like pass over *compiler
  generated* materializations (SR inits, unroll folds); front-end constants don't
  join. Our builds either fold the copy (const-prop) or re-materialize.
- Negative results against LEVERS.md 5a/5b on sc_totembond: self-OR (`orbIndex |=
  orbIndex`) does NOT bump the value number (copy still folds to li); both sides
  are u8 in the target (no type-straddle available); splitting the chain, for-init
  comma forms, and an lvalue-read second statement all fold. The survivor in the
  target may be a VN-ineligible *compiler-generated* copy (cf. class A theory).
- CONTROLLED-HARNESS DISPROOF (probe compiled directly with GC/2.0 -O4,p -opt
  nopeephole,noschedule, sc_totembond shape: u8 avail/idx, call-crossing saved
  webs, in-loop calls): the copy folds to `li;li` under EVERY tested variable:
  compiler {2.0, 1.3.2, 1.2.5n} x opt {-O3, -O4, -O4,p} x {peephole on/off};
  chain/split/reversed statements; int/u8 type mixes; cross-block def (idx=0
  outside the guarded if -- the li then stays at its own statement, unlike the
  target's post-call position); 200-statement padding (no VN capacity effect);
  RHS spellings (|self, &self, ^0, <<0, +=0-value, volatile read, ptr read,
  addr-deref). The target's adjacent `li r25,0; mr r26,r25` (no inbound edge
  between them) is NOT reproducible as a local-to-local copy at function scope
  with these flags. Remaining hypotheses are unit-level: a different -opt string
  for these TUs, or a compiler micro-revision whose VN skips u8 webs.
- OPT-LEVEL BOUNDARY FOUND (probe): the copy SURVIVES as `li;mr` at -O0/-O1/-O2
  and folds at -O3/-O4 (any peephole/schedule combination). No -opt keyword
  ([no]strength/loopinvariants/lifetimes/dead*/prop/cse) re-enables it at -O4 --
  the fold is intrinsic to level>=3 (the IRO linearization/repeated-CSE stage),
  with no pragma/flag toggle. `#pragma optimization_level 2` around the real
  sc_totembond_update produces the mr but rewrites the whole function (149 word
  diffs) -- the rest of the body needs level 4. CONCLUSION: class A is NOT
  source/pragma/flag-reachable with GC/2.0; the retail mr implies either a
  compiler micro-revision with a weaker fold, or IR arriving at the fold with
  distinct value numbers for reasons outside function-local C. These ~6
  functions are principled banks at 99.2-99.8 until the fold's disasm
  (IroLinearForm.c band) identifies the exact value-identity test.

## B. Temp-register selection r0 vs rN for short-lived values

Same statement shape gives a different scratch register (and thus hoistability).

- `saveGame_gplayAddTime` tail vs matched sibling `saveGame_restoreObjectPosToRomList`
  (same file!): sibling emits `addi r0,r4,0; slwi r4,r6,4; add r4,r0,r4` (address in
  r0-temp, shift into the lis reg). gplayAddTime emits `addi r4,r4,0; slwi r0; add
  r4,r4,r0` from the byte-identical statement sequence (p=global; i=i*8; p+=i).
  Sibling context is inside a loop-if; tail is post-loop.
- `objCallSeqFn` (objseq): `lwz r7,76(r4)` vs ours r5 — +2 volatile shift.
- `playerUpdateFn_8005649c` (shader): r6 vs r4 — +2 shift. Same-shape webs.
- `saveSelectFn_8011a70c`: global→global copy temp r3 vs r0.
- `alphaanimator_update`: byte temp r0 (target) vs web r4 (ours).

## C. Rebuilt-add operand order after constant reassociation

`base + (idx<<s) + C` reassociates the constant to a trailing addi/displacement; the
rebuilt add's operand order depends on *which side the constant was attached to*:

- const on base side → `add rD, base, idx` (matched: THPAudioDecode
  `right = left + var` with left=frame+80; sfxplayer fix `pairBase(=handles+4)+off`).
- const on index side → `add rD, idx, base` (ours in `Sfx_RemoveLoopedObjectSound`
  `&flags[(i<<2)+384]`, 4 sites). Rewriting to base-side (`&(&flags[384])[i<<2]` or
  pointer locals) fixes the order but perturbs CSE/coloring (12–42 word diffs).

## D. Misc parked with exact residue

- `WM_newcrystalFn_800969b0`: one `fmuls f0,f0,f1` vs `f0,f1,f0` — operand order is
  canonical against all source spellings tried (incl. self-ref phase temp).
- `fsin16/fcos16/fsin16Approx/fcos16Approx` (MSL 1.2.5n, -O0): target has *fused*
  `rlwinm 2,14,29` + kept `extsh` + s16 slot at 10(r1) + `mr` param copy. u16 param
  fixes slot/extsh but masks stay unfused (2 instrs); `#pragma peephole on` fuses but
  rewrites the param copy `mr`→`addi` and copy-props the operand. No combination
  yields all four properties. (`fn_80293C64`'s matched addi-copies show peephole-on
  regions do exist in this file; fsin16's mr says its region was off.)
- `fn_801C0BF8` (dll_801c0bf8): peephole (required by the rest of the fn) sinks the
  body-tail `addi r23,r23,16` into the cmp→branch gap; target keeps source order.
- `dll_92/94/97/99_func03`: `u8* base = (u8*)(int)lbl_803171C0` blocks addend folding
  but costs a temp+`mr`; every fold-free direct-materialization spelling tried either
  folds (231 diffs) or keeps the mr.
- `mcmdSetPitchADSR` (audio 1.2.5n): target `cmplwi` on s32-typed clamp with *no*
  conversion temp; every unsigned spelling introduces a `mr r4,r0` sink.
- `treasurechest_SeqFn`: both params homed at entry in index order (mr r27,r3 then
  mr r28,r5); ours emits animUpdate's home before the `o = obj` statement copy.


## E. Branch-fold gap (fn_8007FE04, fn_8016A660/pollen) and the compiler-revision hypothesis

Retail shape: `cmp; bne +8; b EXIT` where the bne merely skips the b -- a
trivially foldable pair -- plus a kept tautological `li r6,-1; cmpwi r6,-1`.
Ours folds both (`beq EXIT`), losing one instruction.

Probe evidence (direct-compile harness, fn_8007FE04's exact code):
- ALL 20 available GC compilers (1.0 .. 3.0a5.2) fold it, at every opt level
  (-O0..-O4 x ,p x nopeephole/noschedule), C and C++ frontends, and with up to
  250 filler functions before it in the TU (no pass-budget effect).
- Source space exhausted: goto/continue/else/empty-then/switch (beq+b appears
  but with cmpwi sign + inverted sense)/while/do-while/two-label chains/
  in-loop labels/bool materialization/ternary-wrapped conditions/1- and
  2-term logical operators. All fold.
- Corpus check: matched functions DO contain cond+b pairs, but only the
  STRUCTURALLY unfoldable kind (two distinct non-fallthrough targets): switch
  range dispatch (UpdateIconOffsets), nested and-or chains (IsCard), FP clamp
  ternaries (fogFn_80070404). The retail pairs in fn_8007FE04/fn_8016A660 are
  the FOLDABLE kind -- adjacent-target -- which no available toolchain leaves.

## Root-cause hypothesis (now backed by two independent proofs)

Class A (copy fold: level>=3 intrinsic, no toggle) and class E (branch fold:
universal across our compiler set) are both *unreachable* behaviors whose
retail counterparts appear across unrelated TUs (DLL and main binary alike).
The simplest consistent explanation: the retail build used an mwcc revision
not in our set (a 2.0-era internal/patch build with weaker late IR folding).
If true, a handful of 1-instruction residues per function are permanently
unmatchable with GC/2.0 proper, and these functions should be banked at their
current 96-99.9% as PRINCIPLED. Recommend: (a) treat adjacent-target cond+b
and li-vs-mr residues as non-actionable in matching work; (b) if anyone can
source other mwcc 2.0-era builds (2.0a/2.0b/OEM revisions), test the two
probes in this doc against them first -- a hit would likely convert dozens of
functions at once.
