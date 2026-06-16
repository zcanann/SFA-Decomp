# Decomp Matching Wins (dll_0000-0140 scope)

## Confirmed wins this session
- decoration11a_hitDetect (dll_011A): 97.4->100%. FIX: target re-derives the
  hitState pointer (`*(int*)(*objects + 0x54)`) FRESH at EACH store (lastHitObject
  AND contactFlags), not once into a named `hitState` local. Inline the deref per
  store (#130). The register rotation in the diff was a RED HERRING / downstream of
  the structural single-vs-double deref. Pointer-param retype (#126) REGRESSED it.

## Lessons
- A clean-looking #108 rotation diff can be downstream of ONE structural difference
  (a deref done once vs twice). Look for `delete`/`insert` regions in ndiff FIRST.
- locked_ninja.sh + `timeout` not available on macOS (no GNU timeout).
- push fails (remote ahead, shared tree) - commit locally, one push attempt, move on.

## Win 2: Tricky_applyFloorResponse (dll_00C4): 97.4->100%
- objAudioFn_8006edcc call: target emits the two f32 args LAST (right before bl),
  current emitted them first. FIX: reorder the per-file extern so f32 params come
  LAST in the signature, and reorder call args to match (#87/#29, ABI-NEUTRAL:
  FP args land f1/f2 regardless of list position, int args keep relative order).
  BONUS: the real def in newshadows.c IS (int...,f32,f32) so this is also a
  correctness fix. Per-file extern is fine (#57).
- LEVER CONFIRMED: arg-emission order = callee param POSITION. When target sets up
  GPR args then FP args last, declare f32 params last.

## Banked this session (don't retry blind)
- dll_92/94/97/99_func03: deep volatile coloring scramble in stack cmd-builder (#108).
- boneParticleEffect_release / Objfsa_GetPatchGroupIdAtPoint: `.data` array addr
  materialized via `addi r0; mr rX` extra-mr vs target `addi rX` direct. Peephole
  copy not folded; O1 regresses. Banked single-mr.
- Checkpoint_func10: pure 40/40 volatile permutation (#108).
- dll_15_func07 / WaterFallSpray_init / mediumbasket dll_CA_render: bne;b
  non-inversion (banked).
- explodeanimator_update: f64-bias/f32-mult FP pair swap f30<->f31 (#82, banked).

## Session end summary (2 wins, ~14 attempts)
WINS: decoration11a_hitDetect (#130 re-derive per store), Tricky_applyFloorResponse
(#87/#29 f32-params-last arg order; bonus correctness — matched real def).

ADDITIONAL BANKED (hard, no source lever found this session):
- sidekickball/fn_801796BC, dll_F7_update: param-vs-184deref r30/r31 swap (#108/#126).
  Pointer-param retype made param COPY-pool (r31) - WRONG direction; target wants
  param LOWER (r30), deref(copy)=r31. Could not flip.
- dll_F7_update: ALSO a struct-copy stack slot at fixed HIGH offset; decl reorder
  inert (#67 frame layout). vec=lbl copy won't move below addr-taken px/py/pz.
- grimble A00/A01: frsp-CSE - target keeps double d in reg, separate stfs(x=d dead
  store)+frsp((f32)d); current merges to one frsp. (f32)d->d and ->x both fold back.
- mediumbasket/fn_8015D3C0: targetDelta[3] dead stores DSE'd; target keeps them (#8
  but array not passed). Frame shift hitInfo 8->20.
- CameraModeForceBehind_init: lha 0(r31) (rotX read) scheduled AFTER const lfs;
  target before. scheduling-off/operand-lift/temp inert. +@175-vs-named bias (#70).
- minimap/fn_8013396C, saveselectscreen/render: multi-issue (cmplwi#3 + bne;b + CSE).

## Session N (0 wins, ~7 attempts) — banked, no source lever found
- SaveGame_gplaySetObjGroupStatus (dll_0017, the prompt LEAD): file is OWNED by another
  agent (uncommitted SaveGameTimeEntry/SaveGame_updateTimes WIP that does NOT compile —
  "undefined identifier 'SaveGameTimeEntry'"). SKIP per shared-tree rule. The real lever
  IS clear: target's groupStatuses unrolled write-loop (factor 6) uses DISPLACEMENT form
  (lwz 0/4/8/12/16/20(r5), r5+=24 at bottom) vs current's pointer-walk (lwz 0(r5), r5+=4
  per element). #96 opt_strength_reduction off is the candidate fix — RETRY when the file
  is clean (need: the lbl_80311810 walker r4 stays a +2 pointer-walk, only groupStatuses
  r5 should fold to displacement — verify pragma doesn't kill the r4 walk too).
- hudDrawMagicBar (maybetemplate, 79.8%): ONLY structural issue is `p3 & 0xff` CSE.
  Target re-masks fresh per draw block (clrlwi r0,r25,24; cmplwi 0; beq → 10x into
  VOLATILE r0). Current computes ONCE into SAVED r31, reuses cmplwi r31,0. Tried (all
  INERT or WORSE, all reverted byte-clean): opt_common_subs off (10 deletes unchanged),
  optimization_level 2 (worse 130 regions), opt_propagation off (worse). hudTextures
  re-derivation in ndiff was a MISALIGNMENT artifact (both target+current re-derive base
  — not a real diff). Need a #114-style VN-splitter that forces per-use re-eval of the
  byte mask but I couldn't find the spelling. OPEN.
- groundanimator_update (dll_0138, 85.6%): #108-dominated r20/r21/r15 vs r25/r26/r27
  whole-body within-class scramble. Also real: current saves extra paired-single (psq_st
  f31) growing frame -112 vs target -128... wait target is LARGER (-128). +1 ext-delete
  at resetHitboxMode bitfield (offset 44/45, #83c). Banked — too perm-heavy.
- animatedobj_update (dll_00C6, 83%): #108 scramble (slot8/match/obj saved-reg class
  pool order differs) + 1 extra `mr r30,r0` (slot8 extsb lands in r0 not its saved home,
  #100/#15 didn't obviously apply since not an O0 unit). slot8 and slot ARE separate vars
  in target (mr r6,r28 = slot=slot8). Banked.
- objInterpretSeq (dll_0126_trigger, 87.7%): LARGE switch dispatcher with whole CASE
  BODIES present in target but MISSING/reordered in current (Sfx_StopFromObject block,
  GameBit_Set 2406/2407/2408 triple, getArwing/gameTextFn_80125ba4 block). #13 case
  reorder / #79 dropped-case reconstruction — TRACTABLE but large, needs jump-table
  decode + body transcription. GOOD next-session target (high base %, real structural
  gains available, clean file).
- gameTextBoxFn_80134d40 (dll_02C0_front, 82.8%): multi-issue FP — f30 hoist of
  lbl_803E2300 (#45/#121, target keeps in saved f30 across draw calls) + fmadds/fsubs
  reassoc + __cvt_fp2unsigned ordering. 102 regions. Banked (multi-issue).
