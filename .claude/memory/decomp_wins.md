# Decomp Matching Wins (dll_0000-0140 scope)

## Session: objInterpretSeq (dll_0126_trigger) 87.7->97.4% — BIG win (~10 commits)
Large switch dispatcher. Was the banked TOP LEAD; cracked with stacked structural fixes:
- fn_80295918 / skyFn_80088e54: declare INT param first (caller emits int args before
  the f32-magic block) — target evals li r3,K BEFORE lfs/lfd magic (#87/#29).
- Inner switches on unk2 → switch on `p[2]` (u8, NO extsb) not the s8 struct field (#15).
  (Some sites DO extsb — verify per-site; case 1/0xb at low addr = no extsb.)
- INVERT arm order (#21) was the single biggest lever: case 4 (Play-first/Stop-else),
  case 0x1d (p[2]!=0 set-0 first), case 0x2d (player!=0 showNpcDialogue first),
  tail (s8 p3>0 |=1 / else if <0 |=2). These flipped ~3% in one batch.
- case 0x2c: (f32)(s16) SIGNED magic (xoris 0x8000 + lfd lbl_803E40D0) not (int)(u16) (#10).
- case 0xc d-dispatch: restructure to SHARED TRAILING `match:` block reached by
  goto/continue (==0x54 goto; >0x54{==0x230 goto/continue}; >=0x51||<0x4b continue;
  fallthrough match). +3.2% alone (#13/#79).
- case 0x1f: `d = (d - 0x10000) + 1` two-op wrap-clamp keeps addis;addi;extsh (#83/#20).
- Pointer null checks `(void*)t != NULL` → cmplwi everywhere (ObjGroup_FindNearestObject,
  getLoadedTexture, getTablesBinEntry, getTrickyObject results) (#3).
- DROP (u16) on call args going to INT params (setObjGroupStatus/setMapAct/OSReport pass
  raw `or`, no clrlwi) — KEEP (u16) where arg is a u16 LOCAL `id` (#37 inverse).
- op/bit decl-order swap helped case 0x12/0x21 r22/r23 coloring partially.
- BANKED residual (~97.4%, #108-class): case 0x12/0x21 op/bit r22<->r23 within-class
  scramble (op should color r22, bit r23; decl swap only partial); case 0x15/0x16/0x26
  `mr r22,r3` copy-BEFORE-compare vs target compare-first (peephole on/off NEUTRAL here);
  case 0xc >0x54/0x230 block placement (inline vs out-of-line). @NNN-vs-jumptable/lbl
  relocs are score-neutral (#70) — dense switch kept bctr under peephole-off (#1). The
  jump-table + per-case bodies all match; residual is pure register permutation.
LEVERS THAT WORKED BEST on big dispatchers: read target arm ORDER and INVERT (#21);
shared trailing label for multi-goto dispatch; per-call pointer null check sweep (#3);
int-param-first for mixed int/f32 calls (#87).

## Session (dll_0141-02FF scope): 1 win, ~10 attempts
WIN: wclevelcont_func10 (dll_028D, WC subdir) 82.5->84.9%. FIX: #59 lift the
leading FP subterm. Target evals `lbl_DD0+p` into a reg FIRST, THEN loads the
trailing named const (`lbl_DBC`/`DA8`) — vs MWCC preloading all 3 constants.
Split `DB4 + (DD0+p+const)` into `t=DD0+p; t=t+const; *out=DB4+t;` (only for the
NAMED-const-last cases; the (f32)(int*48) conversion cases want DB4 loaded FIRST
and resisted — left them). NOTE: another agent (commit 0094077ccb) also touched
this fn; merged cleanly. PROTO report has per-fn data (json format DROPS the
functions list — use `objdiff-cli report generate -f proto`; decode wire format,
field3=fuzzy f32, field4=functions, fn field1=name/2=size/3=fuzzy).

BANKED this session (no source lever found):
- SHthorntail_update (dll_01AD, 88.4%): deep obj<->runtime two-saved-object #108
  swap (obj=r26 tgt/r29 cur, runtime swapped) across 80+ regions. Re-deriving
  obj->config->configToken (#107/#130) was INERT. Real but-small: config rederive
  `lwz 76(obj);lwz 20`. Bank — perm-heavy.
- bombplantspore_update (dll_01AA, 89%): clamp `if(const<field)field=const` -> wrote
  `field>const` (#25/op-order): made fcmpo/ble structure MATCH target but f0/f1 reg
  pair stayed swapped (target field->f1,const->f0; mine ->f0/f1). 0 net gain.
  Remaining = #82 FP coloring + li r28/r30 int coloring + explosion-loop li r8/r9
  sched. Reverted (no gain). Clamp polarity edit is semantically correct if retried.
- cmbsrc_init (dll_02B1, 88.9%): target uses a REMAP table (lbzx r24,lbl_803DC3E0,
  colorIndex) + base lbl_8032BD50 (NO lightVariant*0x30 offset) + held pointers
  &colorTbl[ci+1],[ci+2] reused across diffuse/specular. Source caches ci=colorIndex*3
  and bumps bases. Inlining ci (#107) made lbzx appear but REGRESSED (frame 80 vs
  96, +10 instrs, coloring scramble). Bank — needs full remap-table restructure.
- ktrex_stateHandlerA02 (dll_0250, 89.5%): multi-issue. (a) #112 lfsx->lfs:
  `*(f32*)((u8*)((char*)p+unkFC*4)+0x38)` target=`add p,idx;lfs 56` mine=`addi
  idx,56;lfsx` — both `[0x38/4]` and flat forms FAILED to group base-first (single
  use re-folds). (b) #66 add r4,r31,r30 vs r30,r31 (p/idx, ~4x). (c) clrlwi/cmplwi
  byte-mask cluster on unkFF compares (cond= fe==N branches) + r4/r5/r6 flags
  coloring + push-local sched. Mostly #108. Bank.

## Confirmed wins prior session
- decoration11a_hitDetect (dll_011A): 97.4->100%. FIX: target re-derives the
  hitState pointer (`*(int*)(*objects + 0x54)`) FRESH at EACH store (lastHitObject
  AND contactFlags), not once into a named `hitState` local. Inline the deref per
  store (#130). The register rotation in the diff was a RED HERRING / downstream of
  the structural single-vs-double deref. Pointer-param retype (#126) REGRESSED it.

## Win (later session): mmsh_waterspike fn_801BEEA0 (98.87->100%)
- turnVel CSE'd across store+use. Target RE-READS *(f32*)(motion+4) fresh
  from mem for rotZ update instead of reusing stored turnVel; fadds operand
  order = rotZ_conv FIRST + reloaded_vel. #130 + operand order. Must drop the
  named local ENTIRELY (re-read at both store+use); keeping it for store only
  REGRESSED to 97.83.

## CRITICAL build lesson
- NEVER `rm build/GSAE01/obj/.../*.o` — that's the TARGET reference (dtk split
  output), NOT regenerated by ninja <src.o>. Restore: `rm build/GSAE01/config.json
  && ninja build/GSAE01/config.json` (re-runs dtk dol split, ~8s). Only ever
  `rm build/GSAE01/src/.../*.o` (your own build output).

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
- objInterpretSeq (dll_0126_trigger, 87.7%): **PRIOR HYPOTHESIS WAS WRONG.** bl-count
  is EQUAL (115=115); the "missing case bodies" in ndiff were MISALIGNMENT artifacts.
  Decoded BOTH jump tables (jumptable_8032265C main 48-entry, jumptable_8032262C inner)
  from auto_07_803217F8_data.s — case-block emission order ALREADY MATCHES target in
  both the p[1] switch (1,4,6,8,5,A,D,B,C,...) and the seq switch (10,12,21,13,...). The
  REAL divergences (3): (A) outer guard `(s8)p3 < 1`→`<= 0` (#69: target cmpwi 0;bgt vs
  current cmpwi 1;bge); (B) `s8 unk2`→`u8 unk2` field (drops extsb at case-1 dispatch,
  #7); (C) `fn_80295918(f32,int,int)`→declare f32 param LAST so li r4 emits before lfs
  (#29/#87). **ANOTHER AGENT IS ALREADY FIXING THIS** (uncommitted diff applying exactly
  B (unk2→p[2]) and C (fn_80295918 arg reorder) when I went to edit) — SKIPPED per
  shared-tree rule. If clean again, add fix A (`<=0`) which the other agent may have
  missed. LESSON: bl-count EQUAL = not dropped-call vein; ndiff delete-blocks on a dense
  switch are misalignment. Decode the jump table to VERIFY case order before assuming #13.
- objSeq_onMapSetup (objseq.c, 81.16%): unrolled init loop (#28/#96, ctr/bdnz already
  matches). ONLY issue = allocator base-materialization: target does `lis r3;addi r3,r3`
  (symbol INTO r3, reused) then 12 ptrs `addi rX,r3`; current does `lis r3;addi r4,r3,0`
  (copy base to r4) forcing a 5th saved reg (_savegpr_27) + zero-const in r3 vs target's
  r0. base is live across BOTH loops (reused in cleanup loop i<0x55). Tried: opt_level 2
  (fixed saved-reg count 5→4 BUT regressed loop body to `b`-to-cond, 81→77.7, reverted);
  (u8*)(int) launder on base (INERT). Banked — base-into-lis-reg is a coloring decision
  no source lever cracked. The zero-const r0-vs-r3 is tied to base's reg choice.
- expgfx_acquireResourceEntry (dll/expgfxresource.c, 87.2%, gap +40): match-body
  `resourceTable[i].resource` (offset 0): target=`slwi;lis;addi;lwzx` (single indexed,
  no reusable addr) + store re-derives fresh; current=`add base,idx; lwz 0` then CSEs
  that addr for the evictionScore `stw 4`. Need lwzx on the resource read to break the
  CSE (#112/#30/#130). Tried `((void**)resourceTable)[i*4]` spelling — INERT (still
  add+lwz0, still CSE'd). Banked — lwzx-forcing spelling not found.
- dll_9E_func03 (dll_009E, 93.85%): stack cmd-builder (#93 family, SIBLING of banked
  dll_92/94/97/99). Target HOISTS repeated header constants (0, 0x15, &tab[0x1b0]) into
  saved regs r27/r28/r29 and reuses across the buf-header stb/sth/stw; current re-loads
  per group (li r12, li r31). #6/#51 lift-const-to-local candidate but family already
  banked as #108 coloring scramble. Not attempted deeply.
- gameTextGetPhrase (textrender.c, 92.7%, gap +54): coloring-dominated (r3/r4, r0/r5/r6
  swaps) + 1 possible extra stw insert interleaved w/ rotation. Messy. Not pursued.
- SCAN METHOD NOTE: built an automated target-instr > current-instr gap scanner (the
  RIGHT direction for #79 dropped-logic). Most near-misses in dll_0000-0140 scope are
  the WRONG direction (current emits MORE = missing optimization / extra saved reg), NOT
  dropped logic. Clean dropped-call (#79) signatures are now rare in this scope; the
  remaining vein is mostly allocator/coloring (#108) and lwzx/CSE (#112).
- gameTextBoxFn_80134d40 (dll_02C0_front, 82.8%): multi-issue FP — f30 hoist of
  lbl_803E2300 (#45/#121, target keeps in saved f30 across draw calls) + fmadds/fsubs
  reassoc + __cvt_fp2unsigned ordering. 102 regions. Banked (multi-issue).

## ===== Session (later): 1 full + 1 partial win, ~13 attempts =====
WINS:
- mmsh_waterspike fn_801BEEA0 (98.87->100%): turnVel CSE'd; target RE-READS
  *(f32*)(motion+4) fresh for rotZ update + fadds operand order rotZ_conv FIRST.
  Drop named local entirely (re-read at store AND use). #130.
- arwarwing_clampToFlightBounds (dll_0298 WC, 98.30->99.32%): inlined homeX/homeY
  reads (drop cx/cy CSE) -> 11 regions to 6. Residual = within-class FP perm (#82).

CRITICAL: NEVER `rm build/GSAE01/obj/*.o` (TARGET reference = dtk split output).
Restore: `rm build/GSAE01/config.json && ninja build/GSAE01/config.json` (~8s).
Only ever rm build/GSAE01/SRC/*.o (your build).

BANKED (no source lever, all reverted byte-clean):
- animsharpclaw_free (dll_0184, 99.24%): null-checked child ptr saved(r30)-vs-
  volatile(r4) classing. read-order swap fixed load order only. #108/#65.
- arwbombcoll_checkArwingCollision (dll_029F, 99.57%): else two-fsubs from shared
  objZ, eval order (current=20(r5) first vs prev=136 first). decl/inline INERT. #82.
- sc_totembond_update (dll_01BB, 99.79%): `li;mr` const-equal copy (availableCount=
  orbIndex=0). copy-prop folds at O4; O1 regresses 38 regions. #110.
- smallbasket_update (dll_0104, 99.83%): `flag=0;alpha=flag` target reuses r28 for
  stb; current `li r0,0;stb r0` extra instr. Same #110 const-copy fold.
- deathseq_update (dll_010E, 99.78%): f29<->f30 whole-body swap + fmuls operand. #82.
- xyzanimator_update (dll_013C, 99.69%): `unk4*6+rowCount*0xc` accum-reg r3-vs-r4;
  swap-terms regressed. int #108 + #70 relocs dominate.
- DFP_Torch_init (dll_022B, 99.81%): frame -64 vs -48 (16B), conversion-scratch +
  address-taken f32 spawnArg slot layout. #67 frame class. Not pursued (0.19%).

LESSON: #110 const-equal-copy (`li rY,K; mr rX,rY` where BOTH are literal K) is
UNREPRODUCIBLE at O4 (copy-prop always folds to fresh li); O1 wrecks the rest.
Recurring 1-instr cap on 99%+ fns. BANK on sight — don't burn attempts.
