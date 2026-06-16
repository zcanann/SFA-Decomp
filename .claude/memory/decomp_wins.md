# Decomp Matching Wins (dll_0000-0140 scope)

## ===== Session: 0 wins, ~13 attempts (hard #82/#108 residual band) =====
This wave's near-misses were dominated by FP/GPR coloring perms + frame layout, no
source lever. All reverted clean (no regressions committed). Banked:
- textrender getControlCharLen INLINED into GameText_CountPrintableChars (99.98%) +
  GameText_FindControlCodeArgs (99.99%): the dead loop counter `i` (`for i=45;i>=0;i--`,
  p++ walk) decrements by -2 in target (unroll factor 2) but -1 in current. STANDALONE
  getControlCharLen is 100% and uses -1. So it's an INLINING-CONTEXT optimizer artifact:
  post-inline strength-reduction picks -2 for the dead IV only when inlined. peephole/
  scheduling/opt_strength_reduction off all INERT. Index form (lbl[i]) walks wrong
  direction. Bank — can't control inlined dead-IV step from source.
- dll_002E_moveLib fn_80114408 (99.86%): REAL LATENT BUG found but UNWINNABLE on score.
  Line 137 `*(f32*)(p3+0x24)=vb` (vb=lbl_803E1C90) but TARGET stores lbl_803E1CA0 there
  (same value as posY/0x18 — it's the X-component of a 2nd vec3: [CA0,vb,vb,CA0,vb,vb]).
  Fixing to CA0 + hoisting `f32 va=lbl_803E1CA0` for CSE gets the structure right (f0=CA0
  at 0x18/0x24, f1=C90 elsewhere) BUT regs are SWAPPED vs target (target CA0=f1,C90=f0;
  MWCC always puts first-loaded const in f0). decl swap va/vb + load-C90-first all INERT.
  Net 99.63 < buggy-original 99.86 (the wrong-value version coincidentally byte-matches
  more because the perm only spans 2 stores). #82 commutative coloring frontier. The
  value fix IS semantically correct (siblings lines 782/815 use lbl_803E1CA0). Bank;
  retry only if a #82 f0/f1-first-load lever is discovered.
- dll_0104_smallbasket smallbasket_update (99.83%): `flag=0; alpha=flag` — target keeps
  flag in saved r28 and stores r28; current const-folds to fresh `li r0,0; stb r0`. #110
  const-equal-copy-fold. O1 wrapper REGRESSED hard (94.26). Bank.
- grenade trickyFn_80142eb0 (98.82%): `*(int*)stateFlags & ~0x10` produces rlwinm (1-bit
  andi clear); target wants `li -17; and` (materialized #74). Changing to `*(u32*)...
  & ~0x10LL` (matching siblings 782/815) DOES produce the `and` BUT introduces a `li r0,0`
  hoist for the adjacent `substate=0` store + r3/r4 perm → net 98.42 < 98.82. The rlwinm
  happens to byte-match the target's `li;and` better than the correct `and`+perm. Bank.
- camera Camera_UpdateViewMatrices (99.92%): `slot=base+off; slot+=4416` — target does
  both adds into r30 (`add r30,r31,r0; addi r30,r30,4416`); current uses r3 temp for
  base+off then `addi r30,r3,4416`. Single-stmt `base+off+4416` regrouped (K onto off).
  off-inline INERT. #108/#119 throwaway-temp coloring. Bank.
- baby_snowworm pauseMenuDoSave (99.95%): color[2] array + 4 outparams (texture/scale/x/y
  &-passed to objShadowFn). Frame=64 both; target lays color@8(low)/outparams@16-31,
  current color@24(high)/outparams@8-23. Decl reorder (color first/last, texture first)
  ALL INERT — array placement is fixed by MWCC independent of decl order. #67 frame. Bank.
- mm heapSpawnSlot (99.33%) / mmFreeDeferred (99.45%): pure r28/r29 (base vs count) and
  r3/r4 swaps. #108 within-class single-def creation-order. O2 wrapper regressed
  heapSpawnSlot to 94.43. un-naming `top` changed lwz-disp→lwzx (worse). Bank.
- mm mmFreeTick (93.17%): multi-issue — target RE-READS gMmDeferredFreeCount fresh per
  use (lha 0(0) ×2) for `g->deferred[count-1].ptr/.delay`; current CSEs the count (legit,
  no decrement between reads) + uses lwzx vs target's add-base+lwz-disp. End-pointer form
  INERT. Needs volatile-launder of the count + #112 disp grouping together. Bank (multi).
- objfx objfx_spawnBoxBurst (99.30%): prologue param-save INTERLEAVE — target emits
  fmr f29/f30/f31 (mulX/Y/Z) BEFORE `mr r23,r8`(origin) matching loop use-order (mul
  before origin); current saves all int params then FP. peephole/scheduling off INERT.
  #108 cross-class prologue interleave (use-order driven, no source lever). Bank.
- smallbasket fn_80157558 (99.86%): turnRaw/mag r28/r29 swap. decl reorder INERT. Bank.
LESSON: at 99.8%+, a "correctness fix" (moveLib CA0, grenade ~0x10LL) can score LOWER
than the buggy original if it unlocks a coloring perm — objdiff is byte-fuzzy, a wrong
const that shares a reg can out-score a right const that forces a swap. Don't commit a
correctness fix that regresses fuzzy% (per source-of-truth rule); bank it as a known bug.
LESSON: O1/O2 per-fn pragma wrappers REGRESS call-bearing dispatcher-style fns hard
(smallbasket_update 99.83→94.26, heapSpawnSlot 99.33→94.43) — only use O1/O2 for small
call-free loop fns (#110 caveat). Default-O4 is right for these.

## ===== Session (later): 3 wins, ~13 attempts =====
WINS:
- dll_000B fn_800A0524 (98.95->99.99%): else-clamp (s16==0 branch) wrote 3 separate
  stores `*c8=lbl;*cc=lbl;*d0=lbl` -> MWCC reloaded the const per store (3 lfs).
  Target CSEs (1 lfs + 3 stfs). FIX: chained-assign `*c8=*cc=*d0=lbl_803DF430;` (#51).
- dll_0072 dll_72_func03 (98.88->100%): #93 cmd-builder. Decl `base` BEFORE
  `e=buf.entries` so MWCC materializes the lbl base addr before the &buf.entries
  stack addr (matches target lis;addi-base then addi-r1 emission). Pure decl swap (#5).
- dll_01B5 lightfoot_update (98.98->99.01%): CORRECTNESS — flags400 clear in the
  challenge-target-hit branch was `&= ~0x4` but target clears 0x2 (the SAME bit tested
  by the enclosing `flags400 & 0x2` guard). rlwinm 31,29 not 30,28. Fixed mask. Residual
  = #81 fcmpo CSE/operand (lbl_803E8180 kept in saved reg across `-=timeDelta` store;
  current reloads) + int li r30/r27 perm — banked. LESSON: rlwinm MB/ME-width diffs in
  ndiff `--classify` are a RELIABLE correctness-bug vein (clear-mask off by one bit).

BANKED this session (no clean source lever):
- dll_0013 waterfx_onMapSetup (98.95%): `li r6,0` (the `e->active=0` loop-store value)
  scheduled AFTER 2 lfs const-loads; target emits it BEFORE. Hoisting an `int z=0`
  local before the cxyz/cf10 assigns was INERT (CSE'd, didn't move). Pure li-const
  scheduling, 2 regions. Bank.
- dll_0242 dbstealerworm_stateHandlerB06 (98.65%): loop `for(;n!=0;n--)Stack_Push(...
  off-=12)`. Target decrements n (r26) BEFORE the call (between the arg loads and
  off-=12); current after. Tried: while-at-top (moved n-- BEFORE loads, wrong),
  for-empty-update + n-- as first body stmt (moved n-- before loads again),
  `#pragma scheduling off` (INERT). The decrement needs to land BETWEEN the two arg
  loads (lwz msgStack, lwz *entry) and off-=12 — un-controllable scheduling within
  call-arg setup. Bank.
- objfx WM_newcrystalFn_800969b0 (98.78%): `lbl[i]*((1+phase)*0.5)` fmuls operand
  order — target `f1,f0,f31` (var,const), current `f1,f31,f0` (const first). 0.5f is
  HOISTED to saved f31 in BOTH. MWCC FULLY canonicalizes commutative FP mul regardless
  of source order (temp split + both operand spellings INERT). #66 canonicalization-
  inert case. Bank.
- dll_0265 drcreator_spawnProjectileCallback (98.96%): `lbl*conv` fmuls — same reg-perm
  (target lbl->f1 conv->f0, current lbl->f0 conv->f1). conv-to-temp split INERT. #82/
  canonicalization. Bank.
- grenade trickyFn_80143388 (97.3%) / trickyFn_801430e0 (97.4%): two-pointer-param
  coloring perm (#108/#126; both u8*/int params, target colors r28/r29 or r29/r30,
  current r31/r28). trickyFn_80143388 ALSO #112: `trickyState[val+0x81f]` target
  `addi val,2079; lbzx trickyState` vs current `add base+idx; lbz 2079` — inlining the
  ref var INERT (byte disp folds; coupled to param coloring). Bank.
- dll_801c0bf8 fn_801C0BF8 (98.63%): loop body bumps vertex(r23)+=16 then i(r22)+=1 in
  target; current i then vertex. while-loop + `scheduling off` both INERT. Plus a
  @96-vs-lbl reloc (score-neutral #70). Bank — bump order uncontrollable.
- dll_0035 saveSelectSetupMenuItems (98.89%): `off2=off1` (both 0) — target `li r4,0;
  mr r5,r4`, current two `li`. #110 const-equal-copy-fold, unreproducible at O4. Bank.
- dll_0229 dfplevelcontrol_setScale (93.3%): named ptr-local `p=lbl` gets `addi r0;
  mr r7` (extra copy) vs target direct `addi r5`; + `(s16)(i+1)` extsh-CSE'd into r5
  vs target re-extends from r6. peephole-off INERT. #80/#108. Bank.
- dll_00FF magicdust_init (98.72%): multi-issue — divisor lbl_803E34F4 load order
  (target loads before numerator in `(a-b)/lbl`) + switch beq structure (cmpwi 708
  binary-search differs). Multi-issue, bank.
- dll_02BB gflevelcon fn_8023A3E4 (98.0%): 23 regions, all r29/r30 param perm. #108.
- dll_002E moveLib dll_2E_func03 (98.6%): 34 regions, 29 reg-perm. #108. Bank.
LESSON: chained-assign `a=b=c=K` (#51) reliably CSEs a const across same-value stores
where separate statements reload — check ndiff for repeated `lfs lbl; stfs` bursts.
LESSON: #93 cmd-builder base-vs-&buf.entries decl order is a real lever (dll_72 100%);
for VOLATILE regs decl-base-first works; for SAVED regs (dll_93) it's #108 perm (the
randomGetRange mid-loop perturbs the web — decl swap regressed 5->17 regions).

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

## ===== Session (later2): 4 wins / 2 fns, ~8 attempts =====
WINS (all in TOP-LEVEL src/main, NOT dll/):
- newshadows initFn_8006d020 (79.88->82.61%, 3 commits):
  (1) `int collide`->`u8 collide`: target holds collide in saved reg as u8
      (li r4,1; clrlwi r0,r4,24; cmplwi) vs bare cmpwi. +0.88. #7/#58.
  (2) `attempts < 10000`->`< 10000u`: cmplwi not cmpwi (TWO sites, do/while
      + outer while). +1.7. #58/#64.
  (3) hoist __PADFixBits to FUNCTION-SCOPE local padFix: target keeps it in
      f26 across tex loop (fmuls f0,f26); current reloaded per use. +0.13.
      #45/#121. NOTE: block-scope inside tex loop REGRESSED (80.19) - must
      be function-scope.
  RESIDUAL (banked): second tex loop (line ~1862-1877) is multi-issue FP -
  inlined single-prec floor (target fmadds f29,f1,f25 vs current fmadd+frsp
  via double floor), multiple hoisted consts f27/f28/f29/f30/f31, sthx/sth.
  Tried `(f32)floor(cv)` cast -> REGRESSED 80.14. Banked FP-pressure.
- textrender setLanguageFn_8001ad64 (79.99->82.84%, 1 commit): THREE manual
  element-copy loops used `arr[i]` indexing -> base+index addr (add;lbzx/sthx
  with mr r0; addi; lbzx r,base,r0). Target walks POINTERS with post-incr +
  displacement-unroll. Rewrote as `*d = *s; d++; s++;` separate statements
  (NOT *d++=*s++ which merges). +2.85. Ref-table pointer-walk-vs-index lever.
  RESIDUAL: ~57 reg-perm (#82) + 2 `cmplwi r0,0` guard deletes. Banked.

CANDIDATE BANKED (pure #82/#108, no source lever):
- textMeasureFn_80016c9c (gametext, 75.7%): the 18 lbzx are IDENTICAL opcodes
  target vs current; ONLY diff is whole-fn saved-reg rotation (r30<->r28,
  r27<->r31, r5<->r4). Pure coloring. Verified NOT a copy-loop fix.
- ObjAnim_AdvanceCurrentMove (objanim, 82.5%): whole-body f0-vs-f4 reg-perm +
  fcmpo operand swaps. clampedStepScale homes f0(target)/f4(current). #82.
- drawGlow (expgfx, 69.9%): massive saved-reg scramble (r14-r22, f26-f31) +
  frame 256 vs 240. Heavy #108/#67. Banked.

LESSON: TOP-LEVEL src/main/*.c (textrender, newshadows, gametext) still has
STRUCTURAL veins the dll/ scope lacked: (a) signed-vs-unsigned counter compares
(cmplwi via `< Ku`), (b) u8 flag held in saved reg (clrlwi mask), (c) manual
copy loops with arr[i] indexing that should be pointer-walks. ndiff --classify
"cmp-width" + real "delete" blocks (not reg-perm) = the reliable signal. The
src .o objdump-disasm-by-symbol does NOT work here (use ndiff for both sides).
