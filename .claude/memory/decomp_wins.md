# Decomp Matching Wins (dll_0000-0140 scope)

## ===== Session (Jun17h, flat dll widthbranch): 4 %-wins + 1 correctness, ~10 attempts =====
WINS (committed local; push rejected remote-ahead, single attempt):
- waterfx_func05 (94.08->95.98%, e0bd88ef11): GXWGFifo.f32 drop-render block
  compiled interleaved load-then-volatile-store per statement; target computes
  all 3 (z-offz,y,x-offx) AFTER GXBegin then stores f0/f2/f3. Fix: temps
  declared in the if-block, GXBegin FIRST, then `vz=..;vy=..;vx=..` (z,y,x
  order), then 3 FIFO stores. CRITICAL: GXBegin must precede the temp computes
  (computing temps before GXBegin REGRESSED to 87.7 - reorders the call).
- Trigger_hitDetect (94.98->95.84%, f8aeb650f6): 3 levers. (1) fn_80198B68 args
  re-read obj->extra twice -> reuse hoisted `state` ptr (=obj->extra),
  `(int)state+0x28`. (2) Flip r1/r2 dispatch to `if(r1!=0){1/2}else{-2/-1}` so
  r1!=0 block lays out first (target beq on r1==0) - resolves inline
  objInterpretSeq -2/-1 ordering. (3) (u32)GameBit_Get(...)==0u -> cmplwi.
- CameraModeStatic_update (94.87->96.29%, 5f01d63b0a): (1) `camObj[1] =
  camObj[1]+(short)..` kept extsh; compound `camObj[1] += (short)..` (#20)
  drops it. (2) `(uint)*(ushort*)(p+4)` emitted lhz; target lha+clrlwi -> spell
  `(uint)(ushort)*(short*)(p+4)` (#46/#58).
- drearthcal_update (94.54->99.02%, 403d9fa9ad): BIGGEST. (1) player-scan over
  obj+0x58 child list MISSING target's top-of-loop guard - target reads count
  (s8 +0x10f) ONCE, `cmpwi 0; ble`. Add explicit `if (0<count)` BEFORE the for
  -> +4.5pt. (2) `==player` signed -> `(uint)*(int*)(...)==(uint)player` cmplw.
  LESSON: a missing `if(0<count)` before `for(i=0;i<count;..)` (body is only
  count user) is a real recoverable diff when ndiff DELETEs `lwz;lbz;extsb;
  cmpwi 0;ble` at loop entry - NOT coloring.
CORRECTNESS (flat %): alphaanimator_update (d405627e10): unk1C->unk1D byte-
  offset bug (two `s->alphaLevel=d->unk1C` should be unk1D; target lbz 29 not
  28). objdiff % flat (only load immediate changed) but real behavior bug.
BANKED (walls): magicdust_update (79.4%, #108+big-imm equality fold: target
  holds msgId 0x7000b in r31+cmpw, current folds >0xffff eq to addis -7;cmplwi;
  peephole/O1/operand-swap/register-int all INERT) | dll_5E_func03 (88.2%,
  arg-eval: target emits int arg1 `li r3,K` BEFORE lfs float args; sched/peep
  off INERT) | SaveGame_gplaySetObjGroupStatus (85.2%, unrolled loop walker
  addi r5,4 vs target fixed-base disp; strred-off REGRESSED -17pt globally) |
  softbody_update (94.5%, #82 FP coloring wrap-loop; #81 launder REGRESSED) |
  arwarwing_updateBarrelRoll (94.6%, hi/mid scheduling + reg pressure).
LESSON: width/ext (#20 compound +=, #46/#58 lha;clrlwi, #3 (uint) cmplw) +
  missing-loop-guard + branch-sense flips = RELIABLE flat-dll veins at 93-95%.
  FP coloring(#82), big-imm equality folds, arg-eval/sched order = WALLS, bank.
TOOLING: `objdiff-cli report generate` races w/ concurrent builds (transient
  missing placeholder .o) - retry-loop until exit 0. NEVER rm build/GSAE01/obj/
  (dtk-split target refs); restore via `rm build/GSAE01/config.json && ninja
  build/GSAE01/config.json`.

## ===== Session (Jun17g, src/main/dll/player.c): 5 wins, ~11 attempts =====
WINS (all clean structural levers, committed local; push rejected remote-ahead):
- fn_8029A4A8 (95.1->98.2%, 8d969ff237) & playerDie (98.15->98.88%, b7c85a051c):
  the lbl_80332ED4[0..6] death-cleanup loop. Spell `lbl_80332ED4[i]` indexed,
  NOT a walker `p=lbl_80332ED4; *p; p++`. Drops the separate walker pointer reg.
  RESIDUAL (banked both): #108 walker/counter saved-reg swap (target inits the
  counter via `mr rCounter,rZero` reusing the NULL-store zero, AND colors the
  walker LOWER than the counter; current inverts). Index form gains ~3pt; the
  final reg-swap resisted decl-order + chained-init `i=lbl=0` (REGRESSED both).
- fn_802957B4 (97.35->97.98%, 4b3cf64c46): modelState->flags &= 0xFFFFEFFFLL
  forced a high-word `li r3,0` that got REUSED for the adjacent inner->unk7F0=0
  store; target uses fresh `li r0,0`. Spell `&= ~0x1000` (32-bit, NO LL/U) ->
  rlwinm + separate zero store. CAVEAT: ~0x1000 gives rlwinm but target wants
  `li -4097;and` (materialized inverse) — 1-instr residual; both ~0x1000LL and
  0xFFFFEFFFU REINTRODUCE the high-word reuse (REGRESS to 95.0). The plain
  32-bit ~K is the only non-regressing form. (#74 high-word-reuse vein, same as
  enemy_update from Jun17d.)
- fn_80295CF4 (97.9->99.0%, 2869d57faa): `if (lbl==NULL || b40==a) return;`
  early-return guard folded the SECOND `||` term to `bne CONT;b RET` instead of
  target's shared `beq RET`. Split into TWO separate `if(...)return;` guards ->
  beq for each. RESIDUAL: 1 extra beq in the else-branch nested null check
  (target emits a redundant `cmplwi r3,0;beq b34;beq acc` double-beq #109d).
  LEVER: a 2-term `||` early-return where the 2nd term mis-folds to bne;b ->
  split into separate ifs (the inverse of #17 merging — here SPLITTING wins).
- fn_802AA4B0 (97.97->98.24%, bbf40dbf7e): TWO levers. (1) `(void*)setup==NULL`
  -> cmplwi (#3). (2) `mathSinf(fov)/mathCosf(fov)` tan: target calls sinf
  BEFORE cosf; current evaluated cosf first (mathSinf/mathCosf RELOC swap +
  fmuls operand swap). Split `f32 sn=mathSinf(fov); cot=lbl*(sn/mathCosf(fov));`
  -> sinf-first, kills the reloc swap AND the multiply-operand swap. RESIDUAL:
  #82 dx/dy/dz f30/f31 + pt/lbl_803DE44C base GPR perm in the targetObj branch.
BANKED this session (no source lever, reverted byte-clean):
- fn_802AA8D0 (97.59%): #82 base f3/f1 + divisor/bias f30/f31 swap +
  @370-vs-lbl_803E7EC0 conversion-magic reloc. decl-order swap INERT, (int)
  cast on randomGetRange INERT. The bias-magic named-vs-pool is tied to the
  f30/f31 class. Bank.
- fn_802AA2B0 (97.7%): target does `li r30,1; bl Camera_GetCurrentViewSlot
  (DISCARDS return); cmpwi r30,1` — slot is a constant 1 held in saved r30, the
  Camera return is thrown away. `int slot=1;` + separate call REGRESSED (96.0,
  MWCC const-folds the `if(slot==1)` away). Can't reproduce the un-folded
  tautology cleanly. Bank (slot-as-constant-1 + r30/r31 perm).
- fn_8029A76C (95.45%): frame -128(target) vs -112, all stack offsets shifted
  +24 (target r1+8/20, current r1+32/52) — TWO disjoint-branch structs pfx/pfx2
  that target keeps BOTH (bigger frame); merging to one REGRESSED (-112 too
  small). Plus `0x200001` spawn flag: target hoists `lis r28,32`(0x200000) to
  SAVED r28 across whole fn, `addi r6,r28,1` per call; `int spawnFlags=0x200000;
  ...spawnFlags+1` only hoists in the LOOP branch (LICM), the 2 non-loop calls
  re-materialize volatile r6. Multi-issue #67/#6. Bank.
- fn_802AF7F8 (99.31%): chained deref `r35c=*(int*)(extra+0x35c)`: target keeps
  base in r3 (overwrites), current copies to r4. Inlining the expr (#107) INERT
  (CSE keeps the copy). + death-loop coloring. Bank.
- fn_802ABFBC/fn_8029D4C0 (99.18/99.41%): the `d=(u16)getAngle(...)-(u16)field`
  idiom: target masks getAngle result INTO r4 (`clrlwi r4,r3,16;subf r4,r0,r4`),
  current masks in-place r3. Statement-split `d=(u16)getAngle(); d-=(u16)field;`
  INERT. Recurs across multiple player fns. Banked #82/#66. ALSO fn_802ABFBC has
  frame -176 vs -144 (#67 conversion-temp scratch for many `(f32)d`).
LESSON (CONFIRMED): the lbl_80332ED4 death-cleanup loop appears in MANY player
  fns (fn_8029A4A8/playerDie/fn_8029A76C/fn_8029ABD8/fn_80299E44/fn_802AF7F8 +
  caps). Indexed `lbl_80332ED4[i]` beats walker `p++` by ~3pt WHEN the walker is
  the only divergence; inert where it's already `p[i]` indexed (same codegen) or
  where the fn has bigger frame/coloring issues. Residual is always the #108
  walker/counter saved-reg swap (target reuses the zero-store reg for counter).
LESSON: a 2-term `||` early-return mis-folding the 2nd term to `bne;b` -> SPLIT
  into two separate `if()return;` (beq each). The `~KLL`-on-u32 high-word-reuse
  vein (#74) recurs in player.c too (fn_802957B4). Sin/cos tan eval order:
  split sinf into a temp before the divide to force sinf-first call order.

## ===== Session (Jun17f, FLAT dll): 2 wins, ~14 attempts =====
WINS:
- SaveGame_gplayAddTime (dll_0017, 87.9->99.4%, 433b6fb0fd): the final
  entry-address compute `base = gSaveGameData; p = base + i*8` emitted
  slwi(i*8) BEFORE the lis;addi(base). Target wants base materialized FIRST.
  FIX: split into `base=gSaveGameData; p=base; p += i*8;` (3 statements) ->
  forces lis;addi to emit before slwi. The single-expr `p=(u8*)gSaveGameData
  + i*8` was INERT (still slwi-first); the base-assign+`+=` split is the
  lever (#112 K-grouping cousin / base-first emission). RESIDUAL (banked):
  1 region operand-name in `add` (target add r4,r0(base),r4(i*8) vs current
  add r4,r4(base),r0(i*8)) -- which operand holds base. Pure naming.
  NOTE: same split trick was INERT on saveGame_saveObjectPos (loop keeps
  base live in r5; re-deriv has diff pressure) -- banked there.
- fn_8015CE68 (dll_00CA_mediumbasket, 89.6->90.3%, 30e56f9f1f): TWO fixes.
  (1) clamp `if (animSpeedA >= scale) scale = animSpeedA;` over-produced
  `cror eq,gt,eq` (the #25/#91 cror). Rewrite as `if (scale < animSpeedA)
  scale = animSpeedA;` (plain blt, no cror). The empty-then `if(scale>=x){}
  else{...}` form still gave cror -- the `<` direct form is the lever.
  (2) `if (controlMode==4){arg 0}else{arg 2}` -> target emits the else-arm
  (li r4,2) FIRST. Inverted to `if (controlMode!=4){arg 2}else{arg 0}` (#21).
  RESIDUAL (banked): frame -176 vs target -160 (16B) -- current emits an
  EXTRA `psq_st f31` paired-single save alongside stfd f31. Frame #67 +
  f0-vs-f31 scale home. Not cracked.

BANKED this session (no source lever found):
- saveGame_saveObjectPos (dll_0017, 90.2%): store block target loads
  objectId (lwz 76;lwz 20) BEFORE entry addr; current computes entry first.
  base-split flipped entry to base-first but objectId eval-order stayed
  entry-first. Eval-order of store RHS-vs-LHS not crackable. + prologue
  `beq;blr;li r7,0` (non-folded status guard) vs current `bnelr`.
- dll_200_SeqFn (dll_0200, 89.7%): TARGET uses a 7-entry JUMP TABLE
  (jumptable_80328A30, switch mode 0-6); current does if/else BINARY SEARCH.
  Source IS already switch(mode) w/ all 7 cases (1,4,6 bodies; 0,2,3,5
  empty). MWCC COLLAPSES empty cases->default => sparse => binary search.
  peephole off INERT; opt_strength_reduction off (pre-existing) INERT.
  Can't force jump table w/ empty cases (no side effects to keep them
  distinct). Prologue byte-identical thru clrlwi; ONLY the dispatch differs.
  JUMP-TABLE-vs-BINSEARCH heuristic cap. LESSON: empty switch cases that
  share default fall-through DON'T count toward jump-table density.
- trickyBallFn_801793b8 (dll_00F5, 86.3%): #108 whole-body saved-reg perm
  (obj/params/player/playerState r28-r31 scramble). Un-naming playerState
  (inline player->extra deref) REGRESSED 84.7 (target DOES hold it in saved
  reg). Banked.
- tree_init (dll_02AF, 98.7%): target CSEs lbl_803E72F8 const into f2 across
  TWO non-adjacent stfs (offset 64 then 60, integer stores between); current
  reloads f0 for the 2nd. Lift-to-local (#6) REGRESSED 98.1 (forces f31 save
  across later calls); reordering the 2 stores adjacent REGRESSED 97.6.
  Adjacent-store float-const CSE is an allocator decision no spelling hit.
- RomCurve_func1E/func16 (dll_0014, 88/86.5%): binary-search (inlined
  Objfsa_FindRomCurveById) coloring + _savegpr_26-vs-27 + romCurves
  re-derive. #108-heavy. Banked.
- fn_801343CC (dll_0041, 88%): #108 r23/r25/r26/r28 dual-loop scramble +
  extra mr copies between loops. Banked.
- groundanimator_free (dll_0138, 91%): GCC-style _savegpr prologue, whole-
  body #108 + frame -96 vs -80. Banked.
- tumbleweed_updateRollingMotion (dll_00D2, 87.4%): SJIS file. FP-conversion
  magic (__cvt lis 17200/xoris 32768, @NNN bias relocs #70) + 53-region
  coloring. Banked.
- pressureswitchfb_updateStateMode (dll_00FB, 99%): pure r4/r5,r7/r8 coloring.

TOOLING NOTE: ndiff.py reports "Unit not found" for SOME units
(dll_0047/00FB/0110) while function_objdump.py resolves them fine (.o exists
both trees). Workaround: function_objdump.py + awk-split target/current +
sed-strip addr/bytes + diff (normalized manual diff). Snippet used:
  grep -E "^[[:space:]]+[0-9a-f]+:" | sed -E 's/^[^\t]*\t[^\t]*\t//'
SHARED-TREE NOTE: .git had concurrent writers; my 2 commits got buried under
another agent's merge in `git log -3` linear view but ARE ancestors of HEAD
(merge-base --is-ancestor = YES). push rejected (remote ahead, no-pull rule)
-- commits safe on main for next agent's cycle. .git/objects unlink
"Operation not permitted" warnings are environmental (gc.log), commits OK.

## ===== Session (Jun17e, TOP-LEVEL src/main + dolphin): 3 wins, ~9 attempts =====
WINS (all top-level src/main, structural CSE/lbzx/pragma veins):
- textrender gameTextInitFn_8001c794 (62.7->65.9%, e6fa5b99a7): the two
  unrolled tile-copy loops (16x16/20x20). Target walks ONE off register
  re-added to src per row (add r8,r4; lhzx col) + bump-at-top; MWCC
  strength-reduced to 4 saved row pointers + folded col-0 xb=0 to lhz disp.
  #1 lever: `#pragma scheduling off`+`peephole off` round the fn (reset
  after) recovered the lhzx index form +3.2%. RESIDUAL (banked): the
  4-pointer row-base CSE across the two j-loop halves + col-0 xb=0
  displacement fold. Single-use rp=(u8*)src+off recompute was INERT
  (re-folds). opt_strength_reduction already off (pre-existing); toggling
  it on was slightly worse.
- lightmap updateVisibleGeometry (81.8->83.1%, 258d518650): #1/#80. Named
  pointer locals py/pz/pd=&gViewFrustumPlanes[1..3] made MWCC hoist the
  gViewFrustumPlanes BASE into saved r31 (frame+16, cam ptr rotated to r31).
  Writing stores as gViewFrustumPlanes[n*5+k] directly re-derives base per
  store, drops the saved-reg base. RESIDUAL (banked): target keeps 4
  per-element base pointers (gVFP+0/+4/+8/+12 in r3/r31/r30/r29) indexed by
  n*5 (li N; mulli ,20; stfsx) with n LIVE; current folds n to const disps.
  Restoring px/py/pz/pd 4-base form REGRESSED (76.4 - MWCC folds n anyway,
  bases become overhead). The n-nonfold is the open frontier (#28/#111).
- tex_dolphin drawLightmapIndirectPasses (86.8->88.3%, eecaaf5fa7): #112/#30.
  Bit-reader byte0 `*(u8*)(*bitReader+(pos>>3))` shared the +(pos>>3) sum
  with bptr CSE -> lbz 0(bptr). Spelling byte0 as ((u8*)*bitReader)[pos>>3]
  keeps base+index separate -> lbzx r,base,index (matches target). RESIDUAL
  (banked): (u8)i CSE'd into extra saved r25 (target re-masks clrlwi per
  use, saves r24 instead) + frame+16.
BANKED (no source lever this pass, all reverted byte-clean):
- newshadows fn_8006CB50 (73.7%): tile-gen loop. Target hoists 5 loop-inv
  consts (Udchuff[3],lbl_803DED28,Udchuff[6],Vdchuff[0],Udchuff[7]) into
  VOLATILE FP regs f11/f10/f8/f4/f3 before the loop (no FP calls in body -
  sqrt inlined). Hoisting to fn-scope locals put them in SAVED f30/f31 +
  grew frame (live range crosses textureAlloc call) -> 48% REGRESS. Moving
  loads AFTER textureAlloc got volatile regs but still 2 saved + base-ptr
  r7 hoist (from [4]/[5] array reads) -> 59% < 73.7 baseline. Bank: needs
  individual @sda21 scalar reads + no base-ptr hoist, didn't crack.
- lightmap renderSceneGeometry (82.6%): 4 box-fill loops unroll-by-8. Target
  count form (box1+1-box0)>>3 no entry guard; current adds cmplwi;beq. Source
  `while(n!=0)` -> do-while REGRESSED hard (62%, broke unroll). Plus stack-slot
  decl order (box0..3/cv/cv2/map at wrong offsets, frame -208 vs -240) + extra
  r30 buf slot. Multi-issue #67/unroll-internals. Bank.
- objprint staffMtxFn_8003b620 (86.2%): joint loop reads t+(off+K). Target
  keeps off in r23 index (addi r0,r23,K; lfsx); current strength-reduces
  t+off into induction ptr (add base; lfs K). opt_strength_reduction off INERT.
  #112 single-use re-folds. Bank.
- render modelRenderFn_80006744 (87.3%): 1-instr mr (slw;mr vs slw) on acc +
  *p CSE for hi/idx; rest heavy r5/r6/r8/r10 bit-test reg-perm. #108. Bank.
- shader mapBlockFn_80059354 (87.9%): 3x scan-loop goto-found. Target b-over-b
  (bne;b) vs current beq + extra saved r24 + redundant slot copy (mr r28,r0;
  mr r3,r0 vs reuse r25). Multi-issue #108/#109d. Bank.
LESSON (CONFIRMED): the #112 lbzx-vs-lbz crack works when the byte/half load
  shares its base+index sum with a NEARBY pointer CSE -> spell ONE as an
  array index `((T*)base)[idx]` to keep base+index in separate regs. Worked
  tex_dolphin (single-use index here is FINE - the CSE sharing is what folds,
  not single-use). Contrast objprint where it was inert (strength-reduced loop).
LESSON: peephole+scheduling off recovers index/bump-at-top loop forms on
  manually-unrolled byte/half copy loops (textrender +3.2%). Try FIRST on
  unrolled-copy fns showing lhzx-vs-lhz or 4-pointer-CSE.
LESSON: hoisting loop-invariant consts to fn-scope locals only helps if target
  keeps them VOLATILE (no FP calls in loop); if the decl's live range crosses
  a setup CALL it forces SAVED regs + frame growth (newshadows regress). Place
  the loads AFTER the call if matching a post-call volatile hoist.

## ===== Session (Jun17d, baddie DLL scope): 3 wins, ~11 attempts =====
WINS (all clean structural levers, committed locally; push rejected remote-ahead):
- dll_00C9_enemy enemy_update (99.3->100%, 9494947eb4): controlFlags is u32 but
  the clear used `&= ~0x8003LL` (64-bit). The LL forced a spurious `li r4,0`
  high-word zero that MWCC HOISTED and REUSED for the adjacent `rotZ=0; rotY=0`
  sth stores; target uses a fresh `li r0,0` at the stores. Drop the LL ->
  single 32-bit AND + fresh zero -> BYTE MATCH. **LEVER: a `~KLL` mask on a u32
  field is only harmful when the high-word `li r4,0` gets reused by a nearby
  const-zero store — most `~KLL` on u32 (flags2DC etc.) are fine (already 100%);
  the tell is `li r4,0` co-located in the diff with `sth/stb r4` zero-stores
  near a 64-bit mask. NOT a blanket sweep — situational.**
- dll_00D0_grimble grimble_update (94.9->98.8%, 80a42b6f30): the
  `(*gPlayerInterface+8)` state-machine dispatcher was declared
  `(int,char*,void*,void*,f32,f32)` (floats LAST). CANONICAL (see kaldachom
  line 478) = `(double,double,int,int,void*,void*)` floats FIRST. Target emits
  state(r4) then the two f32 args; the floats-last sig mis-ordered emission.
  Rewrote sig + call to floats-first. Residual 1.2% = 1 mr-position + 2 @125
  pool relocs (#70 neutral). **CAVEAT: this dispatcher's arg order is NOT
  universally floats-first — fn_802BE6E8 (drearthwarrior) uses floats-MIDDLE
  `(int,int,f32,f32,...)` and is 100%. Depends on whether target emits floats
  before/after the int args; grimble's floats were a NAMED const (lbl_803E2EBC)
  not timeDelta, which schedules differently. Check the diff (mr-before-fmr vs
  fmr-before-mr) before flipping.**
- dll_00DF_hagabon hagabon_update (88.6->89.2%, ac156073e7): `shouldNotSaveTime`
  was cast `(u8(*)(int))` -> clrlwi;cmplwi. Interface decl is `int(*)(int)`;
  drop the cast -> cmpwi (#11/#124 cmp-width vein). Residual = +1 saved reg
  (`_savegpr_27` 5 regs vs target 4 individual stw, frame -80 vs -96) = the
  CSE-into-saved-reg vein (target holds obj+3 derefs in 4 regs, current CSEs a
  5th). Banked the saved-reg part.
BANKED this session (no source lever, reverted byte-clean):
- dll_00E0_swarmbaddie swarmbaddie_update (96.0%): d[3] array dead-store — target
  keeps the d[2] store, scalars dx/dy/dz INERT (DSE direction unchanged). #8.
- dll_0262_drakormissile drakormissile_render (96.7%): base/walker p/m r26<->r30
  swap (target keeps orig base r26, walker r30; current swapped). decl reorder +
  m re-derive (VN-folds) INERT. #108 single-reg.
- dll_00D2_tumbleweed tumbleweed_updateEffects (98.8%): `field++` stb stores from
  r4(masked) vs target r0(raw +1). separate masked var INERT. #20/#108 sub-instr.
  (SJIS carrier file — edits warn but EXIT=0.)
- dll_00D2_tumbleweed tumbleweed_updateTargetedStateMachine (99.0%): `player =
  field284 ? field284 : GetPlayer()` ternary -> target r3 direct, current
  lwz r0;mr r3 + f30/f31 FP swap (#82). if-embedded-assign form REGRESSED. Bank.
- dll_00D9_pollen fn_8016A660 (98.9%): `if(locked){body}` guard = target
  `bne body;b end` (2 instr) vs current `beq end` (1 instr, fused). peephole off
  INERT. + 3 @101 pool relocs (#70). Effectively 1-instr cap. Bank.
- dll_01A1_nwmammoth nw_mammoth_update (97.3%): multi-issue — table=lbl_803267C0
  named-ptr extra mr (#80, (int) launder INERT) + stateFlags[stateIndex] CSE'd
  vs target re-reads (VN-bound, #130) + slwi/lha ordering. Bank.
LESSON: baddie core units (enemy/tricky/unk/wispbaddie) are ALL 100% already;
  the remaining baddie work is in creature DLLs (grimble/hagabon/tumbleweed/
  drakormissile/nwmammoth/swarmbaddie). proto report fuzzy = PERCENT (0-100) not
  0-1; field3 fixed32 per fn. Cleanest veins THIS wave: (a) `~KLL`-on-u32 when
  the high-word zero is reused (enemy 100%); (b) state-machine dispatcher arg
  order floats-first when target emits floats-before-ints (grimble +3.9, A/B);
  (c) cmp-width drop-u8-cast (#11). Remaining band is #108 saved-reg/single-reg
  perms + #82 FP swaps + branch-fold + pool relocs.

## ===== Session (Jun17c, flat dll_0000-0140 scope): 3 wins, ~7 attempts =====
WINS (all clean structural levers, committed locally; push rejected remote-ahead):
- dll_0271_drakorhoverpad drakorhoverpad_updateMain (86.9->88.6%, bbe34bbb2d): the
  verticalVel clamp. (1) abs via TERNARY `v=(v>=0)?v:-v` (#63) not `if(v<0)v=-v` —
  target uses cror eq,gt,eq + bne/fmr/b/fneg (keep-or-negate), source's if gives
  bge;fneg. (2) FOLD both adjust arms into ONE add: `vv = vv + ((vv>*p)?-limit:limit)`
  so MWCC emits fneg + shared fadds (#27) instead of separate fsubs(arm1)/fadds(arm2).
  RESIDUAL banked: phase = lblA * (f32)(int)getAngle(...) / lblB — target loads lblA
  into f2 BEFORE the int->double conversion (keeps live, fmuls f1,f2,f0); current
  reloads lblA after. Pure multiply-operand load-scheduling, scheduling-off INERT
  (it's isel/eval order). Bank.
- dll_0001_camcontrol camcontrol_updateTargetFeedback (92.7->93.2%, 12d3552666):
  (1) reticle-INACTIVE branch: target calls ObjAnim_SetMoveProgress in a STANDALONE
  if(target!=0) BEFORE a SEPARATE if(target==0) sfx dispatch — NOT if/else. Source
  had it as the else of the target==0 dispatch. Split into two ifs. (2) flip active-
  branch guard `NormalizedMin >= progress` -> `progress <= NormalizedMin` so fcmpo
  loads progress into f1 first (cror lt,eq matching target vs gt,eq). RESIDUAL: the
  `||` FadeIn shared-block (focus==target || progress<Max) still emits inline bge vs
  target cror+branch-to-shared. #17/#91 pinned-|| — didn't crack.
- dll_0137_alphaanimator alphaanimator_update (93.9->94.6%, dceed61988): CORRECTNESS
  BUG. switch case 0 both clamp arms wrote `s->alphaLevel = unk1C` but target stores
  unk1D (offset 0x1D, the bound just compared). Verified: target `sth r3,20` where
  r3=`lbz 29(r30)`(unk1D). Fixed both arms. Cases 1/2/3 all verified MATCH after.
  RESIDUAL: mullw operand order (#66 inert) + case-3 FP const scheduling (lbl_803E3F90
  neg/lfd bias) + 1 reg-perm. METHOD: ndiff `lbz K(r30)` offset diffs (28 vs 29) on a
  byte-field-heavy dispatcher = field-ownership bug vein (#122/#46) — decode target
  asm per case to find which clamp stores the wrong adjacent field.
BANKED this session (no source lever, reverted byte-clean):
- dll_0117_appleontree appleontree_update (93.6%): obj param r29(tgt)/r31(cur) +
  derived extra(lwz184) r31/r29 swap + 1 stack slot (#67). #108/#126 pointer-param
  copy-pool classing. Didn't risk big obj-uncache edit.
- dll_0016_screentransition screenRectFn_800d7568 (90.5%): col2 HudColor struct at
  stack 8(tgt)/52(cur) (#67/#120 aggregate placement) + `(span>>1)&0xffff` srwi+clrlwi
  separate(tgt) vs fused rlwinm(cur) + spurious clrlwi before u8 col.a store. Many
  reg-perms. Multi-issue #67/#108.
- dll_00D5_kaldachom kaldachom_update (93.1%): control(lwz1036) r29/r28 swap + vtable
  call-arg FP-const scheduling (mr r3,r30;mr r4,r31 before vs after lfs). #29/#82.
- dll_0047_cameramodeteststrength fn_8010AEA8 (87.1%): target re-derives `lwz
  lbl_803DD560` (global ptr) FRESH per store; current CSEs. Also q=lbl_803E1888 to f31
  via extra fmr f31,f0 (target lfs f31 direct). #130 global-base CSE needs volatile
  launder (risky). Bank.
- dll_0141_lightning lightning_update (93.1%): the style bit-flag `(flags->style?1:0)`
  call-arg (after the search loop) is HOISTED into saved r27 by MWCC, pushing the loop
  counter objectIndex r27->r31. Target computes style INLINE at the lightningCreate
  call (r0). opt_loop_invariants off INERT (not in a loop), opt_propagation off
  REGRESSED 91.4. #108 — no source lever to stop the pre-loop hoist of an invariant.
LESSON: clean structural veins still exist in flat dll_0000-0140 at 86-94%: (a) FP
  clamp ternary-abs + shared-fadds restructure (#63/#27); (b) standalone-if vs if/else
  call placement + fcmpo operand-order flip; (c) byte-field OFFSET bugs on switch
  dispatchers (lbz 28-vs-29 in ndiff = wrong adjacent field, decode per-case asm).
  The 93%+ band is mostly #108 pointer-param copy-pool / global-CSE / #67 frame.

## ===== Session (Jun17b, dll_0141-02FF scope): 2 wins, ~6 attempts =====
WINS (both = drawTexture per-file extern WRONG arg order):
- dll_003D_titlemenuitem TitleMenuItem_render (83.61->100.00%): per-file
  `extern void drawTexture(void* texture, u8 alpha, f32 x, f32 y, u16 scale)` had
  alpha BEFORE the f32 coords. CANONICAL sig across codebase (newshadows/textrender/
  dll_02C0/dll_0031) = `(void*, f32 x, f32 y, int alpha, int scale)`. ABI-identical
  (FP->f1/f2 by FP-index, int->r3/r4/r5 by int-index, INDEPENDENT of list position)
  but eval/EMISSION order follows list position: target evals floats first, alpha LAST
  (li r4 right before bl). Fixed extern + reordered 3 calls. PLUS (u8) mask on case-2
  alpha*0x96 (target masks before mul) + `frameDelay--; if(<0)` -> `if(--field<0)`
  (keeps decremented val live, drops reload). 100% (residual=#70 @NNN reloc). 29548b9bd1.
- dll_003C_tumbleweedbush Link_render (85.43->94.86%): SAME wrong-order extern. Fixed
  sig + reordered 3 calls. Residual 5% = r27/r28/r30 saved-reg perm (#108). eecec9df1a.
LEVER (RELIABLE): grep `extern void drawTexture` per-file — any with alpha before
  `f32 x` is WRONG -> fix to canonical + reorder calls. Only 2 files had it (both won).
  Arg-EMISSION order = callee param POSITION (#29/#87): floats-before-int in the sig ->
  floats eval first. Check other varargs draw/text fns with mixed int+f32 args.
BANKED (no source lever, reverted byte-clean):
- dll_0045_camTalk firstPersonExit (91.86%): yaw/pitch clamp fcmpo-operand swap (target
  fsubs f1,f2,f3 keeps start@f2/end@f3 live; current lands fVar1 in f3) + outer-guard ||
  term order. `17C4<=start`->`start>=17C4` only flipped cror lt->gt (inert). #81/#82. SJIS
  file (compiles w/ warning, EXIT=0).
- trex_lazerwall TREX_Lazerwall_popQueuedState (87.05%): target CSEs state->stack (0x9B0)
  into saved r28 (mr r3,r28 x6); current re-reads lwz r3. Lifting to `int stack` REGRESSED
  (86.84). #6/#45 inert / #108.
- dll_004A_cameramodeshipbattle CameraModeShipBattle_update (87%): fdivs-repeated vs
  reciprocal-CSE + fmuls/fnmsubs operand perm. FP #82.
- dll_0013_waterfx fn_80095164 (86.4%): whole-body f20-f31 reg shift-by-one (#82) + one
  `li r30,0; mr r29,r27` index setup. Bank.
- dll_80136a40 debugPrintfxy (87%): p1/p2 both=(u8*)buf-1; target materializes addi r1,115
  TWICE (two saved regs), current = one addi + two mr (#94 CSE-temp copy / #80) + add-sum
  CSE. Multi-issue. Bank.
LESSON: ndiff region count is a POOR fuzzy% proxy on reg-perm fns — Link_render went 46->47
  regions but 85->95% (drawTexture region cleaned, perm regions reshuffled). VERIFY with
  report.json fuzzy_match_percent. Report build aborts if ANY unit fails compile (other
  agents' WIP) — retry locked_ninja (transient). config.json is consumed by split step;
  objdump directly: powerpc-eabi-objdump -drz -M gekko --disassemble=SYM
  build/GSAE01/{obj=target,src=yours}/main/dll/UNIT.o.

## ===== Session (Jun17, top-level src/main): 3 wins, ~6 attempts =====
WINS (all TOP-LEVEL src/main, big fns, saved-reg/CSE/temp veins):
- newclouds_update (85.9->96.0%, 3 commits): the WIN VEIN was target re-derives
  the cloud pointer (lbl_8039A828[id]) + index id FRESH per use; MWCC CSE'd it
  into 8 saved regs (_savegpr_24). (1) Redefine NC_CLOUD macro to re-read
  *(u16*)(params+0x26) for the index + drop the cached 'p' local entirely (use
  NC_CLOUD at every deref incl null checks) -> 8->5 saved regs (#80/#107/#130).
  (2) Re-read id from params at the bounds check / env[idx] / snowKill-arg too
  (drop the cached 'id' local) -> 5->4 saved regs, frame 128->112. (3) Reorder
  posB/posA decls BEFORE vec/args so posB@20/posA@32 match target offsets (#67/#5).
  RESIDUAL ~4%: @881/@882 pool vs lbl_802C1FA8/FB4 named (#70 neutral, but ties the
  posA/posB zero-init EMISSION order — split-decl to fix order LOST the blob copy,
  regressed to 85). #112 env+idx*12+0x14 lwzx (paren-group + named-ptr both re-fold).
- Camera_InitState (89.8->94.2%): `slot = base + i*96 + 4416` FUSED the i*96
  multiply into the slot pointer reg (mulli r5; add r5,r31,r5); target uses a
  throwaway r0 (mulli r0,r0,96; add r5,r31,r0; addi r5,4416). FIX: split into TWO
  statements `slot=(T*)(base+i*96); slot=(T*)((u8*)slot+4416);` -> multiply lands
  in its own temp. #112/#119. (NOTE: sibling Camera_UpdateViewMatrices was BANKED
  with the same pattern as off-inline-INERT — but the 2-STATEMENT split is the
  crack, not inlining the off var. RETRY that bank with the 2-stmt split.)
  RESIDUAL 6 regions: lfs lbl_803DE62C FP-const scheduling in C_MTXLightPerspective
  args + addi/li lbl_803DC88A reorder. scheduling-off INERT (eval/isel order).
- ObjSeq_update (86.40->86.51%, marginal): #20/#53 compound-assign `*(s16*)(p+0x30)
  -= (s16)framesThisStep` drops a spurious extsh in the 3-iter cooldown loop.
  Rest is an 18-saved-reg (_savegpr_23) whole-body perm + frame 176 vs 160 (#108/#67).

BANKED (perm/scheduling-dominated, no further source lever this pass):
- voxmapsFn_80010ff4 (85.0%): 18 saved regs both, frame 112 vs target 128 (one
  extra scratch slot #67c), whole-body within-class perm. +1 real extsh on
  state->unk1C=idx+1 store. Heavily #108.
- voxmaps_updateRoutePath (89.8%, 16 regions): #66 operand load order (tgtX-node->x
  loads node->x first), heap sift-up loop reorder, #21 r==0/>0/<0 branch-chain
  layout (target beq;bge;cmpwi -1 vs our bne/ble chain). Multi-issue.
- Camera_UpdateProjection (89.9%): INVERSE of newclouds — target CSEs activeViewIndex
  into r31 (clrlwi;mulli 52), we re-read gCameraCurrentViewIndex global per use. +
  lfs scheduling (inert). Subtle CSE, near-complete, didn't risk.
- shader doPendingMapLoads (84.5%): frame -2592 (big buf), reg-perm + 1 cmp-width.
- objseq RomCurveInterp_EvaluateOffsetPosition (40 regions), shader
  mapLoadUnloadObjects (106), object objFreeObjDef (63): perm-heavy, not pursued.
LESSON (CONFIRMED + STRONGEST this pass): the saved-reg-CSE-vs-re-derive axis is the
top-level src/main vein. When target holds FEWER saved regs than us, find the value
MWCC is CSE-ing into a saved reg (a pointer/index derived from a global or param) and
force re-derivation: re-read the source expr (global deref / *(u16*)(param+K)) at EACH
use and DROP the cached local entirely. This collapsed newclouds 8->4 saved regs +
frame. Diagnostic: _savegpr_NN with a LOWER N than target = too many saved regs = a
CSE'd derived value; grep the body for the repeated lwzx/add holding base+index.
LESSON: 2-statement split (`p=base+off; p=(T*)((u8*)p+K)`) cracks the throwaway-multiply
temp coloring where inlining the offset var is inert (Camera_InitState; retry banked
Camera_UpdateViewMatrices). The multiply must NOT be the same SSA var as the final ptr.
TOOLING: report generate ABORTS (writes nothing) if ANY base .o is missing (other
agents' broken WIP like dll/player.o). Workaround: temp-swap objdiff.json to a 1-unit
config (python filter units list), generate, restore objdiff.json. report.json on disk
may be DAYS stale -> never trust it; always regenerate scoped.

## ===== Session (Jun17): 1 win, ~6 attempts =====
WIN: dll_00D3_staffAction dll_D3_update (86.93->88.10%). flags92 bit-1 (value 2)
  set used `(x & 0xfd) | 2` -> andi.;ori;clrlwi. Target: `li 1; rlwimi r0,r3,1,30,30`
  (single-bit insert). FIX (#12): split StaffBits `lo:2` into `b1:1; b0:1` and model
  BOTH the guard read (`->b1 == 0`) AND the set (`->b1 = 1`) as bitfield ops. lo field
  was unused so split was safe. Committed bc28b80692 (push rejected, remote ahead).
BANKED (no source lever):
- dll_00D3 same fn residual: `(f32)((double)(u32)aggroRange - lbl_803E3040)` where
  lbl is extern double. Target does ONE fsubs (magic - lbl_combined) because its
  lbl_803E3040 .sdata2 value = 2^52+K (bias fused). Current does fsub(magic-@139_2^52)
  + fsub(-lbl) + frsp (two-step). Dropping the `(double)` cast INERT (`(u32)-double`
  still promotes+splits). Can't fuse an EXTERNAL double into the conversion bias from
  source. Plus dominant r27-vs-r26 obj perm (#108). Bank.
- dll_00FF_magicdust magicdust_update (79.4%): obj param colors r28(tgt)/r30(cur) +
  TWO spurious obj copies (r29,r31) + `register int msgId=0x7000b` FOLDED inline
  (cmpw r31 tgt vs addis;cmplwi cur). playerObj/player split reorder INERT. #108/#126
  pointer-param copy-pool + const-fold. Bank.
- dll_0017_savegame saveScoreFn_800e88b4 (82.7%): target uses STACK FRAME + saves r31
  for inner-loop IV `i`; current uses no frame (i in volatile r11). Also initials[1..3]
  stores RE-DERIVE saveData global base (`lis;addi saveData; add; add rank*8`) vs
  current reusing the `file` ptr. Frame-class #67 + #80. Bank.
- dll_005E_dll5efunc0 dll_5E_func03 (88.2%): pure li-const scheduling. Vtable
  addSequenceSpawn(2, lfs, lfs,...) — target emits `li r3,2` BEFORE the lfs FP-const
  loads; current schedules first lfs before li. `#pragma scheduling off` INERT (it's
  eval/isel order not scheduler). 13 calls each 1 mispositioned li. Bank.
- dll_004A_cameramodeshipbattle CameraModeShipBattle_update (87.0%): target RE-DERIVES
  `lbl_803DD570` base (lwz r3) AND reloads `timeDelta` (lfs f1) FRESH per division
  statement; current CSEs both across statements (#130/#71 inverse). Global-base CSE
  that target doesn't do — needs volatile launder (too risky). Also div-result reg
  f2(tgt)/f1(cur) + fmuls/fnmsubs operand perm (#82). Bank.
LESSON: cmp-width/li-const ndiff buckets aren't always winnable — the dll/* low band
is heavily #108 (pointer-param copy-pool perms) + global-read CSE (target re-derives,
MWCC CSEs). The reliable vein THIS wave was #12 bitfield: a `(x&~K)|K` flag set ->
andi.;ori vs target's li;rlwimi single-bit insert. Grep for `& 0x..) | ` flag sets.

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

## ===== Session (Jun17f, FLAT dll_0141-02FF): 2 wins, ~7 attempts =====
WINS (both committed locally; pushes rejected by remote-ahead, banked):
- bombplantspore_update (dll_01AA, 89.9->90.2%): #3 `!= 0u` (u-suffix) on the
  `(state->stateFlags >> 6 & 1) != 0` bit tests (2 sites) -> cmplwi not cmpwi.
  stateFlags is u8 at off 0x2B0. RESIDUAL (banked, all #108/#128 caps): (1)
  detonateMessage=0x7000B folded by current (addis;cmplwi) vs target keeps it
  live in saved r30 + cmpw -- #19 non-foldable lever has no clean C form here
  (no adjacent call to source it from); (2) ObjMsg_Pop stack offsets 8 bytes
  lower in current (16/12 target vs 12/8) + target saves extra r28 for loop
  counter `i` while detonateMessage holds r30 -- pure pressure/coloring; (3)
  several objfx_spawnDirectionalBurst calls: target evals `li r8,0;li r9,0`
  trailing args BEFORE the lfs f1/f2 const loads, current after -- arg-eval
  order; (4) FP clamp chain register perm (#82). Frame/coloring caps.
- gunpowderbarrel_hitDetect (dll_0158, 94.7->95.3%): #3 `!= 0u` on the
  `((state->heldFlags >> 7) & 1) != 0` tests (2 sites) -> cmplwi. heldFlags u8.
  RESIDUAL (banked, DSE cap): target reserves+stores the sp1c[3] throwVel-delta
  stack vector (stfs 28/32/36) that current DEAD-STORE-ELIMINATES, shifting the
  whole frame down 12 bytes (collision_buf at r1+28 vs target r1+40; lbz 109 vs
  121). sp1c is NEVER passed to a callee, so #8 struct-wrap was INERT (struct
  doesn't escape -> still DSE'd); `(void)sp1c` already present is INERT;
  scheduling off INERT (it's DSE not scheduling). The original source must have
  passed sp1c to a vector helper (the inline fadds suggest it got inlined). Open
  -- needs a genuine escape that doesn't change semantics. Also FP fmuls/fadds
  operand-order perm (#59) banked.

ATTEMPTED, BANKED AS CAPS (no win):
- lightning_update (dll_0141, 93.1%): the `style ? 1 : 0` flag bool (LightningFlags
  bit at state+0x25, bit 0x20) is LICM-HOISTED into saved r27 ABOVE the obj-scan
  loop in current; target RECOMPUTES it fresh after the loop (lbz 37; rlwinm 27;
  cmplwi; li 1/0 + clrlwi r7) so the loop COUNTER gets r27 (target) vs r31
  (current). T=C=228 instrs, pure hoist-decision + coloring. TRIED:
  opt_loop_invariants off (INERT), opt_common_subs off (WORSE, 37 regions).
  The @152-vs-lbl_803E4098 reloc is #70-neutral. #108/LICM cap.
- crrockfall_update (dll_016A, 92.4%): r26-vs-r27 whole-fn coloring perm + the
  shadowAlpha conversion-magic. Target uses NAMED lbl_803E46F8 unsigned-u8->dbl
  magic (lis 17200; no xoris) for `(f32)(u32)*(u8*)(obj+0x37)`; current uses
  @100/@210 anonymous (NEUTRAL #70). The streams are near-identical -- mostly
  coloring + 1-2 fmuls operand-order. Low-yield #108 cap.
- DR_EarthWarrior_update (dll_0257, 93.3%): pure #108 -- r26<->r29, r28<->r26,
  f30<->f31 perm + one block reorder. T=C=280. Coloring cap.
- dbstealerworm_stateHandlerA0D (dll_0242, 94%): #128-ish. Current parks
  `&stk.msgN` (sp+K) into saved r29 + `mr r4,r29`; target materializes `addi
  r4,r1,K` inline at the Stack_Push call. obj param (r28 current) gets SPILLED
  (stw/lwz r28,64(r1)) due to the extra saved-reg pressure; target reuses r29
  (obj's reg, obj dead after the pos block) for `q=sub->msgStack`. T=151 C=154
  (3 extra). `q`/`msgStack` used 37+/47 across the WHOLE file -> can't safely
  inline-drop q globally. Open #128/#108 pressure cap.
- cloudprisoncontrol_update (dll_0145, 93.9%): dense r4/r5/r6/r7 coloring perm +
  2 value-liveness diffs (target keeps r7 live; current reloads lwz 16(r1)).
  T=234 C=239. Coloring cap.
- FEseqobject_SeqFn (dll_0143, 94.6%): FRAME-CLASS cap (#67). Current frame 112
  vs target 96 (+16): (a) the `effect` FEseqobjectEffectParams[20B] stack temp
  sits 8 bytes higher (off 32 vs 24; addi r5,r1,32 vs +24); (b) a SPURIOUS
  `psq_st f31,104(r1)` paired-single save current emits that target doesn't
  (target plain stfd f30/f31 only). `register int self = obj;` is LOAD-BEARING
  (removing it -> 38 regions, target uses self in r28). The psq_st + effect
  8-byte misplacement is the open frontier (maybe effect needs 8-align like the
  #67 union trick, untried).

LESSON (this band): FLAT dll_0141-02FF 92-95% is DOMINATED by #108/#82 coloring
perms (DR_EarthWarrior, crrockfall, cloudprisoncontrol all T==C instr-identical-
except-regs) and #67 frame-class (FEseqobject psq_st). The reliable vein remains
#3 `!= 0u` on u8 bitfield `>>N & 1` tests -> cmplwi (both wins this session were
this exact lever; grep `>> [0-9] & 1) != 0` for more). DSE of never-escaping
stack vectors (gunpowderbarrel sp1c) resists all source levers tried.

## ===== Session (creature DLLs): 5 wins / 4 fns, ~16 attempts =====
WINS (all committed, push rejected once = local only, never pulled):
- nw_mammoth_update (dll_01A1, 97.25->98.81%, 2 commits):
  (1) block-scope `extern u8 ObjHitReact_Update(...)` (was int): u8-field
      store `state->hitReactState=ret` emits direct `stb r3` not
      `clrlwi r0,r3,24; stb r0`. #11/#7. +0.39.
  (2) INLINE `table->stateFlags[state->stateIndex]` at the path-control
      bit tests (drop cached `stateFlags` local): target RE-READS the
      flags byte fresh per bit test, current CSE'd. #80/#107. +1.17.
  RESIDUAL (banked): base-into-r0+mr copy (objSeq class), cmpw operand
  order (obj->currentMove read late vs target hoists), r5/r6 index reg.
- dfropenode_func0B (dll_0175, 98.67->98.88%): name `dx` local for
  `node[1].pos[0]-x0` before the fmadds -> first fmadds emits f1,f5
  (diff*fraction) not canonicalized f5,f1. dy/dz already named. #27/#59.
  RESIDUAL: r7/r8 index reg-perm (idx*52 / base+off). #108.
- dfropenode_modelMtxFn (dll_0175, 96.67->100%): declare the f32 param
  LAST `(int obj, float* phase, f32 distance)` -> prologue mr r30,r4
  before fmr f31,f1 (ABI-NEUTRAL: floats use separate FPRs regardless
  of decl position). #87. FULL MATCH. Vtable-callback so no caller fix.
- drakormissile_startActiveLaunch (dll_0262, 98.54->98.84%): decl `p`
  (obj->extra) before `light` -> p lands r30 matching target. Partial;
  residual obj/light r29<->r31 swap (obj int-param wants r29 lowest,
  light call-result wants r31). #108 within-class, not cracked.

KEY LEVERS THIS SESSION:
- #11 u8-return block-scope extern: WORKS great for u8-field = fn() stores
  that emit a spurious store-side clrlwi. Check field type (u8) + callee
  return (declared int). Clean, ABI-neutral.
- #87 f32-param-LAST: ABI-NEUTRAL (PPC EABI: ints->GPR, floats->FPR
  independently, so moving a float param to the end keeps all reg
  assignments). Fixes prologue mr-before-fmr. Use freely on
  vtable-callbacks (no caller to break).
- #59 name-the-diff-local: a fmadds whose multiplicand is a fresh fsub
  result canonicalizes to (fraction,diff); naming it as a local like its
  siblings forces (diff,fraction). Match the spelling of adjacent terms.

BANKED (uncrackable this session, all reverted byte-clean):
- ktrex_shouldAdvanceArenaPhase (dll_0250, 98.78%): base ptr wants r3
  (creation-order ascending), current scrambles base->r5, b->r3. Pure
  #108 within-class. opt_level 2 REGRESSED. char* retype INERT.
- imicemountain_updateEventState (dll_0169, 99.3%): u8 counter
  `cnt=field-1; field=cnt; if(cnt==0)` target stores RAW then extsb;
  current extsb then stores. peephole-off (already on) doesn't unfold;
  peephole-on dot-merges elsewhere (98.17); scheduling-on wrecks (77.5).
  Same as tumbleweed_updateEffects (dll_00D2, 98.78%) `hitPulseCounter++`
  store-before-mask. PEEPHOLE-bound u8-RMW store/mask order = BANK.
- dfropenode_render (dll_0175, 98.99%): mr r29,r5 (p3 saved copy) emitted
  before vs after the p2 stw. #86/#108 prologue copy order. opt_prop off
  INERT.
- pollen fn_8016A660 / dbstealerworm_render: the recurring `bne body;
  b end` (target) vs `beq end` (current) 1-instr branch FOLD. NOT
  source-controllable (early-return, split-condition, peephole-off all
  INERT). BANK ON SIGHT.
- dfplevelcontrol_setScale (dll_0229, 93.3%): `s16* p = lbl[]` base
  materialized `addi r0,r3,lo; mr r7,r0` (via r0+copy) vs target
  `addi r5,r3,lo` (direct into var). decl-order/comma-init INERT. Same
  objSeq base-into-lis-reg class.
- grimble_stateHandlerA00/A01/A02 (dll_00D0, 96.5%): `d=sqrtf;x=d;
  getAngle(y,(f32)d)` - target keeps d double in f0, stfs(x=d) then
  SEPARATE frsp f2,f0 for the call arg; current merges frsp+stfs. CSE.
  getAngle(y,x) tightens CSE (worse). frsp-scheduling, BANK.

LESSON: the #11 u8-return and #87 f32-last levers are clean ABI-neutral
structural wins still findable in creature DLLs. The u8 counter
store/mask order and the bne;b/beq branch fold are PEEPHOLE caps - bank
fast. Push got rejected (shared main, many agents); commits are local.

## ===== Session (top-level src/main + dll_0014 RomCurve): 1 win / ~7 attempts =====
WIN (committed local, push rejected as usual):
- modelLightChannels_applyGXControls (modellight.c, 87.9->88.0%): (1) `u8
  activeMask` (was int) keeps the `&0xff` mask live as a clrlwi-to-u8
  BEFORE each `(activeMask & N)` bit test, matching target's `clrlwi r,24`
  ([ext-delete] classifier = target HAS an extension we fold). (2) declare
  `entry` (the walked ModelLightChannelState* base) FIRST among locals ->
  lands in r31 matching target saved-reg coloring (was r29, swapped with
  activeMask). (3) dropped inert `(int)` Ghidra cast on gModelLightChannelStates.
  RESIDUAL (banked #108): base still materializes via `addi r0,r3,0; mr r31,r0`
  (r0 detour) vs target direct `addi r31,r3,0`; the attnFn if/else vs
  GXSetChanCtrl channel-arg scheduling order. peephole off INERT on the mr;
  ternary-attnFn INERT (== if/else). T=C=191, 15 regions, rest reg-perm.

BANKED (this band, no win):
- RomCurve_findProjectedCurveFromStart (dll_0014, 84.1%): the while-condition
  4-link "all blocked?" check is a SCAN LOOP in target with RUNTIME shift
  `extsb (s8)blockedLinkMask; slw 1,k; and` + a found-flag reusing the k reg
  (li r5,0=usable / li r5,1=all-blocked; cmpwi r5,0; beq body). Rewriting the
  unrolled `&1/&2/&4/&8` `&&`-chain as `for(k=0;k<4;k++) if(linkIds[k]!=-1 &&
  (blockedLinkMask&(1<<k))==0) break;` DID reproduce the exact `extsb;slw;and`
  body (the bulk), BUT MWCC PEELED the first iteration into the prologue (curve
  r29->r30 cascade) + emitted an extra `li r0,0/1; cmpwi; bne` flag instr that
  target folds into the k-reg. Regressed to 47% -> reverted. The loop-rotation
  / flag-coalesce is the open frontier; the scan-loop INSIGHT is correct
  (commit it if the peel can be defeated; try `do{...}` or the exact flag-reuse).
- objSeq_onMapSetup (objseq.c, 81.2%): 5-saved-reg vs target 4. 12 walking
  pointers + i + base; target keeps base in r3 (volatile lis result, survives
  the all-r0/f0 store loop) -> only r29/r30/r31+r28(i) saved. Current parks base
  in r4 -> cascades one pointer into the saved range -> 5th reg + _savegpr_27
  helper (vs target inline stw r31..r28). decl-reorder INERT; opt_level 2 WORSE
  (75.8). 2nd loop also: target walks pointers, current uses base[i+huge_disp]
  index form. #108 base-wants-r3 cap.
- staffMtxFn_8003b620 (objprint.c, 86.2%): 24-saved-reg high-pressure; whole-fn
  reg-perm shifted by one (target r24=staff, current r23). Real lever buried:
  target `addi r0,off,24; lfsx f0,t,r0` (index = off+const, #112 K-group on the
  runtime base) vs current `add t,off; lfs 24(...)` (reassociated to (t+off)+K).
  Coloring cap dominates.
- shadowRenderFn_8006b558 (newshadows.c, 78.2%): frame +32 = 2 EXTRA callee-saved
  FP regs (target f27-f31, current f29-f31) -> target keeps more FP values live
  (the vD/vE/m clamp + sc/objScale). #82/#26 frame-class. Also target CSEs 8.0f
  (lbl_803DED10) AND 320.0f (lbl_803DED14) into f3 across both fmadds; current
  rematerializes per use. Replacing 320.0f/8.0f LITERALS with the named externs
  did NOT CSE (store between the two uses breaks it; needs `extern const f32`
  #127) and REGRESSED to 77.6 -> reverted.
- RomCurve_func16/func13 (dll_0014): base-into-r0+mr + 17-saved-reg coloring
  perms. func13 has a memset countdown loop that target makes `bdnz` (mtctr) but
  current keeps manual `addi -1; cmpwi; bne` -- buried under the coloring perm.
- hitDetectFn_80067958 / voxmapsFn_80010ff4: speculative-unroll + frame-class +
  17-reg coloring perms. Bank.

LESSON (top-level main band 78-88%): same as creature DLLs -- DOMINATED by #108
within-class coloring perms (often base-pointer-wants-rN, or one extra/fewer
saved reg cascading the whole allocation) and #82/#67 FP frame-class. The
reliable wins are the SMALL TYPE levers: u8-field to keep a mask-extension live
([ext-delete] classifier), decl-order to place a walked base in r31. The
named-const-CSE (#71/#127) needs `extern const` to survive a store, plain extern
doesn't. The scan-loop-with-runtime-shift rewrite (findProjectedCurveFromStart)
reproduces the body but MWCC peels iter-1 into prologue -- loop rotation is the
blocker.

## ===== Session (WC/SH/DF/ARW flat dll band): 2 wins committed =====
WINS (local commits; wclevelcont superseded by remote agent's 100%):
- wclevelcont_func10 (dll_028D, 84.95->88.56%, commit a50a2e71f2):
  The 4 mapGetBlockOriginForPos coordinate stores compute
  `DB4 + ((DD0+px)+DBC)`. (1) #32/#59: load lbl_803E6DB4 FIRST into a
  SHARED `f32 base` local used by BOTH outX and outZ in each arm (CSEs
  DB4 into one reg f3, matching target's single lfs f3,DB4 reused across
  both stores). The shared use is KEY -- a single-use `base` gets DCE'd/
  copy-propagated; two uses keep it live. (2) inner `f32 tx = DD0+px;`
  2-statement so `(DD0+px)` computes before DBC loads. (3) #pragma
  scheduling off around the fn (+1.8 alone): recovers per-fn instruction
  adjacency. RESIDUAL: addi-arg-order (ptr args &px,&pz emit BEFORE the
  localPos float args in BOTH scheduling states; target emits floats
  first -- neither scheduling on/off flips it, the float-args-first is a
  target source-order artifact I couldn't reproduce); @148-vs-lbl_803E6DC8
  signed-int->dbl magic (#70 neutral).
- SHthorntail_update (dll_01AD, 88.40->88.52%, commit 281f760e0e):
  #2: behaviorFlags &= ~SHTHORNTAIL_FLAG_LEVELCONTROL_READY (0x08) not
  & 0xf7 -> rlwinm r0,r0,0,29,27 not andi. 247. RESIDUAL (banked):
  whole-fn r26/r29 saved-reg perm + ONE EXTRA saved reg (current 7
  r25-r31 vs target 6 r26-r31). Target: obj(param)=r26 LOW, runtime/
  config(copies)=r28/r29 HIGH (correct #108: param->bottom, copies->top);
  current INVERTS (obj->r29, copies->r26/r27) because the extra r25
  stack-walker perturbs the pool. index-form eventId loop (drops the
  walker) was byte-NEUTRAL on score (just moved regs) -- reverted.

BANKED (no win, reverted byte-clean):
- dfptargetblock_hitDetect (dll_0235, 91.46%): the push-hit block CSEs
  lbl_803E648C into f1 ONCE (forcing velX/velZ to f2/f3); target reloads
  648C fresh per compare (4x) keeping velX/velZ in f1/f2. `*(f32*)&lbl`
  launder on the compares INERT (VN-CSEs regardless of spelling). The
  lower velX/velZ clamps (the degenerate-looking `if(v<K){if(v>=K)...}`)
  ALREADY MATCH -- they're real clamp-to-same-symbol logic, not corrupt.
  hitObj is stack outparam (12(r1)); target reloads, current caches r29.
  #82/#71 FP-CSE + stack-reload cap.
- arwsquadron_update (dll_02A6, 91.00%): `enable=GameBit_Get()!=0` ->
  neg/or/srwi (#23 arithmetic bool). Ternary `? 1 : 0` flips to li 1;b;
  li 0 BRANCH form (matches target li 1/0) but score NEUTRAL -- the
  dominant gap is the enable/disable multi-arm CONTROL-FLOW MERGE (target
  threads arms into the shared if(enable) test; current materializes 0/1
  per arm then re-tests + extra li 0;b islands). Also if(enable) wants
  cmplwi (unsigned, #64) vs current cmpwi. Control-flow-merge restructure
  cap -- not cracked.

LESSON: the shared-local-for-CSE (#6/#16 shared `base` used by 2+ stores)
is the crack for "target loads a const ONCE into a reg reused across
sibling stores" -- a single-use launder local gets DCE'd, you NEED 2+
uses. scheduling-off still a reliable +1-2 on FP-store-heavy flat fns.
The addi-arg-order (ptr-args-before-float-args) resists both scheduling
states. wclevelcont got picked up by another agent (remote->100%) mid-
session; push always rejected on shared main (commits are local only).
