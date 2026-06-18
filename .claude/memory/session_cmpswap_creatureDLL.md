# Session bank: cmp-swap + u8-cond creature/level DLLs (Jun17) — 5 wins, ~8 attempts

Written separate (decomp_wins.md concurrently edited). Merge when safe.

## ===== Session (Jun17 fresh-eyes, hagabon/pollen/swarm/drakormissile/flamethrower band): 0 wins, ~13 attempts — ALL WALLS =====
CONFIRMS prior verdict: this exact creature band is coloring/scheduling-dominated;
no source lever found. Banked (reverted byte-clean, DO NOT re-attempt these levers):
- hagabon_update (89.2%): whole-fn param-pool shift — obj→r27+_savegpr_27 (5 saved)
  vs target obj→r28 (4 saved, inline stw). Extra r31 web from Vec_distance arg
  (addi r31;mr r3,r31 vs target addi r3,r28,24). peephole off INERT. `(u8)fade`→
  plain `fade` on alpha store INERT (clrlwi r0,r0,24 before stb 54 persists — int→u8
  store masks regardless; target stb raw then lbz-reloads. 1-instr cap, not the cast).
- fn_8014E1DC (hagabon helper, 88.7%): accel=lbl_803E2624 — target RELOADS 5x, current
  CSEs to 1. Inlining lbl_803E2624 at each use REGRESSED 88.7→88.0 (MWCC still partial-
  CSEs within branch + reshapes). Multi-issue FP reassoc (fmadds) + frame. Deep wall.
- swarmbaddie_update (96.0%): f32 d[3] distance array — target STORES all 3 to stack
  (stfs 32/36/40) keeping dead stores live (frame -96); current DSEs (frame -80) +
  f3/f4 FP-reg swap on the squares. Address never escapes in EITHER. opt_lifetimes
  off / scheduling off BOTH INERT. The dead-store-keep is a codegen-state diff not
  reachable from C. (#8 needs the buffer head passed to a callee — it isn't here.)
- drakormissile_update (95.6%): near=(int*)hitState->lastHitObject(u32 field), null-
  check spills to 8(r1) + cmpwi (target cmplwi). (void*)near, (u32)near!=0u, retype
  near to void* ALL INERT — the u32-field-source value canonicalizes the reload-compare
  to signed regardless of local type. Dominant residual is GPR shift (r28↔r29) anyway.
- flamethrowerspe_update (97.1%): 133/133 instrs, ONLY diff = `mr r3,r29; lfs f0,36(r29)`
  block emitted 1 slot earlier than target + @230-vs-lbl (#70 neutral). scheduling off
  INERT. Pure emission-position cap.
- fn_8016A660 (pollen, 98.9%): target `bne body; b end` (2 instr) vs current `beq end`
  (1 instr) on the `if(IsLoadingLocked()!=0){body}` wrap. Already #pragma dont_inline on.
  Empty-then/else-body (#33/#21) INERT. +3 @101-vs-lbl_803E3150 (#70 neutral). 1-branch cap.
- dfropenode_func0E (94.1%): whole-fn GPR shift (params→r29/30/31, target r27/28/29;
  extra→r28, target r31) — pointer out-params (distanceOut/phaseOut/sideOut) class into
  COPY pool HIGH competing with extra; target puts extra highest. #126 param-pool. Plus
  node-base in r6 (target) vs r3 (current) — arg-eval order (out-ptr args r3/r4/r5 set
  up BEFORE the 6 float loads in target). Not source-reachable.
- kaldachom_update (93.1%): FP-const double-cast load placement (lbl_803E30C8/timeDelta
  reorder) in vtable-call-heavy else-branch + control r28/r29 perm. arg-eval wall.
LESSON (re-confirmed 3rd time): hagabon/swarmbaddie/pollen/drakormissile/flamethrower/
  kaldachom/dfropenode are ALL #108/#82/#67/emission walls. The cmp-width vein is
  EXHAUSTED here (prior agents cleared the actionable ones; remaining cmpwi-on-u32-field
  reloads are signedness-canonicalized + not flippable). Skip this exact set on next pass.

## ===== Session (Jun17h, tumbleweed/grimble/drakormissile/ktrex/bossdrakor): 2 wins, ~15 attempts =====
NOTE: many flat dll_* moved to lane folders (src/main/dll/{DR,DF,ARW,...}); ktrex
now src/main/dll/DR/dll_0250_ktrex.c. tumbleweed/bossdrakor still flat.
WINS (committed local, push rejected remote-ahead):
- tumbleweed_updateRollingMotion (87.4->88.2%, 765b21428c): def declared
  `short* obj` but call sites + target prologue treat both params as int (#126
  param-type pool classing). Retype to `int obj, int state` + `(short*)` casts at
  the short-indexed uses (obj[2]/obj[1]/*obj/obj[0x23]) -> flips prologue
  `mr r31,r3;mr r30,r4` to target's `mr r30,r3;mr r31,r4` (param saved-reg perm
  that cascaded through all field loads). RESIDUAL: hitDetect-arg field loads use
  r3 vs target r30 (both hold obj; pure prologue coloring) + frame-temp slots.
- tumbleweed_updateEffects (98.8->99.0%, second commit): u8 counter (hitPulseCounter
  at off 635) — current masked-before-store (clrlwi r4,r0,24; stb r4), target
  stores unmasked (stb r0) then masks (clrlwi r4,r0,24, same reg). #20 def-vs-use
  mask position. FIX that worked: `r=field; r=r+1; field=r; r=field;` (RE-READ the
  field after store) shifts mask past store -> +0.27%. CAVEAT: re-read adds an lbz
  reload (180 vs target 179 instrs) but objdiff scores it HIGHER; merged
  `r=field+1` and inline `(u8)r` were both INERT; two-var (r full + rm masked)
  REGRESSED to baseline. The store-then-mask-same-reg ideal is unreachable from C.

## BANKED this pass (no lever found, all reverted byte-clean):
- grimble_stateHandlerA00/A01/A02 (97.2/96.5/?): IDENTICAL residual in all three —
  `d=sqrtf(...); x=d; angle=getAngle(y,(f32)d)`. Target: `fmr f0,f1; stfs f0,8(r1)
  [x=d store unrounded double]; frsp f2,f0 [separate round for getAngle]`. Current
  FUSES: `frsp f2,f1; stfs f2; reuse f2`. The store-of-double-without-frsp +
  separate-frsp-for-cast is UNREACHABLE: peephole off, scheduling off, getAngle(y,d)
  double-arg, getAngle(y,x) all INERT. 1-instr cap. Crack one -> crack all 3.
- drakormissile_render (96.7%): p(base)=r26 m(walker-copy)=r30 in target; current
  inverts (p=r30, m=r26). m is multi-def walker (m+=2) -> descends to lower class,
  but target keeps it HIGH. #130 re-derive (m=obj->extra) folded back (VN-equal);
  decl-order-first REGRESSED; fn-scope move inert. Pure #108 copy-vs-walker class.
- ktrex_stateHandlerA11 (97.8%): gKTRexState (sda21) reloaded EVERY use in target
  (incl unk8 store: lwz r3,0(0); stfs f0,8(r3)); current caches in r5 for the
  unk8 store only (r5 survives because obj uses r3). Split store-into-temp INERT.
  Target frees r5 + reloads into r3; 1-instr coloring cap (re-derive of a global
  not forceable when it's the same symbol).
- drbarrelgr_render (94.3%): #67+#128. Target params at r1+8, vec[3] at r1+20 AND
  hoists &vec[0..2] to r29/r30/r31 before loop; current re-materializes addi each
  iter + swapped stack layout. Decl-reorder (params-first) put vec wrong way;
  named pv ptr + opt_propagation off both INERT. Array placement independent of
  decl order.
- bossdrakor_spawnAttackObjects (97.7%): switch{1,2,4-empty} binary-search PIVOT
  differs — target `cmpwi r5,2` (real case pivot), current `cmpwi r5,3` (gap
  pivot). Moving empty `case 4` to end INERT. MWCC pivot heuristic, not source-
  controllable. (#13/#122 don't apply — the empty case position is irrelevant here.)
- grimble_update (98.8%), dfropenode_update (98.5%), arwsquadron_applyCommandParams
  (97.1%), tumbleweed_updateTargetedStateMachine (99.0%): all 1-2 instr emission-
  order (#86) / @N-vs-lbl reloc (#70 neutral) / fsubs FP-pair (#82) residuals.
  ternary-deref-into-result-reg for the player?:fn() pattern re-folded (VN).

LESSON: this band of creature DLLs is dominated by #108/#82 within-class reg
perms, #86 emission scheduling, and #67 frame/array-placement caps. The
PRODUCTIVE veins remain: #126 param-type recovery (read target prologue mr order
to recover original int-vs-ptr param types — cascades through all field loads),
and #20 u8-counter mask position (re-read field after store).

SCOPE: flat src/main/dll creature/level DLLs (dll_0250 ktrex, dll_0261
drlasercannon, dll_0266 kytesmum, dll_0282 barrelgener). All committed locally,
push rejected (remote-ahead, no pull).

## WINS
- dll_0261 drlasercannon_update (92.7->93.1%, committed): object-handle fields
  (warningObject/firepipeObject/target/spawned) null-checked as `(void*)x != NULL`
  -> cmplwi (#3); hasFirepipe if/else-if -> `switch` for signed-cmpwi binary-search
  (#109d). Residual = state r30-vs-r31 within-class saved-reg perm (#108, dominant).
- dll_0266 kytesmum_update (94.3->95.2%, committed): randomGetRange returns u32 via
  dr_shared.h -> cmplwi; `(int)randomGetRange(..) != 0` casts force target's signed
  cmpwi (#124). `(void*)nearest != NULL` -> cmplwi (#3). Residual = diff-var web
  split (r4->r29 copy vs target in-place r28 extsh) + obj-base r28/r29 perm.
  NOTE: abs ternary `(diff<0)?-diff:diff` REGRESSED (forced r29/r0 web); plain
  if-form is correct here. opt_level 2 also regressed (95.2->93.6).
- dll_0250 ktrex_stateHandlerA02 (90.3->92.5%, committed): TWO levers.
  (1) `u8 cond` not `int cond` for the branchy state-equality bool (unkFF==K chain
  feeding `cond && ...`) -> target re-masks clrlwi+cmplwi on the && test (#38/#58).
  (2) embed the phase load into the && short-circuit: `(phase =
  state->unk101) >= 2` defers the lbz past the unkFC==0 guard, matching target
  load order. Each ~+1%.
- dll_0250 ktrex_stateHandlerA10 (94.1->96.6%, committed): SAME `u8 cond` lever
  (identical unkFF==K cond block). +2.5%. **This is a reliable vein: a branchy
  bool built from `field == K` (field u8) and consumed by `bool && x` wants the
  bool typed u8 so MWCC re-masks (clrlwi clrlwi cmplwi) instead of cmpwi.**
- dll_0282 barrelgener Obj_UpdateRomCurveFollowVelocity{,Indexed} (92.0/92.3 ->
  92.3/92.5%, committed): declare `int result` BEFORE `RomCurveWalker* route`
  -> result lands r31 (top saved class, #108/#5). Small but clean, both fns.
  Residual = routePtr<->flag within-class r29/r30 swap (both params, #108).

## BANKED (no lever this pass)
- dll_0158 gunpowderbarrel_hitDetect (94.7%): #8 dead-stack-stores — target keeps
  3 sp1c[] stores live in stack (28/32/36), current DSEs them; `(void)sp1c` (prior
  agent) inert. Plus a beq;b vs bne branch-fold. Multi-issue spill coloring. Bank.
- dll_02A6 arwsquadron_update (91.0%): phi-merged `enable`/`disable` bools from
  `GameBit_Get()!=0` materialize context-dependently (target uses BOTH branch-form
  cmplwi;beq;li1;b AND arithmetic neg;or;srwi31 in different arms). Ternary `?1:0`
  on the inactive-block enable REGRESSED (90.4). 27 regions, heavy. Bank.
- dll_01AA bombplantspore_update (89.9%): const-fold (0x7000b detonateMessage
  folded to addis;cmplwi range-check vs target lis;addi;cmpw materialized reg) +
  lbl_803E5394 literal-vs-named reload CSE (#71/#127) + many FP coloring swaps.
  27 regions multi-issue. Bank.
- ktrex lfsx residual: `*(f32*)((char*)p + idx*4 + 0x38)` single-use base re-folds
  to lfsx even as struct-member `((KtrexPlacement*)(p+idx*4))->unk38` (the `/lbl`
  division consumer re-folds it). #112 needs multi-use base; uncrackable single-use.

## TOOLING / METHOD
- CRITICAL: build/GSAE01/obj report races with concurrent agents -> "No such file"
  errors + STALE/WRONG fuzzy% (saw 94.275 vs true 95.207 from a corrupted scan).
  Fix: /tmp/measure.sh retries `report generate -f proto` until no error line,
  THEN reads /tmp/fuzz.py. Always confirm a measure twice if it looks like baseline
  after a clearly-applied edit. Check .o mtime > rep.binpb mtime.
- cmp-swap scanner (/tmp/cmpscan.sh + /tmp/scan.py): pipe sorted candidate list
  (pct sz unit fn), runs ndiff per fn, counts cmpwi<->cmplwi swaps. Top yielders
  this pass: drlasercannon(8), kytesmum(3), bombplantspore/arwsquadron/ktrex(2).
- Band [55,95] sz>=400 in flat dll_* shrank to ~38 fns (other agents cleared the
  dll_0014/0015/000A/player cluster — those .o now rebuilt out of band).

LESSON: the cmp-width swap vein is reliable for OBJECT-HANDLE null checks
  (`(void*)x != NULL` -> cmplwi) and for u32-returning helpers wanting signed
  (`(int)f() != 0` -> cmpwi). The NEW reliable vein this pass: **u8-typed branchy
  equality bool** (`u8 cond = field==K; ... if(cond && y)`) -> clrlwi;cmplwi
  re-mask. Two ktrex handlers fell to it (+2.2/+2.5%). Grep `int cond` /
  `int <bool> =` near `== ` chains feeding `&&` for more.
