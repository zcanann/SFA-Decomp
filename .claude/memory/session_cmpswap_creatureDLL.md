# Session bank: cmp-swap + u8-cond creature/level DLLs (Jun17) — 5 wins, ~8 attempts

Written separate (decomp_wins.md concurrently edited). Merge when safe.

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
