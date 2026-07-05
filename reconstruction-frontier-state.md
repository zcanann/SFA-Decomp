# Reconstruction Frontier State

## FIELD-NAMING sweep of dll_01xx unit-local structs (2026-07-05, Opus) — 0 renames, cluster saturated
Middle-range field-naming pass (dll_0100–dll_01FF, unit-local structs preferred). Surveyed ~15
units with residual `unkNN` members: landedarwing (3 Placement structs), doorlock, ecshcreator,
slidingdoor, spiritprize, trigger, pressureswitch, gunpowderbarrel (GunpowderBarrelState),
ecshshrine (EcshShrineState), fuelcell, magiclight, xyzanimator, dll199, linklevcontrol, campfire.
VERDICT: this cluster is already thoroughly named; every remaining `unkNN` fell into a non-renameable
bucket. NO renames made (quality-over-quantity: a wrong name is worse than none).
Three exhaustion buckets (all block a justified rename):
1. **Shared GameObject fields** (`unkF4`/`unkF8`) — out of scope, multi-owner (appear across nearly
   every unit as `==0`/`!=0`/`=1` state latches). Not this agent's struct.
2. **Multi-owner struct fields** — one-owner rule blocks: `XyzAnimatorState.unk4` (MMP_asteroid.h,
   3 owners; dll_00DA reads it as `f32`, xyzanimator as an int count = CONFLICTING roles, must NOT
   unify), `Dll199State.unk10` (dll_0199+dll_019A), `MagicLightState.unk10` (4 owners, write-only
   0x12d), `LinkLevControlState.unk04` (5 owners, init -1 write-only).
3. **Unit-local but write-only / decl-only** — no read usage to justify a name: `EcshShrineState`
   unk18=0xc/unk1C=0x1e/unk1A/unk1E/unk20 (all init-only, never read); `GunpowderBarrelState`
   unk07/unk30/unk3C/unk3E/unk40 (init-to-zero/const, no reads); the many Placement `unkNN` (pad
   markers declared only for layout, never dereferenced: landedarwing unk18/1A/1E/20, doorlock
   unk18/1A, slidingdoor unk20, pressureswitch unk1A/4C/2F8-2FA, trigger ObjInterpretSeq unk4/unk6).
NOTABLE JUDGMENT CALL (left opaque deliberately): fuelcell `FuelcellState.unkBit5` (dll_0123, single
bitfield flag, unit-local) IS behaviorally live — set by fuelcell_func0B (the animEventCallback),
and when set it (a) picks a distinct burst-color const, (b) excludes the cell from the peer
lightning-link network (both self and as a candidate), (c) picks a distinct spread scale. Genuinely
a "special/standalone-effect" mode flag, but the precise meaning is ambiguous between
activated/deposited/solo-effect — left `unkBit5` rather than guess (would be a byte-neutral 1-line
win for a later agent who can pin the semantics; func0B fires on a specific anim event + also sets
resetPos which snaps the cell to its home socket).
FUTURE field-naming agents in dll_01xx: do NOT re-scan for easy unit-local `unkNN` — the readable
ones are named. Remaining work is either multi-owner (needs cross-unit coordination) or requires
reverse-engineering write-only fields against the engine, not local usage.

## SEMANTIC-RECOVERY sweep of the Jul-05 data-split "linked/complete" units (2026-07-05, Opus) — 1 struct win, fresh set saturated
Swept the freshly-linked/data-split units the team named this session (skeetlawall, dll_0127,
texscroll, explodeanimator, lightning, attractor, lightsource, staticcamera, wallanimator,
fogcontrol). FINDING: the team named locals/structs/externs AS they data-split, so var-naming
and extern-elim are ALREADY SATURATED on this set — a tree-wide junk-local scan (iVar/local_/
param_/uStack/etc) over ALL src/main/dll/*.c found ZERO real Ghidra junk locals (only a comment
mention of `undefined4` in dll_008B). main-lib non-dll still has raw Ghidra files (newshadows.c
141 DAT_ + 77 dVarNN doubles=bias-double-conv temps, objprint_dolphin, pi_dolphin) but those are
big/hot/bias-double-trap and mostly other agents' territory.
- **WIN dll_0141_lightning (52bc08686f)**: the 2 raw `*(f32*)(data+0x10)`/`(data+0x14)` casts on
  the LINKED lightning object's extra block (`data = ((GameObject*)*slot)->extra`) read that
  object's `LightningState.hitRadius`/`.burstRadius`. Spelled as named fields. .o md5 IDENTICAL
  (f25ded93...), full all_source EXIT=0, 0 FAILED. Byte-neutral struct-field naming.
- **NEGATIVE (recorded)**: in the SAME fn, changing the two `((LightningMode*)(data+0x24))->mode`
  overlay casts to `((LightningState*)data)->modeBits.mode` (modeBits IS a LightningMode at 0x24)
  CHANGED the .o md5 (a6a04599...). The standalone 1-byte overlay-struct cast and the nested
  outer-struct bitfield access do NOT compile identically here — the overlay cast is CANONICAL.
  Reverted. LESSON: a bitfield reached through an outer struct's member != the same bitfield via a
  direct overlay-struct cast at that offset; don't "unify" overlay casts into the parent struct.
- **dll_0127 obj+0xF8 s16 timer**: accessed `*(short*)(obj+0xf8)` (cooldown timer) while the shared
  GameObject struct types unkF8 as s32 (`*(int*)` flag-word sites elsewhere). The raw `short` cast
  is a per-unit narrow view; retyping the shared field is cross-file risk + breaks the int sites.
  Raw cast CANONICAL, leave. (matches the header's "raw-cast sometimes canonical" discipline.)
- dll_0206_lightsource line 65 `*(int*)&((GameObject*)obj)->extra` = the frontier-confirmed launder
  idiom (already canonical). Externs in all swept units are live engine calls (no dead extern-elim).
VERDICT: the Jul-05 fresh-linked set is well-recovered; struct/naming/extern angles saturated except
the one lightning field-naming win. Future semantic agents: the fresh data-split units are NOT a
junk-local goldmine — the team names inline. Remaining raw-Ghidra bulk is in main-lib *_dolphin.c
(bias-double + DAT_ reloc territory), owned by other agents.

## FRESHLY-LINKED sdata2-inline units triage (2026-07-05, Opus) — 0 attackable, all units already 100%
Prompt targeted the ~15 units just made BUILD-LINKED by the "data-split inline sdata2 -> linked/complete"
sweep (dll_01D0 dimtricky, 0135 texscroll, 025A staticcamera, 021C vfpladders, 00D4 skeetlawall,
015F attractor, 0206 lightsource, 0184 animsharpclaw, 0141 lightning, 0140 fogcontrol, 013D
explodeanimator, 013B wallanimator, 0127, 01EB sbshipmast + 0187 ccqueen, 0055 cameramodeperv, 0219).
METHOD: private proto report (`objdiff-cli report generate -f proto`) + standalone decoder (no fnfz
race). Decoded EVERY scored fn per unit (5-11 fns each, all present & scored = confirmed linked).
VERDICT: ALL freshly-linked target units are at 100.00% on every function. The sdata2-inline sweep
landed them fully matched — the datagen/codegen split did not expose any new sub-100 fuzzy targets.
Only sub-100 fns near this cluster are tricky_rollroute::trickyFn_80141290 (99.27%, 1516B) and
trickyfollow::trickyFn_8013b368 (99.40%, 8764B) — NOT in the linked-unit set, large tricky-family
fns (other clusters). Nothing to attack in owned scope. No commits.

## MICRO-STRUCTURAL 3-lever sweep (const-mul-unfuse / two-stmt-store-fold / compound-+=-narrow) (2026-07-05, Opus) — 0 wins, class exhausted in owned files
Tree-wide grep + scan for each of the 3 recurring levers (each won ~1 fn earlier this session).
METHOD: private proto report + standalone decoder (no fnfz race); function_objdump --diff + ndiff.
- **LEVER 1 (const-mul unfuse, `X*C1<<C2`)**: only 3 tree hits. shader.c:1382 `idx*7<<2`
  = OTHER AGENT (s16-store sweep, doPendingMapLoads, modified 03:55 same-minute). SKIP.
  dll_000B:1949 `(c*3)<<4` = OTHER AGENT (partfx dll_0B_func04, 4ffd0bfcd3/5h). SKIP.
  model.c:2212 modelLoad_calcSizes `(jointCount*7)<<2` @93.53% = NOT a fit: target ALSO
  emits `mulli r0,r5,7; slwi r5,r0,2` (kept separate, NOT collapsed) — current already
  matches the mul+slwi shape. ndiff shows the 93.5% residual is pure accumulator/add-operand
  ordering + `total` in r6(T)/r7(C) coloring, NO slwi excess. BANKED (out of lever scope).
- **LEVER 2 (two-stmt narrow store fold, `LV=f(); LV=LV+K`)**: tree-wide scan found the
  ONLY call-RHS self+const instance = dll_0026_effect13.c:306 `cfg[2]=randomGetRange(); cfg[2]=cfg[2]+0x50`
  BUT `cfg` is `int[3]` (NOT narrow) → no extsh to fold. All other self+const pairs (model
  total = int, voxmaps ySlot = int, dbstealerworm entry = ptr) are non-narrow. ZERO narrow
  lvalue two-stmt folds exist tree-wide. Class exhausted.
- **LEVER 3 (compound-+= narrow array, `arr[i]=arr[i]+x`)**: genuine narrow hits = objhits out[]
  (FALSE POS: float*, not u8), maketex a[]/acc[] (s16/u64 checksum — TEAM-HOT 72min + u64),
  track_dolphin b[] (OTHER AGENT s16-store sweep — banked counts win), curves outVec (TEAM-HOT
  73min), sbcloudrunner state[] (ptr false-pos + hot 76min), model sizes[] (int false-pos).
  objprint.c angleDeltas[4] (short, unowned 18h) = FUN_8003add8 which is ALREADY 100% (the
  self+const short stores already match target). No unowned+imperfect+narrow candidate remains.
SWEEP VERDICT: all 3 levers exhausted in files this agent owns. Every fit was either a
false-positive type (float/int/ptr array), team-hot/other-agent's file (one-owner skip), or
an already-matched fn. Consistent with prior sweeps: these micro-levers are rare single-fn
fits and the current-session instances were already harvested by the winning commits.

## RACE-83 sibling sweep of team's Jul-05 03:xx techniques (2026-07-05, Opus) — 0 wins, all banked
Extracted the 3 freshest team techniques and hit their nearest siblings; none yielded:
- **s16-narrow-out-of-loop** (afe5d4abf3 bossdrakor_update, 3-min-hot). Cleanest sibling
  found: `sandworm_turnTowardTargetAnim` (dll_014C_babycloudrunner, 98.86%) — ndiff is a
  SINGLE extra `extsh r0,r0` between `add r0,r0,r4` and `sth r0,0(a)` at the
  `*(s16*)a += (shifted>>=3)` store (T=101 C=102). TRIED+FAILED: `s16 shifted` retype
  (INVERTED — shift became `srawi;extsh`, compares lost their wanted extsh, worse);
  split `shifted>>=3;` off the `+=` (recomputed shifted per compare, opt_common_subs
  already off — much worse); `s16* pa=(s16*)a` typed ptr (INERT); **`#pragma peephole on`**
  (removed the store-side extsh BUT fused an `extsh.` dot-merge + folded the neg/srawi
  abs-branch at lines 263-269 → 3 regions, net worse — the classic magicdust ambientTimer
  store/narrow-order peephole trade). BANKED coupled 1-instr cap.
- **(u32)obj VN-split** (a9bd21d650 firecrawler crawler_updateC — drops pooled conv-temp +
  extra saved reg). Built a savegpr-fingerprint scanner over all 57 units with 2+
  `SetCurrentMove((int)obj`/`AddObject((int)obj` calls: **ZERO** had the firecrawler
  fingerprint (current `_savegpr_N` < target = extra saved reg). Checked candidates
  directly: `babycloudrunner_SeqFn` (98.83%) = pure r26↔r31 whole-fn renumber (equal reg
  count, #108); `dbstealerworm_stateHandlerA0B` (98.70%) = 38-region within-class cascade
  T=371=C=371, both `_savegpr_23`. The `(u32)obj` lever needs the extra-saved-reg
  fingerprint; the tree's remaining `(int)obj`-heavy fns are pure renumbers.
- **staging-local removal** (4e3d038d42 gunpowderbarrel: `int obj` param + drop
  `int objI=(int)obj` + update-walker). All other `= (int)obj;` staging-local fns
  (iceball, dimbossgut, dimwooddoor2, dim2icicle) are already 100% — the copy only
  hurt at gunpowderbarrel's specific capped allocator state.
VERDICT: team's newest levers are highly fn-specific (fingerprint-gated); siblings that
LOOK similar are mostly #108 renumbers or already-matched. No injectable win this pass.
NOTE: hightop_stateHandler02 (99.79%) residual = state-load r4↔r5 coloring swap + one
cmpw/bge operand-order flip, NOT the s16 lever.

## #126 PARAM/STATE COLORING CRACKED — bare-decl reorder lever (2026-07-03, Opus) — 2 WINS

**The #126 cap is PARTIALLY CRACKABLE.** Mechanism (from docs/mwcc_re/recovered/
CodeGenNumbering.c + Coloring.c + InterferenceGraph.c): saved-reg = GetReservedReg
pool r31,r30,r29... consumed in **web-index order**; web index = **descending
priority** (CodeGen_NumberWebs @0x435650 numbers max-priority-first), ties broken by
**web creation order = local DECL order** (CFunc.c worklist). Loop-resident values get
a priority PIN (=100000, IroLoop desc+0x24&0x40) → numbered first → r31. So among webs
of EQUAL priority (e.g. two loop-pinned locals), the **earlier-declared one gets the
lower web index → r31 (or lower saved reg)**. LEVER: bare-decl the value you want in
the higher saved reg (r31) EARLIER; inits are INERT (numbering is at decl/creation,
not assignment).

### WINS (committed):
- **controllight_update (dll_02AC) 96.78->97.30** (4f34b38ae6): target obj=r29/state=r30/
  bit=r31; current had obj=r31/state=r30. `bit`(=GameBit result, loop-resident + post-loop
  store) and `self`(obj cast) tie on the loop pin; `self` decl'd first won r31. FIX: bare-
  decl `u32 bit; ControlLightState* state;` BEFORE `GameObject* self`, inits after →
  bit=r31, state=r30, self/obj=r29 (byte-match prologue).
- **enemymushroom_update (dll_01A8) 98.99->100.00** (293f9ea32f): target state(184)=r31/
  player=r30; current player=r31/state=r29 (player decl'd before state). FIX: bare-decl
  `char* state;` FIRST, before `u8* player`, init after → state=r31, player=r30. FULL match.

### THE WINNABLE PROFILE (apply the lever ONLY here):
obj/param is ALREADY correctly colored, and the mismatch is TWO **locals** swapping saved
regs, where the target's higher-saved (r31) local is a **heavily-used / loop-resident
POINTER or value** (state deref, GameBit-result). Promote it by declaring it bare FIRST.

### THE BOUNDARY (tested, does NOT work — do not grind these):
1. **PARAM-demotion cases** (obj itself in wrong reg): obj=r31 in current but target wants
   obj LOW (r27/r28), with a local needing r31. A loop-resident PARAM will NOT demote below
   a local via decl order. TESTED+REGRESS: arwbombcoll_update (99.04->98.79, arw-first
   inert), gunpowderbarrel_update (98.02->97.88, state-first left obj=r31), Transporter_SeqFn
   (99.57->99.47, i-counter-first inert). REVERTED all.
2. **LOOP-COUNTER vs LOOP-POINTER**: when target's r31 value is a pure loop induction
   counter (`for(i...)`) competing with a loop-resident pointer, decl order CANNOT promote
   the counter over the pointer. TESTED+INERT: animatedobj_update (res-counter vs seq-ptr,
   99.497 unchanged), Transporter (i vs obj). The multi-def counter web resists.
3. **STATE-DEMOTE-BY-ONE welded tie-break**: state needs r28 but sits r30 (invhit_update
   99.844->99.707 regress), or state r30->needs-demote with a tail scalar wanting r31
   (timer_update: textureId-r31 vs state, same class). Decl swap moves state ONE reg the
   wrong net direction — the smallbasket welded-numbering==emission tie-break. BANK.

### FRESH SWEEP RESULT (dec.py proto, detect4.py in scratchpad):
Ran a tree-wide detector over 261 DLL fns [80,100): **91 have the target obj+state-deref
prologue shape; 22 have a saved-reg MISMATCH**. Of those 22, ~3 fit the winnable profile
(2 won: controllight, enemymushroom; invhit at ceiling). The MEMORY.md #126 bank is
LARGELY STALE — fogcontrol_init, wallanimator_init, texscroll2, dll_0107 fn_80185868 are
ALL 100% now (solved by prior "cache (GameObject*)obj + int copy" and "decl-order hill-
climb" commits — wallanimator's `GameObject* go; int oi;` cache-copy is the same lever
class). Remaining 22 hits are mostly boundary-classes 1-3 above. Detector: /private/tmp/.../
scratchpad/detect4.py (normalizes report `main/main/dll/X` → `main/dll/X.c`).


## SCHEDULING / PEEPHOLE cap class — mechanism decode + 3 tests (2026-07-03, Opus) — 0 wins, DEFINITIVE verdicts

Read the recovered scheduler/peephole passes end-to-end (PCodeScheduling.c, Scheduler.c,
Peephole.c, ValueNumbering.c) and derived the EXACT emission mechanics, then tested one
concrete banked fn per cap sub-class. All three are UNREACHABLE from a source-level steer;
the divergence in each is downstream of scheduling/peephole and owned by coloring/CSE.

### MECHANISM (from the binary, HIGH confidence)
- **List scheduler is BOTTOM-UP** (Sched_EmitBlock @0x507df0): emits DEPENDENTS first,
  drains predecessors as numUsers hits 0. Ready-node SELECTION key (Sched_PickReady
  @0x507fc0) is strict lexicographic K1..K5: K1 deadline-window (slack<=cycle), K2
  frees-most-predecessors, K3 critical-path priority (compute height feeding the node),
  K4 per-opcode unit-table key (gated), **K5 = LIST ORDER (source emission order)** as the
  final tiebreak. So source statement order ONLY decides ties that survive K1-K4; any
  priority/deadline/frees difference overrides it.
- **Two independent field stores** (`buf.a=X; buf.b=Y`) get a dep edge ONLY if MayAlias is
  true (Sched_AddStoreDeps @0x508350). Distinct disp on same base => no alias => reorderable
  => decided by K1-K5. But the STORE ORDER is NOT the residual — the coupled SCRATCH-REG
  COLORING is (which physical reg the CSE'd shared const lands in), and that is set AFTER
  scheduling by the register allocator (Coloring.c), not by any source lever here.
- **Peephole dot-merge** (Peephole.c): the signed-cmpwi-0 record fusion (0x506e70) fires when
  a RECORD-CAPABLE producer (extsb/rlwinm/clrlwi/and/add/srwi...) feeds `cmpwi cr0,rX,0` and
  CR0 is dead elsewhere. UNSIGNED cmplwi has NO standalone rule — it fuses ONLY via the
  branch handler (0x505820) when it DIRECTLY feeds a bt/bf with CR0 dead in the gap. `srwi.`
  is this fusion firing on the shift+compare.
- **VN/CSE**: every literal `0` in a function shares ONE value number (ValueNumbering.c note:
  "make dst/src the same value to kill a copy; distinct value to keep it"). So `n=0`,
  `outCount=0`, `glob=0` are ALL one value-web; which physical reg that web occupies at a
  given store is a COLORING decision, not steerable by statement order.

### TEST 1 — dll_0069 dll_69_func03 store-order↔scratch cascade (99.3301, banked)
Isolated divergence @ src lines 181-185 (`buf.v3c=0; buf.v40=1; ... buf.v5a=0`):
- TARGET: `li r0,1;stw r0,72(v40)` FIRST, then `li r3,0;stw r3,68(v3c)`; the shared zero
  (v3c=v5a=0) lives in **r3**, the `1` in r0; the downstream count-chain (addi/subf/mulhw
  for `buf.count=(e+4)-entries`) is **r0-based**.
- CURRENT: `li r0,0;stw r0,68(v3c)` FIRST (source order), `li r3,1;stw r3,72(v40)`; shared
  zero in **r0**, count-chain **r3/r4-based**.
- LEVER TRIED: swap source lines `buf.v3c=0`/`buf.v40=1`. RESULT: store order FLIPPED to match
  target (72 before 68 — confirms K5=source-order governs these ties) BUT the shared-zero
  colored into r0 (wrong; target wants r3) and the count-chain stayed r3-based. Net
  99.3301->99.3109 (REGRESS). The swap proves the scheduling lever WORKS on store order but
  the coupled scratch-reg COLORING (r0 vs r3 for the CSE'd zero + count-chain temp) is the
  actual residual and is coloring-owned. Reverted. VERDICT: store-order IS source-steerable
  (K5) but here it is COUPLED to a coloring transposition that dominates the score — not a
  scheduling win. Hand to coloring agents.

### TEST 2 — gameloop removeButtonObject srwi. dot-merge (98.0909, banked)
SINGLE-instruction divergence, byte-identical otherwise:
- TARGET @888: `srwi r0,r3,3` + separate `cmplwi r0,0` + `beq` (fusion did NOT fire).
- CURRENT @1728: `srwi. r0,r3,3` + `beq` (branch-feeding cmplwi fusion 0x505820 FIRED).
The `>>3`/`&7` + 8x-unroll is the DYNAMIC-COUNT memmove lowering of `arr[i]=arr[i+1]` — the C
loop body has NO shift and NO compare. The srwi, the cmplwi-0 and the fusion are ENTIRELY
compiler-generated below source level. `#pragma peephole on` is already set (line 1241);
`peephole off` regresses to 87% (documented, kills all beneficial fusions). VERDICT:
DEFINITIVELY UNREACHABLE — no source expression feeds this redex; it is codegen-internal.
The fusion firing-vs-not is a scheduler-adjacency artifact on generated code, and the only
gate (peephole on/off) is global and net-negative. Do not chase.

### TEST 3 — track_dolphin fn_80061DD8 fresh-li vs CSE'd zero (98.6364, banked)
SINGLE 2-instr-vs-1-instr divergence:
- TARGET @24c4: `li r0,0; sth r0,gShadowVisibleCount` — materializes a FRESH zero (2 instr).
- CURRENT @39d8: `sth r4,gShadowVisibleCount` — reuses r4 (n's `li r4,0`), 1 instr, SHORTER.
`n=0` (line 2468) and `gShadowVisibleCount=0` (2472) share one value-number (all literal-0s
do). Target keeps the store's zero in a SEPARATE reg (r0); current coalesces into n's r4.
- LEVERS TRIED: (a) move modelState deref AFTER the store -> 96.10 (BIG regress, broke r11
  sched); (b) split `int n; gShadowVisibleCount=0; n=0;` (store before n-init) -> 98.5065
  (regress; `li r4,0` just moved after the lwz, store STILL reused r4 — VN identity of the
  two zeros is order-invariant). Both reverted.
VERDICT: this is a COLORING outcome (which physical reg the shared zero-web occupies at the
store — r0 fresh vs r4 coalesced), NOT scheduling/peephole/CSE. Statement order cannot force
the allocator to spill the zero-web into a fresh r0. Coloring-owned. Do not chase from here.

### GENERALIZED CONCLUSION for scheduling/peephole agents
The three canonical sub-caps all resolve to the SAME root: the SCHEDULABLE decision (store
order, fusion firing) is either (a) source-steerable via K5 list-order but COUPLED to a
coloring transposition that dominates (Test 1), or (b) on COMPILER-GENERATED code with no
source handle (Test 2), or (c) actually a COLORING/coalescing decision misfiled as scheduling
(Test 3). The list scheduler's ONLY source lever is K5 (statement order breaking a K1-K4 tie),
and it moves stores but NOT the coupled scratch coloring. `#pragma peephole/scheduling off`
remain global + net-negative (re-confirmed conceptually via the mechanism: they skip the whole
block, losing every beneficial fusion). NO clean scheduling/peephole source lever was found;
the residuals in this class belong to the coloring/CSE researchers. This is a DEFINITIVE
"unreachable from scheduling/peephole source steers" verdict for these three banked fns.

## randomGetRange() u32-proto cmp-width lever (2026-07-03, Opus) — 1 WIN, 1 coupled-REGRESS

modgfx.h declares `randomGetRange` as **u32** (outlier — 5 other headers agree it is `int`).
In units that include modgfx.h, a bare `if (randomGetRange(...) == 0/!= 0)` bool test emits
`cmplwi` (unsigned) where the target signed-compares (`cmpwi`). Fix = `(int)`-cast the call
result at the compare site. Root cause is the header, but header is shared by 34 units
(cross-agent risk) so cast per-site is the scoped fix.

- **WIN dll_000E_partfx partfx_spawnObject 98.399->98.483** (committed): cast all 6 sites
  (`randomGetRange(0,0x28)==0` @2783/5238, `(0,3)==0` @3227, `(0,10)==0` @3240, `(0,1)!=0`
  @4165/4182). All 6 cmp-width regions eliminated, 678->672 regions, no new regress. These 6
  are PURE `if()` guards — the result feeds ONLY the branch, no downstream live range.
- **REGRESS firecrawler hagabonMK2_updateB 98.269->98.063** (reverted): the single
  `randomGetRange(0,0x2ee)==0` @2255 cast FIXED its cmp-width but coupled a WORSE change nearby
  (net -0.2). LESSON: the cast is only safe when the compare result has NO downstream data
  dependency (pure guard). firecrawler's site sits in a longer live range -> ripple. Left at
  baseline. Same single-site risk likely applies to dll_000B_dll0b @3152 (untested, team-hot).

### SWEEP EXHAUSTED (2026-07-03, Opus, proto-signedness auditor) — 0 new wins, all remaining sites already match
Full tree-wide sweep of EVERY uncast pure-guard randomGetRange site (137 units include a u32
proto header: modgfx.h / vf_shared.h / dr_shared.h / wm_shared.h). Only 9 uncast direct-`if`
guard sites remain; ALL verified via objdump to ALREADY emit the target's cmp width (no cast
needed, casting would be inert or regress):
  - **playershadow fn_800A3AF0** (99.845%) 4 sites (`==1`,`==2`x3 @1461/1468/1475/1482):
    current ALREADY emits `cmpwi r3,1/2` = MATCHES target. Nonzero-literal `==N` compares
    against u32 stay signed here. Cast INERT. SKIP.
  - **light.c vfpdraghead_update** 3 sites (`!=0` @655/678/688): target WANTS `cmplwi r3,0`
    (UNSIGNED) and current ALREADY matches — u32 proto is CORRECT here. Cast would REGRESS. SKIP.
  - **dll_000B_dll0b dll_0B_func05** (98.164%) 2 sites (`==0` @3082/3152): current ALREADY emits
    `cmpwi r3,0` = MATCHES target (both bl-randomGetRange sites @0x5044/0x52ec signed). INERT.
  - firecrawler @2255: known coupled-REGRESS (above). SKIP.
KEY LESSON: cmp-width at a randomGetRange `==0/!=0` guard is NOT uniformly cmplwi under the u32
proto — MWCC picks per-site (partfx uncast=cmplwi, but dll_000B/playershadow uncast=cmpwi, and
light.c target WANTS cmplwi). partfx was the ONLY site where uncast≠target; it is committed.
The randomGetRange pure-guard lever is fully harvested. Do not re-scan.

### BROADER PROTO-SIGNEDNESS AUDIT (2026-07-03, Opus) — 0 wins, tree already matches
Scanned all headers for helpers declared with DISAGREEING signed/unsigned return protos (the
randomGetRange signature). Audited the frequently-called + compared ones against target objdump:
  - **GameBit_Get** (337 caller files, u32 in all 3 headers): target uses `cmplwi r3,0` at
    `!=0/==0` guards (verified light.c @0x1414/1528/15a4); current MATCHES. u32 proto CORRECT.
    Do NOT retype to int — would regress everywhere.
  - **isGameTimerDisabled** (u32 in engine_shared.h:1185 vs int in 4 other headers): all units
    that COMPARE it include an `int`-proto header (sky_80080E58 / sfa_shared / dll_80220608);
    target uses `cmpwi r3,0` (verified objseq ObjSeq_EvaluateCondition @0x2fa8/4ee0); current
    MATCHES. No unit uniquely pulls the u32 outlier into a compare. No lever.
  - **Obj_IsObjectAlive** (u32 in objlib.h vs int elsewhere): only 4 compare sites tree-wide, 2
    already `(int)`-cast. Tiny footprint, not high-value. Not pursued.
  - **rand** (u32 in sfa_extern_decls.h vs int): NO direct-compare guard sites in tree — inert.
CONCLUSION: the helper-proto-signedness cmp-width lever is exhausted. The tree's include-order
already lands each compared helper on the proto matching the target's compiled cmp width. Future
proto-audit agents: no net-positive header retype exists among the common compared helpers; the
one genuine per-site win (partfx randomGetRange) is already banked. Different lever needed.

## #51 CHAINED-STORE FP-CONST CSE lever — SWEEP (2026-07-03, Opus)

**Result: 0 wins. The additive-store #51 signature is fully harvested tree-wide.**

Method: scanned all `src/main/*.c` for functions with an FP `lbl_803[ED]xxxx` symbol
used in 2+ store/additive expressions (scan_cse.py). Cross-referenced against sub-100%
functions from a private report. For each (unit, fn, lbl) triple, compared TARGET vs
CURRENT `lfs`/`lfd` load counts of that symbol via function_objdump (cmpload.sh / sweep.sh,
in scratchpad).

- **Every parallel additive-store case** (`*outX = base + a; *outZ = base + c`, the classic
  #51 win shape — voxmaps_updateActiveMap, Camera_NdcToScreen, modellight center[], snowclaw,
  crfueltank, appleontree, model.c chain, dll_XX_func03 family, worldobj_init, Curve_EvalBezier)
  **already CSEs the const load-for-load identically to the target.** No reload mismatch. INERT.
- The `dll_XX_func03` buf.entries[] static-init family (dll_5C..dll_A9, ~70 units) is almost
  entirely **already 100%** — the const-CSE is intrinsic and matched.

**Load-count MISMATCHES found (via sweep) — NONE are #51-shaped, all skipped:**
Direction `target > current` = current OVER-CSEs (would need force-reload, NOT a hoist; #127
extern-const would worsen it). Direction `target < current` = current reloads more (hoist
direction) — only 1 case, and it's a `0.0` compare, not additive.
  - trickyfollow trickyFn_8013b368 lbl_803E23DC 17 vs 18 (hoist-dir): the extra load is a
    buried `fcmpo/fcmpu cr0,f,0.0` deep in an 8764B function's control flow — const=0.0f, NOT
    an additive store. No source lever (named `float zero=` over-promotes; 0.0-compares don't
    respond to end-placement hoist). BANK.
  - dll_0000_gameui pauseMenuFn_80129ee0 lbl_803E1E3C 6 vs 3 (target>current): 0.0f passed as
    3 call-args to Camera_SetCurrentViewPosition/GXSetViewport; target materializes per-arg,
    current CSEs. Call-arg const-coloring class, not #51. Also file HOT (semantic 12:19). SKIP.
  - lightmap sceneDraw lbl_803DCE30 10 vs 8; dll_00EF_pushable pushable_hitDetect lbl_803E3528
    12 vs 11; dll_0003_checkpoint fn_800D55BC 9 vs 8; skeetla trickyMove 9 vs 8; objprint
    shaderFuzzFn_8003cc1c 5 vs 4; firecrawler hagabonMK2_updateB 2 vs 1; newshadows renderShadows
    lbl_803DED2C 8 vs 7 — all `target > current` on scattered 0.0f/clamp-compare consts
    (rematerialization class), several in hot files. NOT #51. SKIP.

CONCLUSION for future #51 agents: the parallel-additive-store hoist-and-place-last win is
exhausted here. Remaining FP-const load mismatches belong to the **const-rematerialization /
call-arg-coloring** class (0.0f fed to fcmp/fneg/call-args across basic blocks), which the #51
end-placement hoist and the #127 extern-const retype do NOT fix (and #127 worsens the common
`target>current` direction). Different lever needed.

## opt_propagation-off UNROLLED-INDUCTION lever — SWEEP (2026-07-03, Opus)

**Result: 0 wins. The clean col-shape that won doPendingMapLoads (89.25->89.69,
0c8c9ebeea) does NOT recur elsewhere; the one true structural match regresses.**

RESTRICTION CONFIRMED: `#pragma opt_propagation off`/`reset` is ONLY valid in `-O4,p`
main-lib units (those already using `#pragma peephole`/`scheduling`/`opt_strength_reduction`/
`opt_common_subs`). rcp_dolphin.c already ships it (line 764). FORBIDDEN in audio/MSL/noopt.

Method: scanned all -O4,p main-lib units (src/main, src/main/dll, src/track minus audio,
119 units) for the EXACT winning signature — a scalar index var used in an address expr
(`base + var` / `[var]` / `var*K`), reassigned INLINE (`x=x+1`/`x+=1`/`x++`) mid-body,
then used again in another address expr WITHIN the same straight-line (unrolled) block, no
loop keyword between (scan3.py/scan4.py in scratchpad).

- The strict intra-iteration dual-use shape (shader.c `cellCursor[0]=lbl+col; col=col+1;
  cellCursor[0]=lbl+col`) is UNIQUE to shader.c in the visible source. Every other `x=x+1`
  hit is a **loop-tail counter** (search loops: objhits index/pointCount, pi_dolphin prev/i
  table scans, dll_0014 curves_remove) or **parallel pointer-induction at loop tail** (effect
  DLLs projgfx/expgfx: 6-8 `p=p+1` steps stacked at body end) — neither produces the coalesce.
- ONE genuine structural match: **dll_0014_unk.c RomCurve_func20** (91.68%, the `outZ[n]=...;
  n++; outX[mA]=...; outZ[n]=...; n++;` unrolled placement block ~L3695-3717). Its diff DOES
  show the artifact: target `mr r0,r29; addi r29,r29,1` (n=r29 clean +1 induction read direct)
  vs current `addi r0,r31,2` / `addi r0,r31,3` (n reassociated into mB/mA+K literal-addi +
  `slwi r0,r0,2` scaling). BUT:
    - `opt_propagation off` ALONE: 91.676 -> 91.615 (tiny REGRESS -0.06). Does not unfold here.
    - `opt_propagation off` + `opt_strength_reduction off`: 91.68 -> 87.34 (BIG REGRESS). SR is
      load-bearing for the outX/outY/outZ byte-walk induction pointers; killing it wrecks them.
  Reverted to baseline (no change committed). Unlike shader.c's pure-scalar col, func20 couples
  the propagation refold WITH strength-reduced word-index scaling (`slwi`) that propagation-off
  can't undo and SR-off destroys elsewhere — a coupled SR+coloring case, NOT the clean lever.

CONCLUSION for future opt_propagation agents: the clean unrolled-scalar-index col-shape is a
one-off (shader.c only). The lever is INERT-or-regressive when the mid-body index also feeds a
strength-reduced scaled store (`arr[n]` with word/vec stride), because SR and propagation are
entangled there. Do not add the pragma to func20. No further clean candidates in the tree.

## extsb/extsh-asymmetry flag->int SWEEP (2026-07-03, Opus) — 0 wins main-lib non-DLL

**Result: 0 wins. The clean scalar-flag-widen signature is exhausted in the accessible
(main-lib non-DLL) scope; the entire `src/main/dll/` scope was owned by an active DLL
deep-dive agent doing a tree-wide sweep, so left untouched.**

Method: extscan.py (in /tmp) — for each sub-100% fn (report proto, chkfn/extscan decode),
count `extsb`/`extsh` in TARGET vs CURRENT via function_objdump --diff; flag where
CURRENT > TARGET. Companion cmpscan.py flags signed/unsigned compare asymmetry
(cmpwi/cmpw more in current + cmplwi/cmplw more in target = int->u32 ptr-compare lever).

- **Whole-tree main-lib non-DLL (70-100%) yielded only 3 extsb/extsh candidates, 0 cmp
  candidates.** All 3 are COUPLED cases, not the clean flag-widen:
  - **objseq ObjSeq_ApplyFrameCurves 99.73 (extsh T6/C7):** the extra extsh is `s16 scroll`
    (objseq.c:1710) = `(int)(scale*val)` STORED to two s16 tex fields (offsetS/offsetT),
    ONE negated. This is the STORE-NARROW-REUSE class, NOT flag-widen. Retyping `s16 scroll`
    -> `int scroll` MOVES the eager extsh from the assignment to before the first store
    (`tex1->offsetS=scroll`) but does NOT drop it — target truncates that store with plain
    `sth` (no extsh) because scroll is reused for the negated 2nd store and target keeps the
    RAW int, extending only on the neg path. int vs s16 both give 2 extsh here. INERT. LEAVE.
  - **objseq ObjSeq_RebuildCurveStateToFrame 97.61 (extsb T10/C11):** `s8 flags` (objseq.c:1451)
    built `=1; |=2; =(s8)(flags|4)` and passed as the `int flags` param (4th arg) of
    ObjSeq_ExecuteActionCommand. The extra extsb is `extsb r6,r24` = the s8->int PROMOTION at
    the call site (target does plain `mr r6,r30`, flag lives wide in a saved reg). Looks like
    the exact lever BUT retyping `s8 flags`->`int flags` REGRESSED 97.61->97.23: the call-site
    extsb drops (good) but the DEF-site changes cost MORE — with s8, `|=2` and `=(s8)(flags|4)`
    compile to 2-instr in-place `ori;extsb rN,r0`; with int + `(s8)` casts they become 3-instr
    `ori;extsb r0,r0;mr rN,r0` (temp copy), and int + plain `|=2` LOSES the def-site extsb that
    TARGET emits. Target genuinely keeps flags as an s8-narrowed value in a saved reg (extsb at
    each def, in-place) yet promotes-free at the call — no C spelling reproduces both halves
    (the promotion is intrinsic to s8-local -> int-param). COUPLED def/call trade. LEAVE at s8.
  - **objprint objMathFn_8003a380 98.87 (extsh T22/C24):** already BANKED (#82 FP-perm, MEMORY;
    touched 2c8bb18926). Not this lever's domain.

CONCLUSION for future flag->int agents: the clean win requires a narrow local that is
COMPARED/TRUTH-TESTED 2+ times (re-extending per compare) and NEVER stored narrow nor passed
as a param whose def-site narrowing the target also emits. In this tree those are all in
`src/main/dll/` (gameui fn_80128A7C, pausemenu pauseMenuDrawStatus, babycloudrunner
sandworm_turnTowardTargetAnim, player fn_8029BDB4) — DLL-deep-dive territory. The main-lib
non-DLL residuals are STORE-NARROW-REUSE (scroll) or DEF/CALL-COUPLED (flags), where the
retype is inert-or-regressive. No source lever here.

## GX WRITE-GATHER FIFO union lever (raw-cast → GXWGFifo) — SWEEP (2026-07-03, Opus)

**Result: 0 wins. The raw-cast FIFO-write signature is fully harvested tree-wide.**

CANONICAL UNION SPELLING (use EXACTLY, do not invent):
- Header form: `GXWGFifo.<member>` where GXWGFifo is `volatile PPCWGPipe AT_ADDRESS(0xCC008000)`
  (include/dolphin/gx/GXVert.h line 30) with `#define GXWGFifo (*(volatile PPCWGPipe*)0xCC008000)`.
  Members: u8, u16, s16, u32, f32. GX_WRITE_U8/U16/U32/F32 macros wrap it (GXPriv.h L53-56).
- Local-decl form used by matched units: `PPCWGPipe2 GXWGFifo : (0xCC008000);` (newclouds.c L840,
  typedef union PPCWGPipe2 L828-838) or `WGPipe wgfifo : (0xCC008000);` (lightmap.c L2597).
- The drawGlow win (dll_000A_expgfx, 93.11->93.84, prior commit) used the newclouds-style local
  `PPCWGPipe2 GXWGFifo : (0xCC008000)` local decl.

CANDIDATES: tree-wide grep for raw volatile casts to 0xCC008000 that are NOT the union.
- **ONLY ONE file has raw casts left: src/main/rcp_dolphin.c** — 12 stores, all
  `*(volatile f32*)0xCC008000 = v;` in **lightFn_80052974** (L2080-2100).
- Every other file referencing 0xCC008000 (newclouds, objprint_dolphin, track_dolphin, pi_dolphin,
  lightmap, tricky, front, ~35 effect/DIM DLLs) ALREADY uses the union spelling. 0 raw casts.

WHY rcp_dolphin is INERT (verified via function_objdump --diff):
- All 12 raw casts are **f32** (no s16/u8/u16 narrow stores → no extsh/extsb to drop).
- MWCC ALREADY hoists the base: current AND target both emit `lis r31,-13311` (0xCC01) ONCE and
  store via `stfs f,-32768(r31)` (=0xCC008000). The FIFO-store block is BYTE-IDENTICAL current vs
  target. No per-write `lis` reload. The raw f32 cast CSEs the base identically to the union here.
- lightFn_80052974's residual is elsewhere (GXSetMisc/DCInvalidateRange arg-address coloring,
  gRcpWarpDistortDisplayList lis/addi materialization), NOT the FIFO stores. Not this lever's domain.

CONCLUSION for future FIFO agents: the raw-cast→union win only fires when (a) the store type is
NARROW (s16/u8/u16 → the raw cast forces extsh/extsb the union avoids) OR (b) MWCC fails to hoist
the base (per-write `lis`). Pure-f32 raw casts already CSE the base and match. rcp_dolphin's 12
f32 casts are byte-identical to target and need no change. NO raw-cast candidates remain tree-wide;
the lever is exhausted. (No source edits made this sweep.)

## DLL extsb/extsh + cmp asymmetry SWEEP (2026-07-03, Opus) — 1 WIN (mapScreenDrawHud)

**Result: 1 win in src/main/dll/. Worked the 3 handoff candidates + extended sweep.**
Committed 059db77979.

WIN — **dll_0000_gameui mapScreenDrawHud 98.1597->98.1713** (extsh T8->C7):
  The map-box height compute `h0=(s16)(v-0x14); if(h0<0)h0=0; h0<<=4` with `s16 h0`
  EAGER-narrowed the `(v-0x14)` into r24 at the assignment, then RE-extended (extra
  `extsh r0,r24`) before the `slwi`. Fix: hoist the pre-shift value into a local
  `int hh = v-0x14; if(hh<0)hh=0; h0=(s16)(hh<<4);` -> value stays wide through the
  clamp, narrows ONCE at the store to h0. Current now cleaner than target here
  (keeps hh in scratch r0: addi/cmpwi/slwi/extsh, 1 extsh vs target's 2 in r24),
  net fuzzy +0.0116, twice-confirmed, all gameui siblings hold, full build EXIT=0.
  GENERAL LEVER: a narrow local assigned `(narrow_cast)(expr)` then COMPARED and
  SHIFTED/re-used before a final narrow store -> hoist the pre-final value into an
  `int` temp, narrow only at the last assignment. Drops the intermediate re-extend.

HANDOFF CANDIDATES worked (all NEGATIVE, no lever):
  - **gameui fn_80128A7C 99.209** (extsh T8/C10): the 2 extra extsh are `s16 v` copies
    `v=scaled`/`v=alpha` (target plain `mr`, current `extsh`). But `v` is ALSO built by
    in-place s16 arith (`v&0x1f; v^=0x1f; v*=div15` -> target extsh's IN-PLACE into r24,
    no temp). Retyping `int v` REGRESSED 99.21->98.56 (loses the in-place arith extsh,
    adds temp mr). `int v`+explicit `(s16)` arith casts -> 98.99 (temp-copy at `v^=0x1f`).
    `s16 vv` temp for arith + `int v` for copies -> 99.17 (extra `v=vv` copy). COUPLED:
    the copies want plain-mr (int) but the arith wants in-place-narrow (s16) on the SAME
    var; no single spelling gets both. Same class as objseq RebuildCurveStateToFrame.
    LEAVE at s16 v.
  - **pausemenu pauseMenuDrawStatus_801274a0 97.9792** (extsh T9/C10): the 1 extra extsh
    is `*(s16*)(lbl_8031BB90+0x160)=magicVal!=0?0x4e:0x25` -> current `extsh`, target
    `clrlwi r0,r0,24` (u8 narrow). Casting the ternary `(u8)(...)` MAKES 1744 byte-match
    target (extsh->clrlwi, T9/C9) and the instruction stream is strictly 1-op closer, BUT
    aggregate fuzzy REGRESSED 97.9792->97.9718 (objdiff diff-alignment penalty; the
    baseline extsh had aligned favorably against a nearby target instr). Determinism
    confirmed. Genuine 1-instr miss but the metric says worse -> LEAVE (fuzzy is truth).
  - **player fn_8029BDB4 98.157** (extsb T9/C11): the 2 net-extra extsb are NOT a local
    flag-widen. All extsb here are `lbz s8_field; extsb; cmpwi` (signed-byte field
    COMPARES, target matches) or store-narrow (`addi;extsb;stb`, required). The count
    delta couples to a #108 coloring diff: a loop-induction reg r5(current)/r7(target)
    swap + a lwz/mr scheduling reorder. `u8 changed` local is unsigned (clrlwi not extsb).
    Field-access + #108, NOT type-correction. player.c sensitive -> LEAVE untouched.

EXTENDED SWEEP (DLL [95,100), extscan + cmpscan on /tmp/full.binpb proto):
  - extsb/extsh asymmetry: ONLY 6 fns flagged in [97,100), ZERO in [95,97). The 6 =
    the handoff list + mapScreenDrawHud (won) + partfx (deep-dive owns) + babycloudrunner
    (SKIP-banked store-narrow).
  - cmp signed/unsigned asymmetry (ptr->u32 lever): ONLY 1 fn flagged in [96,100):
    **partfx_spawnObject** (cmpwi T200/C213, cmplwi T132/C118) — a LARGE ptr-compare
    asymmetry, likely a real int->u32 lever at scale, BUT it's actively owned by the
    concurrent partfx deep-dive (last edit 44min ago). HANDOFF to that agent: partfx has
    ~13 excess signed cmpwi where target uses cmplwi (unsigned/ptr compares) — retype the
    compared locals u32/unsigned.
  CONCLUSION: DLL extsb/extsh + cmp asymmetry lever is now EXHAUSTED in [95,100) except
  partfx (owned). Clean flag/intermediate-widen wins are rare; most residuals are
  coupled (fn_80128A7C), alignment-negative (pausemenu), field/#108 (player), or owned.

## WIN Jul3 — partfx_spawnObject (dll_000E) 98.29->98.40 (variant signed/unsigned split)
Compare-asymmetry scan flagged cmpwi-excess (cur 118 cmplwi/213 cmpwi vs tgt 132/200).
Root cause = the `variant = *(u8*)extraArgs; if(variant=='\x01')...` chains. The shared
`int variant` local made every `variant==N` compare SIGNED (cmpwi). Target splits by chain
KIND:
- 8/3-value chains (case 0x323/0x30f/0x310, textureId 0xc9a/0xc98/0xc99, lines ~4899/5023/5079):
  the byte-load + whole if/else-if chain live INSIDE one `if(extraArgs!=NULL){...}` block with
  NO null-else merge -> target emits **cmplwi** (unsigned, tracks the u8 load).
- 2-value chains (case 0x54d..., lines ~2546/2576/2607/2637): `if(extraArgs==NULL){variant='\0';}
  else{variant=*(u8*)extraArgs;}` -> the two-way MERGE forces the declared `int` type ->
  target keeps **cmpwi** (signed).
FIX: kept `int variant` for the 2-value merge cases; added a SEPARATE `u32 variantU;` local
used only in the three 8/3-value non-merge chains (byte-wise rename in ranges 4899-4978,
5023-5045, 5079-5156, all pure-ASCII). Flipped exactly those chains cmpwi->cmplwi.
MEASURE: 98.2943 -> 98.3991 (twice-confirmed proto report), opcodes 118/213 -> 137/194
(tgt 132/200), all 4 siblings HELD 100%, all_source EXIT=0. Committed 14330cc97b.
FALSE START: retyping the shared `int variant`->u32 wholesale (v1, 98.386) OVER-flipped the
2-value merge chains to cmplwi (regressing them vs target's cmpwi); the separate-var split
(v2) is strictly better. LEVER GENERALIZES: signedness of a `*(u8*)p`-derived compare tracks
the declared type ONLY when the value merges from >1 assignment; a single-assignment-in-block
u8 read compares unsigned regardless. Use distinct locals when target wants both forms.
RESIDUAL (not chased, different class): ~5 `cmpwi rX,0` vs `cmplwi rX,0` zero-compares in the
tail/epilogue region + one `cmpwi rX,3`-vs-`,2` value mismatch + compare-count off-by-1 =
structural tail-codegen diff, NOT variant-chain; out of this pass's scope.

## #67d saved-reg-COUNT researcher (Jul02-03) — CRACKED the LEVER, characterized the coupling

### The compiler-source answer (Coloring.c / IroCSE.c / ValueNumbering.c)
The saved-GPR COUNT = the PEAK number of simultaneously-interfering webs in the GPR class
that are live at any program point (the register-pressure high-water mark among cross-call
values). Coloring.c is a textbook Chaitin-Briggs allocator with **NO spill-cost weighting**
(web+0xc is always 0; degree/cost = +Inf for every web), so there is no heuristic knob — the
count is purely structural. A value becomes cross-call-resident (-> a callee-saved reg, +1 to
the savegpr count) iff it is LIVE ACROSS A CALL. Per IroCSE.c/ValueNumbering.c the decision of
whether a value survives a call is:
  - A **memory-load expression** (e.g. `flags & MASK` recomputed, or `p->field`) is KILLED by
    an intervening call -> recomputed each side -> VOLATILE (r0/scratch), needs NO saved reg.
  - A value HOISTED by global CSE (IroCSE 0x46a360) to a dominator, OR a value cached in a
    named local, is NOT a killable memory expr -> stays available across the call -> gets a
    SAVED reg. This is the +1.
=> To ADD a saved reg (match a higher target count): CSE a value that is used/tested at >=2
   sites with a CALL between them into a named local computed once. To DROP one: keep the
   value a killable expression recomputed on each side of the call (no local).

### VALIDATED LEVER (the crack): Effect3_func04 (dll_001C_effect3)
Target `_savegpr_26` (6 saved r26-r31) vs our `_savegpr_27` (5 saved r27-r31). The extra
target reg = `(spawnFlags & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE)` (rlwinm ,0,10,10), which
is TESTED at line 1389 AND line 1933 with the entire switch (dozens of randomGetRange calls)
between. Target CSEs it ONCE into saved r31 (1 rlwinm); our build recomputed it at both sites
(2 rlwinm), so the extracted flag never took a saved reg.
FIX that MATCHED THE COUNT: `int useAttachedSrc = spawnFlags & MASK;` local, used at both
sites. Result: build flipped `_savegpr_27`->`_savegpr_26`, rlwinm 2->1, saved regs r26-r31
EXACTLY the target set. **#67d COUNT solved.**
BUT NET-NEGATIVE HERE (99.895 -> 99.600, REVERTED): the CSE'd flag colored to r29, target
keeps it in r31; the count fix triggered a #108 within-class NUMBERING permutation of the
6 saved regs (param<->flag homes swapped) that cost more diff than the count gain won. Decl-
reorder (flag first) did NOT move it off r29 (allocator picks by interference here, not decl
order). So for THIS fn the off-by-one count was NOT the dominant residual.

### GENERALIZED LEVER (documented for a sweep)
`int flag = X & MASK;` (or any value used at >=2 sites straddling a call) forces the value
cross-call into a saved reg = +1 savegpr, matching a higher target count. Inverse (recompute,
no local) drops one. **Use this ONLY when the target count is higher/lower AND the remaining
saved-reg NUMBERING already aligns** — otherwise the count fix unleashes a #108 renumber
cascade that can eat the gain (as in Effect3_func04). It is a genuine, reproducible lever, not
call-structure-fixed; the #67d count IS source-controllable via cross-call CSE. The catch is
it is COUPLED to #108 numbering, so a count-win only nets positive when numbering is neutral.

### SR-DRIVEN #67d is a DIFFERENT beast (RomCurve_func20, dll_0014_unk — banked, no win)
Target `_savegpr_22` (10 regs) vs our `_savegpr_18` (14 regs) — we OVER-commit 4. Root cause
is NOT cross-call liveness: the `outX[mB]/outY[mB]/outZ[mB]` array stores get STRENGTH-REDUCED
into per-array pointer-walker induction vars (`addi rWalk,+16` x6, r18-r21), each a saved reg.
Target does NOT walk (0 addi+16); it recomputes a shared byte index `mB<<2`/`mA<<2` via `slwi`
at EVERY store and uses indexed `stfsx` (24 stfsx tgt vs 11 ours). `#pragma opt_strength_
reduction off` HALVED the over-commit (_savegpr_18->_savegpr_20, stfsx 11->14, 2 walkers left)
but REGRESSED fuzzy 91.68->86.81 (partial SR-off produced a hybrid shape further from target's
full-recompute form; 789 instr vs target 831 — target has MORE, un-CSE'd index recomputes).
REVERTED. To match target here needs SR off AND index-CSE off so each store recomputes `slwi`
fresh — no single clean-C lever found; banked.

### SCAN TOOLING for #67d (reusable)
`scratchpad/sgdiff.py sub100.txt` compares min `_savegpr_N` in target vs src obj per scored
function (proto-unit `main/` + config-name-minus-.c). Live #67d list found (fuzzy, tgt/src min
savegpr; TGT<SRC = we over-commit, TGT>SRC = we under-commit):
  Effect3_func04 99.90 26/27(under1) | player_SeqFn 99.08 21/20(over1) | fn_80089A60 98.71
  24/23(over1, sky) | crawler_updateC 98.31 25/24(over1) | fn_802A87CC 96.24 14/15(under1,
  player) | expgfx_addremove 95.81 22/23(under1) | trackIntersect 95.57 16/17(under1) |
  mapLoadDataFile 94.78 22/23(under1, pi_dolphin) | fn_80007F78 94.03 15/14(over1, render) |
  drawGlow 93.84 14/15(under1, expgfx) | RomCurve_func20 91.68 22/18(over4, SR-driven) |
  doPendingMapLoads 89.69 18/20(over2, shader). The under-N (target saves MORE) cases are the
  CSE-flag-into-local candidates; try the lever where numbering is already aligned.

## #110 SHARED-ZERO-FOLD + #113 UNROLL-DECREMENT probe (2026-07-03, Opus, compiler-source researcher)

**Result: 0 wins. BOTH caps are DEFINITIVELY unreachable from clean-C source, now proven
from the recovered MWCC passes (not just empirical banking). #113's canonical example is
also RESOLVED tree-wide (matched by intervening work).**

### #110 shared-zero-fold — MECHANISM (from ValueNumbering.c + Coloring.c, recovered)
`li rN,0` vs `mr rN,rZero` (fresh-materialize vs reuse another reg's zero) resolves to the
COALESCE half of the register allocator, NOT to any orderable source construct:
- **ValueNumbering.c (ValueNumber_Block 0x509010)**: every literal `0` in a fn shares ONE
  value-number; a copy `dst=src` is DELETED iff dst/src carry the same VN at the copy point,
  KEPT iff they differ. To make two zeros distinct requires an INTERVENING DEF of the zero-web
  between the uses — and there is no clean-C construct that gives one literal `0` a distinct VN
  from another literal `0` (they unify order-invariantly). Confirmed by frontier TEST 3.
- **Coloring.c (Color_Coalesce 0x508c10 / Color_Select 0x508900)**: whether the store's
  zero-operand web is MERGED into an existing zero-web (`mr`/reuse) is set by the coalesce
  descriptor flags (`desc+0x24 bit1/bit2`) built UPSTREAM during web/move construction — not a
  source knob. Which physical reg the (non-coalesced) zero-web then takes is Select's
  lowest-free-reg over the web-index-ordered simplify stack. No cost weighting (web+0xc is
  always 0). So the target's `li r0,0` = a distinct zero-web that Select gave scratch r0; our
  `sth r4` = the store-zero coalesced into n's r4-web.

**TEST (track_dolphin fn_80061DD8, 98.6364, the canonical #110 store case):** single-instr
divergence — TARGET `li r0,0; sth r0,gShadowVisibleCount` (fresh zero in scratch r0) vs CURRENT
`sth r4,gShadowVisibleCount` (n's r4-web coalesced into the store), everything else byte-identical.
Source order ALREADY matches the target emission order (li r4,0; li r5,0; lwz r11; store). The
divergence is purely coalesce-vs-not. LEVER TRIED this session: swap decl order
`outCount`-before-`n` (the #126 web-index-tiebreak lever that cracked enemymushroom/controllight)
-> 98.6364->98.5065 REGRESS (swaps r4/r5 loop-counter assignment, wrong). The #126 decl-order
lever does NOT reach the store-zero coalesce because the store-zero web has a tiny post-init dead
live range that does not participate in the loop-body coloring the decl order controls; moving
decls only renumbers the LOOP webs (n/outCount), never the transient store-zero. Reverted; baseline
restored + reconfirmed 98.6364. VERDICT: #110 store-materialization-zero is COALESCE-owned and
has NO clean-C lever — the target's non-coalesce is an interference-graph artifact of its build
that no source spelling reproduces. Matches TEST 3's independent verdict. BANK — do not re-chase.

### #113 unrolled dead-var decrement — MECHANISM (from IroUnrollLoop.c, recovered) + RESOLVED
The `addi r4,r4,-2` (2x-unroll stride) vs `-1` is the unroll FACTOR scaling the induction
increment. Per IroUnrollLoop_Emit (0x4a3f80): the factor comes from the LOOP CONFIG window
(cfg+0x20/+0x24 thresholds vs the static trip count), NOT from source (U2: "cannot pick 2x vs 8x
from C"). The only source lever (U1) is toggling unroll on/off by making the trip count
static-vs-runtime — inapplicable to a fixed-bound scan like getControlCharLen (`while(i--)`, i=46).
The inlined-vs-standalone difference (frontier's old GameText_Count note) was the INLINER changing
the surrounding trip context, not a loop-source knob.

**TREE STATE (verified this session):** the canonical #113 example is GONE:
- `getControlCharLen` STANDALONE = **100%**; `GameText_CountPrintableChars`,
  `GameText_FindControlCodeArgs`, `subtitleParseControlCmds` = **100%** (the MEMORY #113 -2/-1
  case is fully matched by intervening work).
- ALL remaining inlined callers (textRenderStr 97.87, gameTextGet 99.58, textMeasureFn 92.05,
  subtitleBuildLineTable): every `addi ...,-2` (unrolled getControlCharLen) matches TARGET 1:1;
  every `-1` is an unrelated counter that also matches. There is NO live position where target
  `-2` faces current `-1` (or vice-versa) anywhere in the gametext/textrender scope. textMeasureFn's
  92% residual is BROADER register coloring (r4/r5/r20 vs r6/r4/r28 #108/#126 cascade) + harmless
  objdump psq mis-decode (`xsmaddadp`/`xxsel`), NOT a decrement-stride issue.
VERDICT: #113 has NO live divergence in the tree. The cap is RESOLVED; the mechanism confirms no
source lever exists even if a case resurfaced (factor is config-driven). BANK — nothing to chase.

### GENERALIZED for future #110/#113 agents
The just-cracked #126 (decl-order web-index tiebreak) and #67d (cross-call CSE-into-named-local)
levers do NOT extend to these two caps:
- #110's zero is COALESCE-owned (a copy-merge decision on VN-identical literals), not a
  web-index-order decision; decl order only renumbers loop-participating webs, never the transient
  store-zero, so #126 is inert-or-regressive on it.
- #113's stride is unroll-FACTOR-owned (loop config), fully below source level; #67d (a saved-reg
  count/liveness lever) has no bearing on an induction increment constant.
Both are DEFINITIVELY compiler-internal. No further probing warranted.

## #126 TREE-WIDE SWEEP (2026-07-03, Opus sweep specialist) — 0 fresh wins, class CONFIRMED-EXHAUSTED

Re-ran the #126 saved-GPR-swap sweep tree-wide (all sub-100 DLL + main-lib fns) with a fresh
proto report and a rebuilt detector chain. Independently re-derived and re-confirmed the
research agent's verdict: the winnable two-NAMED-loop-resident-locals profile is EXHAUSTED
(controllight + enemymushroom already won; nothing else steerable).

### DETECTOR CHAIN (scratchpad, reusable)
Report fuzzy is stored 0-100 float32-LE (NOT 0-1 — do not multiply). MWCC saves the GPR block
via `_savegpr_N` helper (NO per-reg prologue `stw` for r14-31), so the swap signal is the
FIRST-DEFINITION instruction of each saved reg (mr/lwz/li/addi/clrlwi...), not stack-slot order.
Three-stage filter:
  1. detect126b.py: same _savegpr_N + same reg SET, invert srckey->reg, flag GENUINE value->reg
     swaps (same source instr maps to a DIFFERENT saved reg tgt vs cur). Distinguishes a real
     coloring swap from a mere mr-emission-order diff (treasurechest_SeqFn: r3->r27,r5->r28 in
     BOTH, only the two `mr` emit order flips = NOT a swap, boundary).
  2. detect126c.py: keep only two-locals swaps where NEITHER source is a raw param copy
     `mr r3..r10` (param-home swaps = boundary #1, e.g. objFreeObjDef mr r3<->mr r4,
     dll_15_func08, objRenderShadow2 — all params, ABI-pinned, decl-inert). -> 22 hits [90,100).
  3. detect126loop.py + looptest.py: keep only swaps where a swapped reg is LIVE inside a
     backward-branch (loop) body. -> 15 hits [88,100). The KEY discriminator: the won cases had
     LOOP-RESIDENT locals (equal-priority PIN => decl-order tiebreak); linear-flow locals get
     web indices from use-structure, NOT decl order, so the lever is INERT on them.

### TESTED + REVERTED (all inert/boundary, tree now byte-clean)
- **hoodedZyck_updateB (firecrawler) 99.897**: swap turnRaw(int, fctiwz-store-reload lwz 260(r1))
  <-> mag(u32, clrlwi r0,16 u16-abs). 0 backward branches — NON-loop-resident. Decl-swap
  turnRaw<->mag INERT (turnRaw stayed r27). Boundary (linear-flow, use-structure numbering).
- **textureFreeFn_8012fcec (gameui) 98.824**: swap g(GameUiHud* base ptr, addi r3,0) <->
  z[0](loop counter, li 0). BOTH loop-resident (only clean-looking hit), BUT decl `g` before
  `z[2]` INERT — base stayed r29, counter r28 (off-by-one welded, boundary #3). The `u8 z[2]`
  array-element counter is welded.
- INSPECTED (not built, boundary by structure):
  - timer_update (dll_02B5) 99.10: state(184-deref)=r30 tgt / textureId=r31 — ALREADY banked
    boundary #3 (STATE-DEMOTE-BY-ONE welded) in the crack write-up. 0 backward branches.
  - boxDrawFn_8012975c (gameui) 99.02: swap is the u32->double bias const 0x43300000 (lis 17200,
    stw ...(r1)) vs a loop index. The bias-const reg is COMPILER-EMITTED (#70), not a named
    local — no source handle. Boundary.
  - RomCurve_func1E (dll_0014) 99.68: swap = inlined RomCurve_FindByIdInline binary-search
    internal value (lwz 0(r3)) vs its `low` counter (li 0). Inline-search coloring, not a
    top-level named pair; dll_0014 heavily worked. Boundary.
  - hudDrawCMenu (cmenu) 99.84: swap = &stackLocal (addi r1,8) vs base copy (addi r3,0). Stack
    address-of, welded. Boundary.
  - lightningDrawBolt (newclouds) 99.15: swap = x&1 (clrlwi r0,31) vs a `li 0` where the &1 and
    >>1 (srawi r0,1) come from ONE decomposed expression — compiler-split, not two named
    locals. Boundary.
  - expgfxRemove (dll_000A) 99.46, fn_80128A7C (gameui, already banked coupled #108),
    ObjHits_CheckObjectHitVolumes (0 backward branches), mapScreenDrawHud (WON per prior note):
    all derived-base-pointer or non-loop-resident swaps.

### VERDICT
The #126 lever fires ONLY when the two swapped saved regs are (a) both genuine NAMED source
locals AND (b) both loop-resident (equal PIN => decl-order is the allocator tiebreak). Every
remaining tree-wide hit fails (a) [magic const / inline-search temp / stack-address / decomposed-
expr half / obj-copy] or (b) [linear-flow, use-structure numbering] or is a welded off-by-one.
Confirmed via 2 rebuild-tests + 6 structural inspections. NO fresh wins. Class CLOSED for the
decl-order lever. Scratchpad detectors saved for any future re-scan after new matches land.

## SEMANTIC-NAMING sweep (2026-07-04, Opus semantic-recovery agent) — 1 commit, angle largely EXHAUSTED

### WIN (committed bcec01176f) — byte-neutral param_N naming, 3 files, all .o md5-IDENTICAL
- dll_00C4_tricky.c: extern-proto param_N -> role names via sibling signatures
  (objAudioFn_800393f8 obj/audio/soundId/volume, hitDetectFn_80065e50 pointCount,
  objAudioFn_8006edcc mask/scaleX/scaleY, objBboxFn_800640cc arg7-10). FUN_80147884
  shim body: param_1 (single-use = reg-intrinsic-only) -> unused1; forwarded param_2..8
  (pass-through to FUN_80006a64) -> arg2..8.
- tricky_substates.c: objAnimFn_8013a3f0 param_1-4 -> obj/animId/blend/flags (sibling).
- dll_0141_lightning.c: hitDetectFn_80097070 param_3-6 -> arg3-6.
- Verified: 3 .o rebuilt md5-IDENTICAL, ninja EXIT=0, 0 FAILED, changed lines pure-ASCII.

### EXHAUSTION VERDICT (tree-wide scan, non-hot/non-audio/non-dolphin):
1. **DEAD single-occurrence extern decls: 0 remaining** in DLL .c (prior team sweeps
   dll_0243/004F/014C/0054/00EF/0150/002A cleaned them). Top-level src/main .c also clean.
2. **Body-local Ghidra junk (iVar/local_/uStack): 0 remaining** in safe files. Only the
   tricky cluster had param_N remnants (now done). The 44 files still flagged by a raw
   DAT_/FUN_/param scan are: (a) the *_dolphin.c + objprint/newshadows/maketex/shader/
   lightmap/rcp cluster = OTHER AGENTS' domain (spill-slot names, skip); (b) the
   dll_006X-007X func0 cluster = ACTIVELY worked by struct-cast agent (commits "4 minutes
   ago", skip); (c) DAT_-global references (Angle 3, below).
3. **Angle-3 DAT_ naming: REJECTED by reloc discriminator.** Checked effect13
   (DAT_8039d0b8/d0bc/de090 lookup table) and hagabon (DAT_803de6d0 shared handle):
   NONE appear as R_PPC_EMB_SDA21 / ADDR16 reloc targets in the target .o (objdump -drz
   -M gekko). These DAT_ refs resolve via a base+offset already-relocated symbol, NOT as
   standalone relocated addresses -> naming them would be coincidental-alias = REJECT per
   the discriminator. No reloc-confirmed DAT_ naming opportunity found in owned units.
CONCLUSION: byte-neutral naming/dead-decl angle on units I safely own is EXHAUSTED this
session. Remaining junk belongs to active agents or fails the reloc test.

## STRUCT-RECOVERY (localPos-on-obj idiom) — VEIN EXHAUSTED + renumber-trap confirmed (2026-07-04, Opus struct-recovery)

Hunted the localPos/velocity/worldPos raw-cast -> `((GameObject*)obj)->anim.*` idiom on
GameObject-typed vars in DLLs (the func0 worldPos-spawn vein being separately worked/near-done).
**0 wins.** The DLL raw-pos-cast-on-GameObject-var vein is EXHAUSTED: a full tree scan
(scratchpad/scan2.py, scan3.py) found only **10 remaining load sites**, **0 store sites**, and
of the 10 loads only 3 are "clean" (no adjacent int->float conv) — all 3 in OFF-LIMITS files
(dll_0014_unk.c touched <2h by fresh-fuzzy agent; player.c team-hot).

### CONFIRMED NEGATIVE — the bias-double / sdata2 anon-reloc RENUMBER trap (frontier's known trap, now pinned to this idiom):
Two candidates tested, BOTH md5-REGRESS (text bytes IDENTICAL, only anon .sdata2 reloc ordinals shift):
- **dll_023F_dbegg fn_801FE774** (localPos-diff `sibling.localPos - *(f32*)(obj+0xc/0x10/0x14)`):
  typing the 3 obj reads -> `((GameObject*)obj)->anim.localPosX/Y/Z` left EVERY `lfs` instr
  byte-identical (verified via -drz diff) BUT renumbered `@254->@257` (x3) and `@481->@484` (the
  u32->double bias-double consts feeding the later `mathSinf/Cosf((gPi*(int)*(s16*)sibling)/...)`
  int->float conversion). md5 eec990->495e53. REVERTED.
- **dll_0044_cameramodeviewfinder** (2 sites, `obj.worldPos - *(f32*)(camObj+0xc/0x10)`): same
  class — function has `gCamViewfinderPi * camObj[0]` int->float conv; typing regressed md5
  d3e7bd->90128f. REVERTED.

### MECHANISM (why localPos-diff differs from the SAFE func0 worldPos-spawn vein):
The func0 spawn sites are byte-neutral because those functions are pure copies (dst.field =
src.field) with NO int->float conversion in scope. The renumber trap fires ONLY when the
enclosing function ALSO contains a `(f32)(int)`/`(f32)(s16)` conversion (bias-double `0x43300000`
sdata2 const): typing a nearby field access reorders the compiler's constant-pool insertion,
bumping the anon `@NNN` sdata2 ordinal by +3. Score-neutral (#70) but FAILS the src-vs-src md5 gate.
RULE for future struct agents: BEFORE typing an obj-field read/write, grep the enclosing function
for `mathSinf/mathCosf` or `(f32)(int/s16)` — if present, the change is NON-byte-neutral, SKIP.

### NEXT CANDIDATE IDIOMS (unhunted, for the next struct-recovery pass):
1. `*(u16*)(obj+0xb0)` objectFlags reads/writes on int-obj vars in DLLs NOT already typed (most are).
2. `*(int*)&obj->extra`-adjacent per-class state-block casts where a named `*State` struct exists.
3. NON-GameObject struct veins entirely: `ObjMsg`/message-buffer field casts (`*(TYPE*)(msg+off)`),
   `CameraObject` (camera_object.h), and the placementData s16-union view
   `*(s16*)(*(u8**)(state+0x4c)+off)` -> `->anim.placementData[N]` — but VERIFY the enclosing fn
   is conversion-free first (renumber trap above applies to ALL of these).

### RE-CONFIRMED EXHAUSTED (2026-07-04, second struct-recovery pass, Opus) — 0 new candidates
Fresh tree-wide re-scan of the localPos f32-cast idiom (all spellings: `(f32*)`/`(float*)`/
`(float *)` at byte offsets 0xc/0x10/0x14, plus `localpos` textual) after new decomp landed.
**No new byte-neutral localPos-on-GameObject candidate exists.** Every remaining raw-cast site
falls into a prior-known reject bucket:
- **dll_0231_dfpforceaw.c / dll_0232_dfprotatep.c** (the only files whose grep hits are the
  `+0xc/0x10/0x14` macro): the flagged lines 566-578 are a `SFXPLAYER_UPDATE_EFFECT_HANDLE_POS`
  macro that is DEFINED then immediately `#undef`'d (line 580) and NEVER invoked = dead text, not
  compiled. The LIVE localPos-diff sites (dll_0231 L540-558) sit in a function saturated with
  `convHi0=0x43300000; (double)(u32)convLo0` bias-double conversions (L505-507) — renumber trap,
  REJECT. dll_0232 is the same class (bias-double at L228/240/252/264 + `(float)((double)(int))`
  compares L119-144). Both files' localPos reads also use int-pointer arithmetic `*(float*)(obj+6)`
  = worldPos(0x18)/velocity, not the 0xc localPos, so even the base-offset doesn't match anyway.
- **weapone6.c:445** `(float*)(obj+0xc)` — `obj` is `int*` so `obj+0xc` = byte 0x30 (NOT localPos
  0xc; would need `(char*)obj+0xc`); it's an address ARG to ViewFrustum_IsSphereVisible, not an
  `lfs` load; file is mathSinf/Cosf + `(f32)(s32)` heavy (trap) and actively worked today (20:11).
- **dll_00D2_tumbleweed.c:74** — obj-side localPos ALREADY typed `->anim.localPosX/Y/Z`; the raw
  `*(float*)*hitEntry` is a hitEntry deref (correctly left raw), and the fn has 7 conversion sites.
- The objhits/objprint*/newshadows/lightmap/track_dolphin hits are the OTHER agents' spill-slot
  cluster (skip per frontier L637). appleontree/objprint `+0xc` hits are on `extra`/`curve`/`state`
  bases, not localPos on a GameObject.
VERDICT: localPos-on-GameObject idiom is DOUBLY-CONFIRMED EXHAUSTED. No .o was rebuilt (no edit
made — nothing passed the renumber-trap pre-filter). Next struct pass should pursue the NON-
GameObject veins in item 3 above (ObjMsg / CameraObject / placementData), conversion-free fns only.

## BANK Jul04 (fuzzy deep-dive: render fn_80007F78 94.03%, worldplanet_update 97.74% — no lever, spill/coloring caps)

### render.c fn_80007F78 94.03% (sz 2212) — frac.hi SPILL-vs-PROMOTE cap
64-bit audio-decode inner loop. ENTIRE diff cascades from ONE surplus saved GPR: current
uses `_savegpr_14` (18 saved r14-r31), target `_savegpr_15` (17, r15-r31). The surplus reg
is `r28 = frac.hi` (the sign-extension of `frac.v = (int)t`, a union{s64 v;int w[2];}). TARGET
spills frac.hi to stack `stw r0,40(r1)` and RELOADS it (`lwz r0,40(r1)`) at each of the two
`tmp*frac.v` 64-bit multiplies, keeping only frac.LO in a saved reg (r28) hoisted once from the
fctiwz conversion scratch (`lwz r28,36(r1)`). CURRENT promotes BOTH halves to saved regs
(lo=r29, hi=r28), never storing hi to mem, using `mullw r0,r4,r28` directly. This asymmetric
"low-in-reg, high-in-memory" split for a loop-invariant sign-ext is a pure ALLOCATOR spill
decision — no source spelling reproduces it. TRIED+FAILED: `volatile union` (91.81 — spills BOTH
halves, reloads lo too), explicit `frac.w[1]=(int)t; frac.w[0]=...>>31` (91.82 — both to mem
8/12(r1), lo not reg-held), plain `s64 frac` no union (94.00 — both promoted, inert vs union),
`#pragma optimize_for_size on` (83.88 — whole-fn structural blowup, wrong). The 150+ reg-perm
regions are all the r28-surplus renumber cascade (#67d/#108). NO lever. Left at committed baseline.

#### Jul04 SPILL-vs-KEEP compiler-source deep-dive (Opus spill-researcher) — DEFINITIVELY UNREACHABLE, 0 wins
Re-verified baseline 94.0271. Went to the recovered allocator source to settle the frac.hi
spill/keep question once and for all:
- **The `40(r1)` reload IS an allocator spill slot, NOT a source-visible struct field.** Target:
  `lwz r28,36(r1)` (frac.lo <- fctiwz scratch), `srawi r0,r28,31; stw r0,40(r1)` (frac.hi
  computed to SCRATCH r0, immediately spilled), then `lwz r0,40(r1); mullw ...` reloaded at each
  of the 2 multiply sites. Src: `lwz r29,36(r1); srawi r28,r29,31` — frac.hi lands in SAVED r28,
  used directly, never stored. Everything else = uniform renumber (target `_savegpr_15` r15-r31 =
  17 saved; src `_savegpr_14` r14-r31 = 18 saved).
- **Coloring.c (verified):** Chaitin-Briggs, NO spill-cost weighting (web+0xc bzero'd, never
  written → degree/cost = +Inf for every web). `Color_Select` (0x508900) spills ONLY on a genuine
  "no free reg" failure (flags|=1, ok=0 → driver InsertSpill). Optimistic spill in `Color_Simplify`
  (0x508a20) picks the **highest-web-index high-degree web** (structural, not cost). frac.hi is
  created late → high index → it IS the natural optimistic-spill victim WHEN pressure forces a
  Select failure. There is **no rematerialization pass** in the recovered allocator — the "spill"
  of a sign-ext is just the generic spill inserter (store once, reload per use).
- **Why the outcomes differ:** the spill is a pure peak-register-pressure tiebreak. Target's peak
  momentarily needed one more GPR than k → Select failed → optimistic-spilled frac.hi (highest
  index) → 17 saved. Our build's peak fit in k → no Select failure → frac.hi kept → 18 saved. Same
  C ⇒ nearly-identical interference graph; the ONE-web pressure delta that tips target into a spill
  is not expressible in source (no cost knob, no remat hint, no per-web spill directive).
- **All source forms tried (this session + prior), each rebuilt+measured:**
  - `union{s64 v;int w[2]}` (baseline) 94.0271 — frac.hi kept in reg.
  - `struct{int v}` (int, not s64) 93.6745 — widening at mul sites changed, WORSE.
  - explicit `frac.w[0]=(int)t; fracHi=w[0]>>31; frac.w[1]=fracHi;` 91.8192 — forces BOTH words to
    memory (union writes), lo no longer reg-held. WORSE (matches prior `volatile union`/explicit-w).
  - `register union frac` 94.0271 — INERT.
  - `#pragma scheduling off` 94.0271 / `+ #pragma peephole off` 94.0271 — INERT (allocation
    unchanged; the spill is not a scheduler/peephole artifact).
  - plain `s64 frac` (prior) 94.00, `#pragma optimize_for_size on` (prior) 83.88 whole-fn blowup.
- **Verified symmetric (not the delta):** curB sign-ext (`srawi rX,r22/r25,31`) is RECOMPUTED at
  multiple sites in BOTH builds; `end`(=dst+6), `maskConst`(0xFFF0) are SPILLED to stack slots in
  BOTH. No value is reg-kept in target-but-recomputed-in-src (or vice-versa) that could inject the
  +1 pressure needed to tip the spill via the #67d cross-call-CSE lever — the graphs match too
  closely. The one asymmetry IS frac.hi itself.
- **CONCLUSION (definitive for the #67d SPILL-vs-KEEP class):** unlike the #67d COUNT/cross-call-CSE
  case (source-controllable by adding/removing a named cross-call local), the SPILL-vs-KEEP of a
  specific sign-extension web is **decided entirely inside the pressure-driven Chaitin-Briggs
  select/optimistic-spill with no cost heuristic and no remat pass** — there is no source construct
  that makes MWCC spill exactly the high word while keeping the low word register-resident. Any
  typing that touches frac either keeps both (inert) or spills both (regression). This cap is
  **source-unreachable**; frac.hi spill/keep is not a lever. render.c fn_80007F78 stays at committed
  94.0271 baseline. (Distinct from the cracked #67d ADD-a-saved-reg lever, which works because it
  changes cross-call LIVENESS, a graph property; spill-vs-keep changes the per-web SELECT outcome,
  which is below source level.)

### worldplanet.c worldplanet_update 97.74% (sz 3136) — tbl[N][idx] addressing-fold + reg-perm
`int (*tbl)[5]` 2D-array accesses. ~4 addressing regions where target and current pick OPPOSITE
forms: `tbl[2][i]` (row offset 40) target=`add base+i*4; lwz 40(that)` vs current=`addi idx,40;
lwzx base,idx` (folds +40 into index); `tbl[0][b]` (offset 0) target=`lwzx base,b*4` vs
current=`add base+b*4; lwz 0`. The fold direction is context-driven (whether the index reg is
reused across sibling tbl accesses in the same loop — loop-590 shares b*4 across tbl[0/1/2] so
target keeps b*4 live and uses lwzx; loop-428 tbl[2][i] is standalone + i also feeds `mask>>i`
so target does add+lwz40). Fixing one direction risks breaking the other (opposite folds). Only
~4 regions vs 19 reg-perm (r19/r25/r31 vs r25/r26/r29 saved-reg perm dominates). Cap-shaped;
not attempted-committed. Deferred — marginal expected gain under a coloring cap.

## STRUCT-RECOVERY (per-class *State extra-block casts + CameraObject) — EXHAUSTED, #130 launder confirmed on state-field reads (2026-07-04, Opus struct-recovery)

Hunted idiom #2 (raw `*(TYPE*)((char*)state+off)` on an ALREADY-typed `*State` local ->
existing struct field) and CameraObject casts. **0 wins.** All accessible candidates regress
md5 or fail the bias-double / cross-agent gate. The fixed-offset-state-field-read sub-idiom is
now a CONFIRMED NEGATIVE (same #130 launder class as the frontier's obj `*(int*)&extra` note).

### PRECISE SWEEP (scratchpad, reusable): fixed-hex-offset raw casts whose base is a named
`*State` local (excludes func0/player/team-hot). Tree-wide only THREE hits — ALL disqualified:
1. **dll_00EF_pushable.c:1370** `state->flags = *(u16*)((u8*)state+0x100) & ~MASK` — 0x100 IS
   offsetof(PushableState,flags) (STATIC_ASSERT-confirmed), so this is a SELF-REFERENTIAL
   read-modify-write of the same field. Enclosing fn conversion-FREE. TESTED: arrow-ify to
   `state->flags = state->flags & ~MASK` -> .o md5 24f94a->f81585 (REGRESS). Reverted, md5
   restored. The raw u16 read is a #130 launder: the read-side and write-side of the same field
   CSE differently through the raw cast vs the arrow. NEGATIVE.
2. **dll_00C6_animatedobj.c:812** `int slot8 = *(s8*)((char*)seq+0x57)` — seq is `ObjSeqState*`,
   0x57 IS offsetof slot (u8, sits before curFrame@0x58 per STATIC_ASSERT), fn conversion-FREE,
   and the SIBLING line 832 already spells it `(s8)otherSeq->slot`. Looked like the ideal clean
   profile (NOT self-referential, reads into a fresh local). TESTED: `int slot8 = (s8)seq->slot`
   -> .o md5 039874->2851a5 (REGRESS). Reverted, restored. WHY: enclosing fn is
   `animatedobj_update` = the BANKED #126 loop-counter-vs-loop-pointer coloring cap (99.497,
   MEMORY.md). `slot8`/`slot` are heavily reused in the immediately-following ObjList scan loop;
   changing the load expression form perturbs the delicate CSE/coloring equilibrium of that loop.
   Launder-sensitive coloring cap. NEGATIVE.
3. **drhightop.c:562** `st->yaw = *(s16*)((char*)st+0x40e)+yawDelta` — DISQUALIFIED PRE-BUILD:
   enclosing fn has `mathSinf(gDrHighTopPi*(f32)(s32)st->haloDriftPhaseB)` = (f32)(s32) conv =
   bias-double sdata2 renumber trap (frontier rule). Also 0x40e is read SEPARATELY from `st->yaw`
   at line 553, so 0x40e may not even be yaw's offset (self-ref-adjacent). SKIP.

### CameraObject idiom: NO byte-neutral opportunity. `CameraObject` struct exists (camera_object.h,
well-defined through 0x14C) but ZERO src files reference the type — the CAM/ handlers spell "cam"
as short*/u8*/int throughout. The fov(0xB4)/probePos(0xB8) raw-cast sites the header advertises are
NOT present as clean `*(f32*)(cam+0xb4)` casts in the CAM .c files (grep for +0xb4/b8/bc/c0 f32
casts = 0 hits); the f32 casts that exist (e.g. arwing base+52/56) are on local matrix/vec bases,
not the camera record. Introducing `CameraObject*` = a new-type retype, not a per-site field-typing,
and the header explicitly warns against sizeof/array-indexing it. Out of byte-neutral scope. SKIP.

### GENERALIZED NEGATIVE for future struct agents (adds to the localPos exhaustion verdict):
The "raw `*(TYPE*)((char*)state+FIXEDOFF)` -> `state->field` on an already-typed State local" idiom
is NOT byte-neutral in general, even when (a) the offset provably equals the field, (b) the fn is
conversion-free, and (c) a sibling line already uses the arrow spelling. Two independent regressions
(pushable self-ref RMW, animatedobj fresh-local read into a coloring-sensitive loop) show the raw
cast acts as a #130-class launder whose removal shifts CSE/coloring. This is a DIFFERENT and more
pervasive failure mode than the localPos bias-double renumber trap: it fails the src-vs-src md5 gate
via *codegen* change, not const-pool reorder. RULE: state-field arrow-ification is presumed
NON-byte-neutral; only the pure spawn-COPY sites (func0 worldPos vein, dst.f=src.f, no reuse of the
loaded value) survive. The func0 vein is separately owned/near-done. No fresh struct-recovery win
exists in the accessible non-hot tree this pass; idioms #1/#2 (State-field, CameraObject) are
EXHAUSTED. (No .c/.h committed; both test edits reverted to md5-identical baseline.)

## STRUCT-RECOVERY (ObjModel->bufferFlags @model+0x18) — 1 WIN + vein map (2026-07-04, Opus semantic-recovery)

NEW conversion-free struct vein: `*(u16*)(model + 0x18)` = `((ObjModel*)model)->bufferFlags`
(ObjModel def in include/main/model.h L132-160, bufferFlags u16 @0x18 STATIC_ASSERT'd;
model = Obj_GetActiveModel(obj)). Precedent = pausemenu.c (`ObjModel* model;
model->bufferFlags &= ~0x8`, 10 sites). The `& ~8` bit-clear is byte-neutral vs raw u16 cast.

### WIN (committed 264580fb2d) — cloudaction renderClouds, .o md5 71f147f4... IDENTICAL
dll cloudaction.c: added `#include "main/model.h"`, retyped `u8* model`->`ObjModel* model`,
cast the 4 `Obj_GetActiveModel()` assigns `(ObjModel*)`, converted 4
`*(u16*)(model+0x18) = ...& ~8`->`model->bufferFlags &= ~8`. Fn is conversion-free (no
mathSinf/(f32)(int)/bias-double) so the new include + retype did NOT renumber sdata2 relocs.
md5 IDENTICAL src-vs-src; full ninja EXIT=0, 0 FAILED, changed lines pure-ASCII. The
model.h include (a fresh include in a DLL that lacked it) was md5-SAFE here — no conflicting
decls, no codegen shift.

### VEIN MAP (17 raw model+0x18 sites tree-wide; only cloudaction was clean+conv-free+unowned):
REJECTED (bias-double trap — enclosing fn has (f32)(int/u32/s16) => sdata2 renumber, SKIP):
  - dll_02B3_vortex.c L109/147/191: fn has `(f32)(u32)objAlpha` + `(f32)(setup->radiusParam/..)`.
  - cmenu.c hudDrawCMenu L655/658: fn saturated `(f32)(u32)*(u16*)`, `mathCosf((f32)*(s16*)..)`.
  - sky.c renderSunAndMoon L2903/2920: fn has `(f32)(s16)(int)` localPos conv (L2809+).
DEFERRED (conv-free but INVASIVE/CORE-FILE, marginal 2-site gain):
  - object.c Obj_UpdateModelBlendStates L2135/2156: `m`=u8* loop-local from `banks[j]`
    (ObjAnimBank**), ALSO used as `*(u8**)m` + passed to ObjModel_AdvanceBlendChannels(u8*).
    Full `m`->ObjModel* retype breaks 3 uses; inline `((ObjModel*)m)->bufferFlags` needs a
    fresh model.h include in a 22-include foundational file (md5 risk not worth 2 sites). Fn IS
    conversion-free — a future agent wanting the 2 sites can test the inline-cast + include and
    md5-gate it; left untouched here.
OTHER-AGENT territory (spill-cluster / complex buffer-select addressing): model.c (mtx buffer
  select `(& 1)*4` addressing), objprint.c, newshadows.c — skip.

### GENERALIZED for struct agents: the model+0x18 bufferFlags vein is now DOWN TO object.c only
(the one remaining conv-free site), and it is invasive. The bias-double pre-filter (grep fn for
mathSinf/mathCosf/(f32)(int|u32|s16)/0x43300000 BEFORE typing) correctly gated 3 of 4 rejects.
CONFIRMED: adding a fresh header include to a DLL is md5-SAFE when the fn is conversion-free and
the header introduces no conflicting decls (cloudaction proof) — the include itself is not the
risk; the renumber trap is purely the (f32)(int) sdata2-const interaction.

## BANKED (audio deep-dive, Jul04) — 4 fns, 0 source levers found
- **synthClaimVirtualSampleSlot** (vsample_alloc, 95.04): ENTIRE 24-region diff = pure
  within-class #108 saved-reg transposition. Target parks base `v`=synthVirtualSampleState
  in r31 (direct `addi r31,r4,0`), sb/voiceID byte-cast (`clrlwi ...,r29,24`) in r30.
  Current swaps: v->r30 (staged via r7-detour `addi r7,r4,0;...;addi r30,r7,0`), cast->r31.
  Loop walker is strength-reduced ptr (r7+=36 over streamBuffer stride). TRIED+INERT: decl
  reorder i/sb, addr-first, v-last (all 95.04, allocator unmoved). Base already hoisted to
  named local `v`; decl-order lever documented for #108 does NOT flip this pair. Bank.
- **hwSetADSR** (hw_adsr, 95.51): scratch-rotation cap. Target keeps base(dspVoice reload)->r0,
  field value->r4 on EVERY store; current matches first 2 stores then flips to base->r3/value->r0.
  Driven by reused `value`/`entry`/`offset` volatiles. TRIED+REGRESS: inline `entry=dspVoice+offset`
  into casts (63.55, entry recompute is load-bearing). INERT: value decl-first. Bank.
- **snd_handle_irq** (hw_init, 90.04): already tuned 5d ago (5 distinct zero temps). Residual =
  target derives changed[1..4] index by chained addi (+4) off one computed addr; current
  recomputes. TRIED+REGRESS: single `entry=dspVoice` per iter (76.22 — the 5 volatile reloads
  are required). Bank.
- **synthInit** (synth_control, 95.37): 401-instr voice-init; giant within-class GPR renumber
  cascade driven by 2 prologue diffs: target `li r30,0` in prologue (r30=voiceOffset zero reused
  for 4 global stores) + frame 128 vs 120 (extra 8B live-range). TRIED+INERT: chain globals off
  voiceOffset (copy-prop refolds to independent li). Bank #67/#108.

## WIN (structural deep-dive, Jul04) — bossdrakor_update 96.44->97.26
- **bossdrakor_update** (dll_024D_bossdrakor.c): +0.82%. The rotX/rotY/rotZ yaw-delta
  clamps used an `s16` accumulator `d`. MWCC narrowed the input at the compare (extsh on
  the yaw return) then PROVED the clamped value in-range and ELIDED the post-clamp narrow.
  Target double-narrows: extsh on input AND a second extsh on the clamp OUTPUT before the
  += / -=. Fix = the file's own matching neck-clamp pattern (line 405-409): declare an `int`
  accumulator (`step`), clamp as int, cast `(s16)step` at the store. Recovers the post-clamp
  extsh on all three clamps, drops the ext-delete regions, collapses reg-perm 62->14.
  LEVER (generalizable): a clamp feeding a narrow-store `field += clamped` wants an INT
  accumulator + explicit `(s16)` at the store to keep the post-clamp narrow the target has;
  an s16 accumulator lets O4 prove range and elide it. Committed d5e02c9888.
- BANKED same fn: shakeX/shakeY loop-invariant `sth` gets a spurious pre-loop extsh
  (r27/r28 saved) + store-order swap (uvec[1]/[0] reg assignment) vs target `mr`+direct sth.
  s16-typing shakeX/Y REGRESSED (97.26->97.14). Loop-invariant-narrowing hoist + coloring,
  no clean lever.
## BANKED (structural deep-dive, Jul04) — animobjd2 fn_8013E0D0 96.92
- TRICKY_RETARGET `*(s32*)flags &= ~0x400LL` emits a dead `srawi r0,r3,31` (high-word of the
  64-bit AND, immediately clobbered by li -1025). Target has none. The LL is REQUIRED to defeat
  the single-bit-clear->rlwinm peephole (plain `~0x400` gives rlwinm, target wants `li -1025;and`).
  Isolated repro of s32+LL NEVER emits the srawi even under pressure/pragmas — it's a within-fn
  register-pressure artifact (AND lands in r0, srawi kept alive). u32 lvalue kills srawi but
  wrong coloring (li r3,0 for the trailing sth 0xd2 steals r3): 96.92->96.35. Statement swap
  regressed 94.4. Also a `bne;b` vs `beq` branch-island fold on the eventTime `&&` (nested-if
  split re-fuses identically). Both = known-resistant layout/coloring caps.

## BANKED 2026-07-04 (Opus, synth-cluster audio deep-dive — 6 fns, 0 wins, all within-class)
Session mined synth/voice/seq/reverb/adsr/mcmd cluster. Every candidate = within-class
saved/scratch-reg coloring OR single-instr scheduling cap; NO source lever (all tries
inert or regressed). Confirmed-resistant this pass:
- **synth_handle/synthUpdateHandle 93.63**: prologue r8/r9-vs-r5/r8 volatile split for
  the queued/allocated list-walk + r0-detour on voiceBytes/voiceCursor init (addi rX,r27,0
  target vs mr rX,r0 current) + currentStudio reloaded via shared r27 base (3760(r27))
  vs raw r29 (8880(r29)). TRIED: `voice->currentStudio` in loop cond (93.63->92.38 REGRESS),
  swap voiceBytes/voiceCursor decl order (->93.49 REGRESS). Volatile-reg cascade, no lever.
- **vsample_alloc/synthClaimVirtualSampleSlot 95.04**: UNIFORM r30<->r31 saved-reg swap —
  target v(base symbol synthVirtualSampleState)=r31, voiceID-clrlwi-offset=r30; current
  reversed. TRIED: named `u8 vid=voiceID` local (95.04->93.27 REGRESS, adds copy). #108.
- **synth_queue/synthQueueHandle 96.28**: voice ptr r28(target)/r31(current) + loop-counter
  i r31/r30 renumber; target stages gSynthVoices[found] addr in scratch r3 then copies to
  r28, current computes direct into r31. TRIED: decl-reorder i-first (INERT). #108.
- **mcmd_exec/mcmdVarCalculation 95.46**: param home r28/r29/r30(target ascending)/
  r30/r31/r27(current scrambled) + extra `mr r3,r0` on extsh-narrow of varGet32 result.
  Within-class param coloring. Not pursued past gap analysis.
- **mcmd_exec/macInit 92.12**: target strength-reduces off(r8)=copy-of-zero (addi r8,r7,0)
  with loop-bound lis r3 interleaved; current emits fresh `li r8,0`. Chained-init
  `macRealTimeLo=off=0` is ALREADY best. TRIED: split off=0 (89.62 REGRESS both positions),
  decl i-first (90.38 REGRESS). Const-share/schedule cap.
- **hw_adsr/hwSetADSR 95.51**: uniform base/value scratch-reg split — target dspVoice base
  ->r0, value->r4; current base->r3, value->r0 (same load ORDER, diff regs) across ~10
  store sites. TRIED: entry-before-value stmt swap (INERT), inline base drop-named-entry
  (95.51->78.79 REGRESS — named `entry` REQUIRED). Scratch-coloring cap.
- **mcmd_setup/DoSetPitch 98.00**: SINGLE instr — `srwi r4,r7,24` (oKey=prevSampleId>>24)
  scheduled 1 slot early; target computes key(mulli+add) THEN oKey THEN cmpw, current oKey
  first. #84 arg-hoist that scheduling-off would fix but FORBIDDEN in audio units. TRIED:
  (no*12)+i reorder (INERT), inline `key>(oKey=...)` (98.00->95.50 REGRESS). 1-instr cap.

## STRUCT-RECOVERY (ObjModel bufferFlags — object.c site WON + DLL vein blocked by header conflict) — 1 WIN (2026-07-04, Opus struct-recovery)

### WIN (committed 58fec2789f) — object.c Obj_UpdateModelBlendStates, .o md5 3bf5f1fc... IDENTICAL
The frontier's explicitly-DEFERRED object.c bufferFlags site is now recovered. Both banks[]
model-instance sites (L2135/2156) `*(u16*)(m + 0x18) &= ~8` -> `((ObjModelInstanceLite*)m)->
bufferFlags &= ~8` (INLINE cast, `m` KEPT as u8* for its other uses `*(u8**)m` @off0 +
ObjModel_AdvanceBlendChannels(m,...)). Used the FILE'S OWN idiom — objmodel_types.h's
`ObjModelInstanceLite` (bufferFlags u16@0x18), precedent at Obj_SetModelRenderOpAlpha L157-160
(`ObjModelInstanceLite* model = (ObjModelInstanceLite*)objAnim->banks[..]; model->file`).
NO new include (objmodel_types.h already in object.c). Fn conversion-free. .o md5 IDENTICAL
src-vs-src, full ninja EXIT=0 0 FAILED, changed lines pure-ASCII. KEY: the inline-cast (not a
full local retype) is the minimal byte-neutral move when the local has non-field uses; the
lite-struct exists precisely for this. This CLOSES the prior "vein down to object.c only" note.

### DLL bufferFlags vein — HARD-BLOCKED by ObjModel_GetJointMatrix redeclaration conflict:
The remaining clean+conv-free DLL bufferFlags sites — dll_0262_drakormissile.c:412
(drakormissile_render, CONV-FREE, model used ONLY for +0x18), dll_00E5_shield.c:990/1011
(shield_render, CONV-FREE, 2 sites), dll_00E3_fireball.c:1112 (fireball_render, CONV-FREE but
model ALSO raw-casts +0x34=textureRefs) — all need `ObjModel` visible to field-ify, but full
`ObjModel` is NOT reachable via their existing includes (only a `f32* ObjModel_GetJointMatrix
(int*,int)` fwd-decl from dr_shared.h / the DLL shared headers). Adding `#include "main/model.h"`
CONFLICTS: model.h declares `ObjModelJointMatrix* ObjModel_GetJointMatrix(u8*,int)` — a signature
mismatch = compile error (tested drakormissile: `undefined identifier 'ObjModel'` without include;
model.h include would redeclare-conflict). These DLLs also can't reach objmodel_types.h's
ObjModelInstanceLite. So the inline-cast trick that worked in object.c is UNAVAILABLE in the DLLs
(no lite/full ObjModel type in scope, and the one header that would bring it conflicts).
REJECTED-by-bias-double (unchanged from prior map): dll_00E2_staff.c:1372 (staff_update has
`(f32)(int)*(s16*)(vp+0x10)`), dll_01CA_dimexplosion.c:400 (explosion_render has `(f64)(int)` x2),
vortex/cmenu/sky (prior map). dll_01D6/objprint*/model.c/newshadows = complex `&1`-select
addressing or other-agent spill cluster.

### player-objectFlags DLL vein (`*(u16*)(player+0xB0)` on Obj_GetPlayerObject local) — ALSO header-blocked:
maybetemplate.c pauseMenuDrawStatus L586/619 (`u8* player=Obj_GetPlayerObject(); *(u16*)(player+
0xB0)&0x1000` = objectFlags, CONV-FREE) and NW/dll_01A5_nwlevcontrol.c, dll_0000_gameui.c: the
full `GameObject` struct (with objectFlags@0xB0) is NOT reachable in these DLLs — they use an
opaque/fwd GameObject and deliberately omit game_object.h; `objectFlags`-visible=0 via preprocess.
Retyping player -> GameObject* OR inline `((GameObject*)player)->objectFlags` both need
game_object.h, a wide invasive include in files full of custom typedefs (conflict/renumber risk,
many `(int)player` call-sites). staffactivated_helpers.c L188 `*(f32*)(player+0xc)` = localPos-diff
spawn = bias-double trap territory anyway. NOT byte-neutral-safe. SKIP.

### GENERALIZED verdict for struct agents: the ObjModel/GameObject field-recovery vein is now
GATED NOT by the bias-double renumber trap but by HEADER REACHABILITY + REDECLARATION CONFLICT.
The main-tree file that already carries the type (object.c via objmodel_types.h) is DONE. The DLL
sites are blocked because (a) they lack the struct type in scope and (b) the header that supplies
it (model.h) has a conflicting `ObjModel_GetJointMatrix` signature vs the DLL shared decls. A
future win here requires either harmonizing that decl (out of struct-recovery scope, touches
shared headers = many owners) or a per-DLL lite-struct like objmodel_types.h — both structural,
not per-site. The accessor->raw-cast bufferFlags/objectFlags vein is EXHAUSTED for byte-neutral
per-site work: object.c won this pass; all other sites are bias-double-trapped or header-blocked.

## BASE-HOIST SWEEP (2026-07-04, Opus bh51 agent) — 0 wins, class EXHAUSTED in accessible tree

Followed up salActivateStudio 84.70->100 (hoist `.data` array base into named saved-reg local).
Built a precise fingerprint scanner (scratchpad/bhdec.py + parked.txt): for every sub-100 fn,
compare TARGET vs CURRENT ADDR16_HA/LO symbol materialization. WIN shape = target `addi
rSAVED,r3,0` (base in r14-r31) while current uses scratch/no-saved. Found 36 such fns across
main+audio+DLL. RESULT: every one is either already-hoisted (local exists, MWCC still picks
r0/detour) or the target itself re-materializes cheaply via SDA21 (`lwz rN,0(r13)`, 1 instr —
NEVER parked, current already matches; hoist would REGRESS).

### KEY DISTINCTION (why salActivateStudio won but these don't):
- salActivateStudio: `dspStudio[studio].field` with a RUNTIME index (param `studio`). The base
  went straight into a saved reg as `add rWork,rBase,rIdx; lwzu` — no offset pre-compute, so
  introducing the named local flipped r0->r31 cleanly. `lbl_803CC1E0` is ABSOLUTE (ADDR16_HA),
  not SDA.
- The 36 residuals: base used to derive CONSTANT field offsets (+16/+24/+48...) BEFORE the
  loop. MWCC materializes base into r3, computes the offset walkers, THEN copies base to the
  saved reg via `mr` — the r0/r3-DETOUR (`addi r3,r3,0; mr rSAVED,r3` vs target `addi
  rSAVED,r3,0`). Exactly the objLoadPlayerFromSave / player-family #108 r0-detour cap.

### EMPIRICAL CONFIRMATION (voxmaps_resetLoadedMaps, gVoxMaps r24, 96.9231):
Single-instr miss: target `addi r24,r3,0`; current `addi r3,r3,0; mr r24,r3`. Tested the
salActivateStudio fix verbatim: hoisted `VoxMaps* base = &gVoxMaps;` and derived all 4 field
walkers (`base->slotOrigin/mapBuffer/blockId/timer`) from it. Rebuilt: BYTE-IDENTICAL, detour
UNCHANGED, fuzzy 96.9231->96.9231 (INERT). Reverted to md5-identical baseline. Confirms the
detour is intrinsic to the named-.data-pointer init when constant field-offset walkers are
pre-computed; the hoist cannot flip it because the local already exists / MWCC needs r3 first.

### VERDICT: the base-hoist lever is a NO-LOCAL->LOCAL transform. Prior matching passes already
introduced these locals tree-wide (pad `base=`, shield `tbl=`, expgfx `runtime=`, dfshshrine
`base=`, boneparticle `base=`, staffcollision `base=`, walkgroup `base=`, savegame `s=`, etc.).
What remains is pure #108 saved-reg coloring / r0-detour, which the hoist does not address.
No fresh base-hoist win exists in the non-hot, non-owned accessible tree this pass. Owned/skipped:
player.c (r0-detour family, other owner), objprint/objprint_dolphin (-O4 deep-dive agent),
sal_studio/synth_voice/hw_dspctrl (the 3 macro-base defines, audio deep-dive agents), shader/
track_dolphin/lightmap (team-hot <3h). NO .c committed; the one test edit (voxmaps) reverted.

## BANKED (structural deep-dive, Jul04 session2) — 6 fns, 0 wins, all coloring/artifact caps
Ranked sub-98 fns, prioritized count-mismatch (T!=C) + ext-class regions. All 6 turned
out to be coloring/const-materialization/compiler-artifact caps with NO source lever:
- **model modelLoad_calcSizes** (93.53): line 2212 `total = A + (B<<2 + 0x1c + total)`.
  Target places const 0x1c EARLY (addi r0,r5,28 before the two adds); MWCC canonicalizes
  const-LAST regardless of parens (tried extra `((B+0x1c)+total)` grouping — INERT). The 3
  add-regions are downstream of `total` living r7(mine)/r6(target) coloring. Pure #66/#108.
- **voxmaps voxmaps_resetLoadedMaps** (96.92): target `addi r24,r3,0` stages slotOrigin base
  directly into r24; mine `addi r3,r3,0`(no-op self)+`mr r24,r3` (+1 instr). The r0-detour/
  redundant-copy named-saved-reg-ptr-init pattern (memory-documented resistant). Comma-init
  reorder (slotOrigin LAST) REGRESSED 3->4 regions. Bank.
- **savegame SaveGame_gplaySetObjGroupStatus** (96.67): the two `transient[i]` search loops
  (MapBitTransient 3-byte struct) — target keeps FIXED base r4 + growing displacements
  (0,3,6,9) across the 4x-unroll, incrementing ONLY the counter r3 (SR-off form). Mine
  strength-reduces to a `+3` ptr induction var + separate counter (2 IVs). `#pragma
  opt_strength_reduction off` scoped whole-fn REGRESSED 25->67 regions (disabled SR on the
  other good groupStatus loops 518/530 too). No per-loop SR control. Bank #112.
- **object objFreeObjDef** (96.87): 52 regions ALL reg-perm (r29/r27, r30/r31, r4/r5), T=C=356.
  Pure saved-reg numbering cascade from one offset. SKIP-coloring. (also touched by another
  agent mid-session.)
- **mm mmAllocateFromFBMemoryStore** (96.99): target `mr r5,r4` stages param `size`->r5
  (keeps r4 free for gMmStoreArray walker); mine keeps size in r4, walker in r5 (opposite
  pref, no mr, -1 instr). Local `int sz=size` copy INERT (copy-props back). Register-pref
  coloring cap. Bank.
- **pi_dolphin loadDataFiles** (96.82, 2-instr, PRE-BANKED): the region is the EMPTY
  `vi=0x50; do{}while(++vi<0x57)` spin loop (NOT the scan loop the old comment blamed).
  Target emits counted `subfic 87-i; mtctr; bdnz`; mine `addi;blt`. Rewriting empty do-while
  as `for` DELETED the loop entirely (dead-code, -6 instr, worse) — do-while is REQUIRED to
  keep it. mtctr counted-loop emission for an empty body is a compiler-internal decision, no
  source lever. Confirms prior bank.
- **rcp_dolphin textureFn_80053d58** (97.25, 5 regions): li-const region — target reuses
  r30(=mipmap 0) for both stw 64 / stb 72; mine spills fresh `li r0,0`. mipmap saved-reg-zero
  reuse vs fresh-materialize = const-materialization coloring. Bank.
NET: 0 committed changes this session (all experiments Edit-reverted). Real source-
controllable ext-delete (s16-clamp, my specialty) lives in headdisplay drawFn_80125424
(`extsh r0,r26` before u32->double xoris) but that file had a very recent ext-CSE commit
(active-agent domain) — deferred to avoid one-owner collision.

## Jul04 dd55 session (bossdrakor + banked coloring caps)
- **WIN bossdrakor_update (dll_024D) 97.26->97.48** (+0.22, committed 75b5f7e8f8):
  `step = (s16)Obj_GetYawDeltaToObject(...)` on the rotX yaw-delta clamp
  (lines 171-180). Target narrows the call result to s16 BEFORE the
  [-0x200,0x200] clamp (extsh-before-cmpwi) and loads anim.rotX first;
  raw-int assign clamped early with constants in wrong reg. Cast collapsed
  both li-const clamp regions. Verified twice (97.482), all-source EXIT=0,
  0 FAILED, siblings 100%/unchanged (headTracking 98.05). Residual = #108
  shakeX/shakeY r27/r28 store-perm + #82 FP f1/f3 perm (store-order swap
  INERT, both tried).
- BANKED (no source lever, coloring/compiler-const bound):
  - drlasercannon_aimAtTarget (DR/0261) 97.66: `(s16)yaw` cast REGRESSED
    97.66->97.02. clamp/negClamp r27/r4 vs r6/r3 within-class #108. Named
    lbl_803E68D8 vs @NNN = #70 u32->double bias, neutral.
  - cmbsrc_init (dll_02B1) 99.45: 20 pool-relocs all #70 named-vs-anon bias
    doubles. Const-ifying the cmbsrc lbl externs in shared header was FLAT on
    init (99.453) and REGRESSED siblings (shouldActivate/hitDetect 100->99.5).
    Reverted. Header-const risky even for exclusive symbols.
  - DR_CloudRunner_stateHandler05 (DR/0258) 99.09: 4 fcmpo = f4/f3 reg-numbering
    (#82), not operand swap. Banked.
  - dfsh_shrine_update (DF/0178) 99.32: RESET-loop i/required r30/r29 sched-order
    (#108); decl-reorder REGRESSED 99.32->99.20. jumptable_80326024/@NNN +
    bias doubles = compiler-emitted. Banked.
  - DIMwooddoor_updateShardAim (DIM) 99.15: distSq f31 vs f3 fcmpo (#82).
    const-ifying lbl_803E48C8 (local extern, used 3x) FLAT (99.154). Reverted.


## BANKED (s16-clamp sweep, Jul04) — clamp double-narrow lever tree-wide: 0 wins/3 tries
Swept sub-99 -O4 fns for the bossdrakor lever (target DOUBLE-narrows a clamp/store:
extsh on clamp-input AND on clamp-output before sth/+=; retype accumulator int + cast
(s16) at store). Tight source scan (narrow local, clamped, feeding +=/narrow-store) found
only 5 real candidates; ext-delete ndiff scan over 177 clamp-file sub99 fns surfaced ~20
more, mostly getAngle-narrow or #126 param-staging (NOT clamp-store). All 3 clean tries
regressed or inert -- the residual extsh is compiler-internal, NOT source-castable here:
  - CameraModeBike_update (dll_0045_camTalk) 98.178: two ext-deletes = target `extsh r0,r0`
    before `sth 0(r31)` (rotY += angleDelta>>3) and `sth 2(r31)` (rotZ = rotVal, int->s16).
    `short angleDelta`->`int` EXPLODED ext-delete 2->9 (the clamp COMPARES `if(0x8000<d)`
    change width w/ int accum -> addis/addi/cmpwi -32768 mismatch; angleDelta is used in
    BOTH clamp and store, so can't int-ify without breaking the compare). `(s16)(angleDelta>>3)`
    on rotY store REGRESSED 97.807 (added ext-INSERT + frame delta, extsh landed elsewhere
    not at sth). `(s16)rotVal` on rotZ store INERT (int->s16 store already truncates; the
    target extsh at sth is not reproducible by a source cast). Banked baseline.
  - drlasercannon_aimAtTarget (dll_0261) 97.660: ext-delete = target `extsh r28,r0` (narrows
    getAngle yaw return into saved reg) vs current `mr r28,r3`. `pitch=(s16)getAngle` is cast
    but `yaw=getAngle` is NOT -- looked injectable. BOTH `yaw=(s16)getAngle` AND `s16 yaw`
    retype REGRESSED 97.021 (ext-delete 1->3): the target's extsh is a coloring byproduct,
    the yaw/pitch asymmetry is intentional. Banked baseline.
  - fn_80128470 (dll_0000_gameui) 98.424: ext-delete = target `extsh r31,r25` before
    `mullw` on `alpha16*(0x200-lbl_803DD75C)`. `int alpha16`->`s16` INERT (98.424, moved
    the extsh: ext-delete 1 -> ext-delete1+ext-insert1, net zero). Banked baseline.
LEVER SCOPE (refined): the bossdrakor win holds ONLY when the clamp accumulator is a
SEPARATE var from the clamp-COMPARE operand (bossdrakor: `int step` accum, clamp on `step`,
store `(s16)step` -- clean). When the SAME narrow var is both compared in the clamp AND stored
(camTalk angleDelta), int-ifying breaks the compare width; when the extsh is on a call-return
narrow or a mul-operand (drlasercannon/gameui), it's a coloring/use byproduct not a store cast.
No further clean clamp-double-narrow candidates remain tree-wide (all in target-matching
int-accum form already, or no ext-delete, or resist as above).

## dd57 flat-DLL structural deep-dive (Jul04, Opus) — 5 candidates examined, all coloring caps

- **SaveGame_gplaySetObjGroupStatus** (dll_0017_savegame) 96.67% BANK: first transient-scan
  loop `for(i){transient[i].mapId==idx && transient[i].shift==shift}` — target keeps base r4
  FIXED with constant displacements (0/3/6/9/12(r4)) + index i in r3 (+1/body, +15 at unroll
  boundary); my build strength-reduces base to walker (+3/body) AND keeps separate index
  (+1/body) = 1 extra addi/body. TRIED+FAILED: `MapBitTransient* e=&transient[i]` elem-ptr
  (96.30 regress — SR'd base harder), `gTransientMapBits[i]` global-array index (96.09
  regress), `#pragma opt_strength_reduction off` fn-scoped (71% WRECK — kills the matched
  groupStatuses walker loops in same fn). Top `mr r29,r0` r0-detour = named-saved-from-.data
  cap (#107). Second transient loop (mapId==-1 write) already matches (walker+mulli-on-found).
- **expgfx_addremove** (dll_000A_expgfx) 95.84% BANK: entire diff = #67d one-extra-saved-GPR
  cascade (target `_savegpr_22` r22-31=10 saved vs mine `_savegpr_23` r23-31=9). Uniform
  r22<->r23/r29<->r30 renumber. The `extsh r24` saved-reg-reuse of resourceTableIndex is the
  extra live value; typing it `short` (was int, (int)(short)) INERT (asm byte-identical, 95.84).
  or/and operand swap (maskHighWord|bit) INERT/regress (95.82). No lever for the extra saved reg.
- **expgfx_updateActivePools** (dll_000A_expgfx) 97.01%: FOUND clean structural — 2 spurious
  `clrlwi r0,r0,16` before `sth gExpgfxPhaseAngleA/B` (u16 `+=` narrowing; target does
  `add;sth` direct, sth truncates). FIX `*(s16*)&gExpgfxPhaseAngleA = gExpgfxPhaseAngleA + ...`
  REMOVES both clrlwi (asm matches target exactly, verified) BUT fuzzy byte-identical
  97.009514 both ways — objdiff gives zero credit (2 instr below precision floor / net-neutral
  vs neighbor matching). Kept cleaner `+=` baseline (no measurable gain, uglier cast). Bigger
  diffs (fmuls f31 vs f22 FP-const-reg, lfs load-position) = FP coloring/CSE caps.
- **dll_15_func08** (dll_0015_curves) 97.55% BANK: uniform param saved-reg swap curveObj->r30/
  state->r31 (target) vs r31/r30 (mine) — `mr r30,r3;mr r31,r4` transposition across whole fn.
  Param-vs-param = BOUNDARY. The addi r27,r27,12 placement diffs are downstream of same cascade.
- **expgfxGetSlot** (dll_000A_expgfx) 94.49% BANK: pool-slot scan loop bodies STRUCTURALLY
  IDENTICAL (addi r30,+2 walker + addi counter +1 + lwz/cmplw/lha/cmpw/lbz/extsb/cmpwi 25);
  pure #108 induction reg transposition (r9<->r10, r11<->r12, r30<->r10) + early named-base
  staging detour (addi r30,r9,0 target vs mr r30,r10 mine, #107). No source lever.

NOTE flat-DLL scope now thin: nearly all sub-98% >700B flat dll_00xx-01xx fns are coloring
caps (#67d extra-saved-GPR, #108 induction transpose, param saved-reg swap, .data-base
staging detour). dll_0014_unk + dll_000B_dll0b actively owned by other agents (skipped).

## Jul4 flat dll_02xx (0x200-0x2FF) triage — deep-dive #58 (0 wins, scope confirmed thin)
Ranked ALL sub-100 flat dll_02xx fns >200B via private proto report + ndiff --classify.
The ENTIRE top of scope is coloring/scheduling/reloc-bound — no source-controllable
structural levers remain (the prior sessions + parallel agents picked them over).
- **hightop_stateHandler04** (dll_0272) 99.63% BANK: sole diff = ONE `fmr f1,f2` on the
  SECOND `(dy>=const?dy:-dy)` abs (line 926). Target reuses dy's reg f2 in-place (dy dead
  after) → `fneg f2,f2`; current allocates fresh f1 → needs positive-branch copy. Pure #82
  FP-coloring liveness outcome. TRIED: drop `*(f32*)&lbl` cast on line 926 to match line 922
  plain form (REGRESSED 99.63->worse, 14 regions); add cast to line 922 too (REGRESSED, 14
  regions); `if(dy<const)dy=-dy;` in-place mutation (REGRESSED 12 regions — changes the
  >=/< compare sense vs target's fcmpo+cror ternary shape). Baseline (asymmetric cast) is
  BEST. No lever.
- **dbstealerworm_stateHandlerA0B** 98.70% / **A0C** 99.05% (dll_0242) BANK: mr-copy =
  ObjGroup_GetObjects result copied to saved reg placed at LOOP-ENTRY (target, after found=0
  li + guard branch) vs BEFORE-branch (current). Pointer-walk `objs=call; found=0; for(*objs;
  objs++)` induction setup — scheduler placement, resistant. Rest = reg-perm + frame-offset
  (#67 8B conversion-temp slot shift 72(r1) vs 64(r1)).
- **gameTextBoxFn_80134d40** (dll_02C0_front) 98.19%: 31 reg-perm + 20 pool-reloc + 1
  fcmpo-swap. Pure coloring/neutral. Skip.
- **vortex_init/render, timer_update, cmbsrc_*, kytesmum, waterflowwe, dbegg_update,
  dbstealerworm_A07/A08, hightop_02, gflevelcon fn_8023A3E4, drakorhoverpad** — all
  COLORING-ONLY (reg-perm/pool-reloc/lone fcmpo-swap), no non-neutral structural regions.
- **bossdrakor_update** (dll_024D) 97.48% has the ONLY [ext-insert] in scope BUT is actively
  owned by the boss-cluster agent (committed 27min prior, s16-clamp int-accumulator work) —
  SKIPPED per one-owner rule.
- **andross_update** (dll_02BC) 99.52% (17624B): 2 li-const = zero-init placement tangled
  with obj/state(184(r31)) coloring; negligible ceiling in a 17KB fn. Bank.
CONCLUSION: flat dll_02xx structural frontier is exhausted for this session. Residuals are
FP/GPR coloring (#82/#108), call-result-copy scheduling, and frame-slot (#67) caps. No commits.

## dd59 burst (WM/WC/VF/NW/MMP/LGT/IM/CF/CC/ARW/DF clusters) — Jul04
Clusters are ~fully matched: only 9 funcs sub-99.9% (>256B) across all 11 subdirs.
ALL 9 are reg-perm / const-fold / r0-detour caps; NO ext-clamp (s16/s8) signature
anywhere in the clusters (scanned all sub-99.9 with ndiff --classify for ext-insert/
extsh/narrow — zero hits). Nothing to commit; working tree left clean.

- wmwallcrawler_update 98.50% (3860B): pure #130 obj->r28 / state(184)->r30 coloring
  SWAP cascade (target mr r28,r3 then lwz r30,184; mine reversed). ~20 reg-perm regions,
  one coupled lwz r3,84 reorder. BANKED — the documented resistant obj/state pattern.
- wcpressures_update 98.95% (840B): reg-perm dominated + one #110 shared-zero region:
  target `li r5,0; mr r6,r5(j); mr r3,r5(found)` (ONE zero copied to j+found) vs mine
  `li r8,0; li r6,0; mr r3,r6` (two materializations). TRIED `j = found = 0;` chained
  init — INERT (copy-prop refolds to two li). BANKED.
- dfsh_shrine_update 99.32% (1508B): SINGLE structural miss = named-.data-symbol ptr
  r0-detour. Target `lis r3; addi r31,r3,0` (rewardtable addr DIRECT into saved r31);
  mine `lis r3; addi r0,r3,0; mr r31,r0` (+1 mr). Everything else byte-identical
  (r28=obj,r30=state,r29=player). TRIED `base=&gDfShShrineRewardTable[0]` — INERT.
  Confirms MEMORY: r0-detour intrinsic to named saved-reg ptr from .data symbol;
  base used 3x deep across calls so can't drop the hoisted local. BANKED 1-instr cap.
- Remaining (arwbombcoll 99.04, wcpushblock 99.61, controllight 99.67, nwtricky 99.70,
  dfropenode 99.75, wcfloortile/updateBarrelRoll 98.69): all reg-perm + fcmpo-swap +
  pool-reloc caps, no structural lever. SKIPPED.

- **render.c fn_80007F78** 94.03% BANK (#67d one-extra-saved-GPR cap): 64-bit
  bit-unpack sample interpolator. ENTIRE 59-region reg-perm cascade roots in the
  `frac.v = (int)t` s64 union: target SPILLS frac's high (sign-extend) word to stack
  slot 40 (`srawi r0,r28,31; stw r0,40(r1)`) and RELOADS it inside each 64-bit multiply
  (`lwz r0,40(r1); mullw r0,r4,r0`), keeping only frac-LOW in a saved reg. Current keeps
  BOTH frac words live in regs (frac-low r29, frac-high r28) = one extra saved GPR ->
  `_savegpr_14` (18 saved r14-r31) vs target `_savegpr_15` (17 saved r15-r31). That single
  extra kept-live value drives the whole 59x renumber + the curB-load-order seed
  (target lhz curB->r22 FIRST vs current lhz->scratch r3 LAST). TRIED+FAILED: union->plain
  `s64 frac` (94.027->94.000, reorders saved homes worse), `s64* fp=&frac.v; tmp*=*fp`
  memory-force (91.81 WRECK, forces BOTH words to memory every iter = extra loads),
  frac decl-reorder (inert). No source lever forces the allocator to spill-vs-keep the
  high word (matches MEMORY #67d/#108 findings). render.c otherwise thin: only 3 imperfect
  fns (modelRenderFn_80006744 95.98, fn_80006B1C 98.57 both smaller coloring caps).

## BANKED Jul04 (freshly-cooled dd64) — object.c residuals all CAPS (0 wins/2 tries)
Freshly-cooled window (30-60min): object.c (touched 30min ago, byte-neutral bufferFlags
typing), cloudaction renderClouds + lightmap getVisibleObjects (both 100% now). object.c
4 sub-100 fns, ALL confirmed caps:
  - fn_8002B758 98.46% (260B): SINGLE extra dead `blr` at tail. Target's last block is the
    memmove loop-rotation prep ending in unconditional `b 11c4` (NO trailing blr, 72 instr);
    my build emits identical block + dead `blr` at f58 (73 instr). Restructure `if(i==count)
    return;`->nested `if(i!=count){...}` REGRESSED (introduced beqlr + inlined the cold
    loop-prep island, 70 instr, 2 regions). Baseline layout already optimal for source shape.
    Dead-blr-after-unconditional-branch = MWCC block-placement cap, no source lever.
  - objFreeObjDef 96.87%: pure r30/r31 PARAM-swap (#108/#130 — obj param r3->r30 target vs
    r31 mine, r4->r31 vs r30). ~20 reg-perm regions + 1 downstream li-const. Cap.
  - loadCharacter 98.87%: r28/r29 reg-perm cascade + `lbl_803DE8B0` vs `@1543` = the
    u32->double bias const #70 named-vs-anon NEUTRAL (per MEMORY, compiler-emitted, not
    injectable). Cap.
  - Obj_UpdateModelBlendStates 99.07%: walker/counter #108 transposition (li r26,0/mr r30,r25
    vs swapped) + 1 coupled mr-copy. Cap.
No object.o change committed; all experiments Edit-reverted, git diff clean, fuzzy% at
baseline (twice-confirmed via dd64 proto reports). Freshly-cooled surface exhausted of
structural levers this pass.

## dd63 pass Jul04 — cooled-residual structural sweep (0 wins, all caps)
Swept ~18 cooled fns (1-4h post-team-touch) via proto report + ndiff --classify.
EVERY cooled non-100 fn examined is reg-perm/coloring-capped — the team cooled them
BECAUSE they hit the coloring wall after taking the structural gains. Confirmed caps:
  - shader.doPendingMapLoads 93.08%: ext-delete (extsb on cn2++ store @3200) is a
    coloring byproduct (r20 vs r22); store/inc split `= cn2; cn2++;` REGRESSED 93.08->92.70.
  - gametext.textMeasureFn_80016c9c 94.90%: ext-insert on `(f9+f8)+fC` (MeasGlyph s8/s8/u8
    advance @484). Target hoists the f9 load early (r5) = scheduling hoist, not reassoc.
    fC+(f8+f9) and fC+(f9+f8) both INERT (94.90 exact). Cap.
  - lightmap.updateVisibleGeometry 97.60%: li-const `li r0,0;mulli r0,r0,20;stfsx` on
    gViewFrustumPlanes[0].normalX (dead const-0 index, plane-0 @177). Baseline mixes
    literal [0] on normalX + [n=0] on rest = OPTIMAL. Uniform literal [0] all four
    REGRESSED 97.60->94.82; uniform [n=0] all four REGRESSED 97.60->97.33. The dead
    mulli is strength-reduction tied to n's shared induction across planes 0-4. Cap.
  - textrender.gameTextRun 95.15%: ext-delete/insert cluster = clrlwi(u8) masks on
    GameTextLoadSlot dirId/sourceId stores (@1732/1735) + switch-case field-load order
    (4/8/12/16) all rooted in the fade-struct base pointer coloring (target r27 vs
    current r29). Coloring-rooted, team already reordered fade-loop 4h ago. Cap.
  - mapLoadBlocksFn_800685cc 98.05%, fn_80136E00 99.10%, fn_80069B1C, trackIntersect,
    ObjAnim_AdvanceCurrentMove, doLotsOfMath, textRenderStr: all pure reg-perm/pool-reloc.
All experiments Edit-reverted; git diff clean; twice-confirmed via dd63 proto reports.

## dd60 session (Opus, main-lib cooled structural sweep) — 3 BANKS, 0 wins
- **tex_dolphin.c mapBlockRender_setupShaderTextures 97.12% (cooled 9h, NOOPT unit)**:
  all 8 regions are the SAME noopt operand-eval-order pattern in `dividend/lbl_803DEBC8`
  PSMTXTrans call args (layer0/layer1 inline + layerN mvec). TARGET loads dividend
  (lfsx/lfs f0) BEFORE divisor (lfs f2 lbl_803DEBC8); CURRENT loads divisor first.
  Divisor is reused (f2) for both divisions per call in BOTH. TRIED+FAILED: mvec-ptr
  temp for layer0 (97.12->96.82, +1 region), f32 n0/n1 dividend value-temps
  (97.12->96.49). Divisor-first is intrinsic noopt codegen; no source lever, no
  pragma (noopt unit). BANK.
- **dll_0017_savegame.c SaveGame_gplaySetObjGroupStatus 96.67% (cooled 6h, NOOPT)**:
  the transient found-search (line 541) + free-slot-search (553) loops both 5x-unrolled
  by MWCC. TARGET holds base pointer FIXED (r4) across 5 entries with immediate
  displacements (0,3,6,9,12), counter i in r3 (also = `found`, extsb r0,r3), base +=15
  per ctr-block. CURRENT strength-reduces to a walking pointer (r3 += 3 per entry) +
  separate counter i in r4. Same 5x-unroll, only addr-mode differs (immediate-offset
  vs pointer-walk) = the documented resistant SR pattern (#112 / fn_802AB1D0 /
  waterfx_spawnRipple). TRIED+INERT: `s->transient[i]` direct index (drop `transient`
  local) — byte-identical .o, no change. NOOPT so no opt_strength_reduction pragma.
  BANK.
- **textrender.c gameTextRun 95.15% (cooled 3h, team-active file)**: independently
  reconfirmed the prior agent's finding — dominant residual is the `cmd`-pointer saved-reg
  cascade (target r27 vs current r29) propagating through ~30 switch-case field-read
  regions, plus counter i (r26 vs r27). TRIED+FAILED: case-3 descending-offset u8 read
  reorder (95.154->95.133, read-offset order matched but within-case reg map reversed),
  cmd decl-move later (95.154->94.689). Coloring-rooted. BANK.
All experiments Edit-reverted; my 3 files git-clean; full `ninja` EXIT=0. NOTE: an
unrelated concurrent edit to src/main/pi_dolphin.c (another owner) is in the working
tree — left untouched per one-owner-per-.c.

## BANKED Jul04 (dd66 restructure) — walkgroupFindExitPointFn_800dc398 (dll_0014_unk) 95.38% CAP
Big fn (4776B). ENTIRE 897/1268-line diff is ONE clean **r30<->r31 within-class
transposition** rooted at the entry: target parks `patchBase = gObjfsaPatches`
DIRECTLY into r30 (`addi r30,r3,0`, no detour); current stages it into r31 via the
`addi r0,r3,0; mr r31,r0` r0-detour (the documented named-saved-reg-pointer-.data-init
detour, MEMORY-confirmed intrinsic). Because patchBase lands in r31 (highest) vs r30,
EVERY downstream reg flips: target keeps the u32->double bias const `0x43300000`
(`lis r31,17200`) live in r31 across the whole float-conversion block (asm 947-1225,
~20 reuse stores to stack 536/544/552) while patchBase=r30; current has patchBase=r31,
bias=r30. Same `_savegpr_21` count (11 saved r21-r31) BOTH — pure numbering, NOT #67d.
Only +1 instr (the `mr r31,r0`). TRIED+FAILED (all twice-confirmed 95.3836 baseline):
patchBase decl moved past arrays w/ late init (inert), `&gObjfsaPatches[0]` addr-of init
(inert), patchBase declared LAST among ptr locals (inert) -> MWCC weights patchBase's
whole-fn live range over the late bias-const range regardless of decl order, always
gives it r31. `#pragma optimization_level 2` scoped (WRECK 20.96%, big -O4 fn). No source
expression reorders which of r30/r31 the allocator gives patchBase vs the CSE'd late
bias const. Matches MEMORY's banked "named saved-reg pointer .data init r0-detour +
r30/r31 within-class swap = confirmed cap, no source lever". Fn already heavily tuned
(opt_propagation off 2263-2591, scheduling on 2717-2731, walking-ptr/decl-init wins by
team 4h ago). BANKED. Also spot-checked dll_0B_func04 (dll_000B, 93.95%): same class
(601/627 lines, param-block saved-reg shift r23-r29 target vs r25-r31 current + another
r0-detour) — #108/#130 param-class cap, no structural seed. No .o change; tree clean.

## dd65 — pi_dolphin.c zlbDecompress 42.17% HARD BANK (foreign-compiler save-strategy)  Jul04
Picked the biggest sub-96 non-team-hot cap: zlbDecompress (2352B, 42.17%), a full
DEFLATE/inflate decoder. pi_dolphin.c otherwise 99%+ across all 80 fns; this is the
lone outlier and cool (file last touched 13:05, fn untouched). Root cause = the target
`.o` compiled zlbDecompress with a DIFFERENT save-strategy than its 19 TU-siblings:
  - Target: `stmw r14,12(r1)` + `lmw r14,12(r1)` (inline multiple-save, frame 84), and
    it SPILLS `final` to 8(r1) (kept in r16 AND memory), and materializes each .bss
    array (lbl_8035F740/F860/8036F860/F880) INDEPENDENTLY via its own lis/addi+RELOC.
  - Current: `bl _savegpr_14`/`_restgpr_14` (helper calls, frame 80), keeps `final`
    purely in r28 (no spill), and HOISTS a shared `...bss.0` base (`lis;addi r7` +
    `addis r6,r7,1`/`addis r4,r7,2`) offsetting each array from it.
PROOF it's foreign: in the TARGET pi_dolphin.o, `stmw` appears in EXACTLY ONE function
(zlbDecompress); all 19 other fns use `_savegpr` helpers. MWCC applies save-strategy
per-COMPILATION-UNIT (a codegen/flag decision, no pragma exposes it) — so there is NO
lever to make ONLY this fn emit stmw while its 19 helper-using siblings stay matched.
The source comment already flags it "foreign-compiler (GCC/SN ProDG family)".
TRIED+FAILED (all reverted, baseline byte-identical after):
  - `optimize_for_size` OFF (removed #pragma at 7980): still `_savegpr` helpers, frame
    80. Dropped ndiff 41->32 regions BUT report.json fuzzy FLAT at 42.17 (prologue+
    addressing dominate the byte-weighted score). Not the stmw lever.
  - `volatile u32 final`: spills final -> ndiff 41->13 regions (body matches target's
    spill shape!) BUT report.json only 42.17->42.27 (prologue/base-hoist still wrong,
    and volatile changes load semantics = not plausible C). Confirms body-divergence is
    the final-spill, but the DOMINANT score residual is the unreachable prologue+.bss.
  - .bss reorder (moved lbl_8035EF48 group before the zlbDecompress arrays / before
    lbl_8035F730 def): MWCC bss layout does NOT follow source-def order (lbl_8035F730
    stayed at bss offset 0 both times). No source lever forces the target's ascending
    bss layout that pushes the arrays past the base-anchor window. Fuzzy FLAT 42.17.
CONCLUSION: irreducible foreign-object cap. The 42% ceiling is set by (1) stmw/lmw vs
`_savegpr`/`_restgpr` (per-TU codegen, breaks 19 siblings if changed), (2) final's
extra 8(r1) spill (allocator-internal), (3) independent-vs-base-hoisted .bss addressing
(bss-layout-internal) — none exposed as a per-function C/pragma lever. NO COMMIT. Build
EXIT=0, working tree clean.

## BANKED dd67 Jul04 — scarab_update (dll_0106) 98.90% #130 3-cycle obj/best/flag (0 wins/6 tries)
Big creature update (3476B). ENTIRE residual = a clean 3-cycle saved-reg transposition
among {obj, best, flag} over regs {r27,r30,r31}; state=r28 and player=r29 IDENTICAL both
builds; instruction SEQUENCES/offsets all match (pure reg-numbering per ndiff --classify).
  TARGET:  r26=const0x7000b, obj->r27, state->r28, player->r29, flag->r30, best->r31
  CURRENT: r26=const,        flag->r27, state->r28, player->r29, best->r30, obj->r31
Root cause = #67d: target parks DEAD `best`(=0 from `best=0;flag=best;`) in the HIGHEST
saved reg r31 and copies it to flag(r30) via `mr r30,r31`; best dies at `flag=best` (141)
and is reused only at a fresh `li r31,0` ~line 440, so r31 holds a dead value across the
Obj_GetPlayerObject() call + the whole msg loop. `list=NULL` shares the same 0 (stw r31,36
= list's address-taken stack home). My build sensibly gives r31 to LIVE obj instead ->
best/flag rotate down. Same allocator "waste-a-high-saved-reg-on-a-dead-0" heuristic as
groundanimator/magicdust/render fn_80007F78 — no C/pragma lever forces it.
TRIED+FAILED (all REGRESS from 98.90, baseline is a tight local optimum — any top-block
web-creation-order change disturbs the matched 160-site body):
  - state deref moved to very top (before best/list): 98.90->98.67
  - decl-reorder best/flag before player/state: 98.90->98.45
  - decl-reorder (opposite, best/flag after): regressed
  - chained `flag = best = 0;`: 98.90->98.73 (hoists flag=best above start/end copies)
  - swap init source `flag=0; best=flag;` (semantically identical, both 0): 98.90->98.73
  - `#pragma opt_propagation off` (fn-scoped, reset after fn): 98.90->98.53
  - `#pragma opt_common_subs off` (fn-scoped, reset): 98.90->97.88
NOT TRIED (judged net-negative, high sibling-regression risk): full `GameObject* go=
(GameObject*)obj` typed-pointer conversion — obj also used in arithmetic (obj+0x80),
(u32)obj, (u8*)obj so a partial `go` splits into TWO webs (worse); a fully-coalescing go
is byte-identical (no gain). The 3-cycle is the #67d dead-value-in-high-saved-reg cap with
no source lever. NO COMMIT, working tree clean, single-.o rebuild EXIT=0, fuzzy 98.90 x2.

## ============ r0/r3-DETOUR ON .data-POINTER-INIT: DEFINITIVELY UNAVOIDABLE (Jul04, compiler-source crack agent) ============
GOAL was to crack the tree-wide #1 residual: target `addi rSAVED,r3,0` (base direct into
saved home) vs current `addi r3,r3,0; mr rSAVED,r3` (base into scratch r3 + copy). Isolated
it EXACTLY on voxmaps_resetLoadedMaps (96.92, gVoxMaps→r24, single-instr miss). VERDICT:
NO SOURCE LEVER EXISTS. It is a coalescing/value-numbering outcome fixed upstream of every
knob clean C can turn. STOP GRINDING THIS CLASS — it is the multi-IV twin of the smallbasket
numbering-decoupled-from-emission ceiling.

### THE MECHANISM (read from recovered ValueNumbering.c + Coloring.c + RegisterInfo disasm):
- Coloring.c Color_Coalesce merges a copy's src/dst webs ONLY if the move descriptor carries
  desc+0x24 bits (0x2=coalesceable, +0x4=dst-mergeable → full 0x6). Set by RegisterInfo
  0x4d0300/0x4d0fc0 for genuine 2-operand copy PCodes. But the ACTUAL mr-kill happens earlier:
- ValueNumbering.c ValueNumber_Block @0x509010 line 80: a copy `dst=src` (flags&0x10) is
  DELETED iff `valTab[cls][dst*3]==valTab[cls2][src*3]` — dst and src carry the SAME value
  number at the copy point. It SURVIVES iff they DIFFER.
- For voxmaps: base address (invariant) lives in r3 with value-number V_base. slotOrigin
  (offset-0 IV) is colored to r24 and is REDEFINED every iteration by the loop-back
  `addi r24,r24,4`. That def KILLs r24's value record (VN kill/gen, line 94) → r24's
  value-number ≠ V_base at the `mr r24,r3` point → the copy is NOT folded → it SURVIVES.
- The target instead materializes the base ADDRESS DIRECTLY into r24 (`addi r24,r3,0` — the
  ADDR16_LO addi's DEST is r24, the IV home) so base and slotOrigin are ONE web from birth;
  no copy is ever emitted; siblings derive `addi r28,r24,92` FROM r24. That dest-register
  choice is made in PCode address-lowering / instruction selection, UPSTREAM of value
  numbering, and is exactly what our GC/2.0 build resolves the other way for identical C.

### EMPIRICAL PROOF (scratchpad probes, real GC/2.0 mwcceppc.exe, -O4,p nopeephole,noschedule):
Reproduced the shape in isolation (struct base at offset 0, 4 parallel `= gVM.field` IVs +
++). ALL of these produce `addi r3,r3,0; mr r24,r3` + siblings-from-r3 (the CAP), NONE
produce target `addi r24,r3,0` + siblings-from-r24:
  - decl-reorder (slotOrigin first / last / interleaved) — INERT
  - explicit single base pointer `VM* b=&gVM; so=b->slotOrigin,...` — INERT
  - deriving ALL siblings from `so` via byte arithmetic `(char*)so+92` — INERT
  - `register` hint — INERT
  - opt flag sweep: nostrength, noschedule-only, nopeephole-only, FULL peephole+schedule ON
    — ALL still emit the mr copy (base→r3, copy→r24). Strength-reduction is NOT the driver.
POSITIVE CONTROL (proves the mechanism): the SINGLE-IV index form `for(i){ b->mapBuffer[i];
b->blockId[i]; ... }` (base NOT loop-mutated, ONE derived IV) emits `addi r28,r3,0` DIRECT
into the saved reg, NO detour — because there the base coalesces cleanly into the lone IV
whose value-number stays == V_base. So the detour is INTRINSIC to the MULTI-parallel-IV
pattern (2+ pointers each seeded from the base + each ++'d): base parks in scratch, one IV
(the offset-0 one) needs a home that is loop-redefined → un-foldable copy.

### WHY salActivateStudio WON but this class can't: salActivate was single-base runtime-INDEX
(`dspStudio[studio].field`, no ++, no parallel IVs) → base coalesced into the one saved reg
directly (positive-control case above). The 36 base-hoist residuals + this whole tree-wide
r0-detour bank are all MULTI-IV or scratch-clobbered; the hoist/index lever does not apply.

### NET FOR THE TREE: the r0/r3-detour on a named .data-pointer parked in a saved reg, when
the function walks MULTIPLE parallel induction pointers off that base (or clobbers the scratch
base reg before the copy), is a value-numbering coalescing ceiling with NO clean-C lever.
Confirmed inert: decl order, base-cast, single-base spelling, sibling-from-base arithmetic,
register kw, and ALL opt flags. Do NOT re-open unless a CIR-shape (IroCSE/address-lowering
dest-selection) handle is found. voxmaps.c left byte-identical/untouched; no other .c touched.

## dd68 session (Opus, unroll/loop-shape restructure) — 1 BANK, 0 wins
- **pi_dolphin.c loadDataFiles 96.824% (cooled 9h, MY file, -O4,p `-opt nopeephole,noschedule`)**:
  CLEAN 2-region cap, entire diff = the empty spin-loop (`int vi=0x50; do{}while(++vi<0x57);`)
  before `printHeapStats(1)`. TARGET emits a pre-tested COUNTED loop keeping the start value
  live: `li r3,80; subfic r0,r3,87; mtctr r0; cmpwi r3,87; bge <skip>; bdnz <self>` (7 empty
  iters via ctr, r3 NEVER mutated, `87-80` left SYMBOLIC not folded). CURRENT `do-while` emits
  the increment form `li r3,80; addi r3,r3,1; cmpwi r3,87; blt`. The target shape is MWCC's
  counted-loop transform on a `for(i=80;i<87;i++){}` that survived DCE — but THIS TU's DCE
  unconditionally DELETES any empty for/while loop (only the do-while's `++vi`-in-condition
  observable keeps a loop alive at all). TRIED+FAILED (all Edit-reverted):
    - `for(vi=0x50;vi<0x57;vi++){}` and `while(vi<0x57){vi++;}` and `!=` variants -> loop fully
      DCE'd, C=101 (drops all 6 instrs), 92.929.
    - `for` + dummy `dummy++` body -> both loops DCE'd, 92.929.
    - `#pragma optimize_for_size on` (worked for mapLoadDataFile sibling) -> 79.165, wrecks the
      whole fn (too broad; changes callsite arg-emission elsewhere).
    - `#pragma opt_dead_assignments off` (+`opt_lifetimes off`) with for-form -> still DCE'd, 92.929.
    - `#pragma opt_unroll_loops off` with for-form -> still DCE'd, 92.929.
    - `#pragma ppc_unroll_speculative off/on` -> INERT (96.824). NOTE: this pragma rejects
      `reset` (illegal #pragma) — pair `off` with `on`, like model.c does.
    - down-counter `int n=0x57-vi; do{}while(--n)` -> counted-ish `li r3,7; addi -1; bne` but
      FOLDS `0x57-0x50=7` (target keeps 80+subfic symbolic); 96.800, 1 region, slightly WORSE.
  ROOT: toolchain DCE-divergence — retail's empty counted loop survived; mine won't survive DCE
  in the counted shape. No source lever preserves an empty for-loop AND yields the pre-tested
  counted `mtctr/bdnz` form. do-while baseline (96.824) is the best surviving form. BANK.
  All experiments Edit-reverted; pi_dolphin.c git-clean; full `ninja all_source` EXIT=0, 0 FAILED.
  NOTE: an unrelated concurrent edit to src/main/render.c (render #67d agent's file) is in the
  working tree — left untouched per one-owner-per-.c.

## ============ DEFINITIVE RESIDUAL CENSUS (2026-07-04, Opus residual-analyst) ============
Full proto-report enumeration (build/tools/objdiff-cli report generate -f proto) + per-region
ndiff --classify over ALL O4p+RT sub-98% fns. Snapshot: 9501 fns total, **543 sub-100%**.

### BY COMPILER FAMILY (543 sub-100 fns)
  442  O4p-main   (MWCC GC/2.0 -O4,p — the matchable body of work)
   73  AUDIO      (1.2.5n — different compiler family, matchable-HARD not foreign)
   18  MSL        (1.2.5n C runtime — foreign runtime, effectively unmatchable)
   10  pi_dolphin (RT loader — mixed; 1 true-foreign stmw fn)
   (DOLPHIN-SDK sub-100 folded into MSL/pi buckets above)

### TRUE-FOREIGN (stmw/lmw prologue — irreducible, EXCLUDE from reachable)
  Only **1** genuine stmw-prologue fn tree-wide: pi_dolphin zlbDecompress 42.17% (banked
  line 1287, foreign save-strategy + .bss-layout cap). MSL/pi/rcp_dolphin do NOT use stmw —
  they compile with `_savegpr`/`_restgpr` like the main lib; their residuals are the SAME
  coloring caps as O4p, just on runtime code (loadDataFiles, initLoadFiles, __kernel_cos,
  powf, etc.). So "foreign-unmatchable" is essentially a 1-fn set, NOT the audio/RT bulk.

### SCORE-BAND HISTOGRAM (sub-100)
  <50:1  80-90:2  90-95:25  95-98:112  98-99:173  99-99.5:119  99.5-100:111

### DOMINANT-CLASS TALLY (96 O4p+RT sub-98% fns, ndiff --classify per region)
  reg-perm (coloring/#108 + coalescing) ......... 88  (91.7%)
  mr-copy (coalescer copy-survival) .............. 1
  li-const (const-materialization coloring) ...... 3
  reloc-only (already byte-matched, #70-neutral) . 3
  true-foreign ................................... 1
  -> The residual is a WALL of register-allocation caps. 92% of sub-98 fns are reg-perm-
     dominant. Secondary coupled minority regions inside those bodies: fcmpo-swap (#82 FP-perm),
     mr-copy, li-const, and a handful of sched-order — NONE standalone-dominant in any cold fn.

### #70 RELOC-NEUTRAL (already effectively matched)
  Sampled O4p >=99%: 7/200 are reloc-only (@NNN vs named lbl_ literal-pool = score-neutral).
  Extrapolated ~15-20 of the 442 O4p sub-100 are already byte-equivalent-modulo-pool-reloc.

### REACHABLE COUNT
  Non-foreign, non-#70-matched sub-100 fns ≈ 442 O4p − ~18 reloc-only = **~424 "reachable"**,
  BUT reachable-in-name-only: EVERY sampled one resolves to a coloring/coalescing cap with NO
  proven source lever. The taxonomy above (this file, 1400+ lines) has already characterized
  and banked each sub-class. The census confirms NO overlooked structural vein remains.

### WHICH CRACK UNLOCKS THE MOST
  #108/coalescing register-allocation (reg-perm) is the #1 residual by a wide margin (~88 of
  96 sub-98 fns; hundreds tree-wide). Its highest-frequency concrete sub-case is the
  **r0/r3-DETOUR on .data-pointer-init** (`addi rSAVED,r3,0` vs `addi r3,r3,0; mr rSAVED,r3`),
  already DEFINITIVELY BANKED as unavoidable (line 1395, mechanism proven from recovered
  ValueNumbering.c/Coloring.c). A general MWCC coalescing/web-creation-order crack would unlock
  the most fns, but every source-level knob (decl-order, base-pointer spelling, register hint,
  opt-flag sweep, byte-arith siblings) is proven INERT against it. This is a compiler-internal
  ceiling, not a source gap.

### OTHER/STRUCTURAL SEARCH — 0 overlooked fns
  Scanned all 96 O4p+RT sub-98 for a DOMINANT genuinely-source-steerable class (cmp-width,
  lha-lhz, branch-over-branch, frame, via-r0). Result: only 5 fns carry ANY such region, and in
  every case it is a SINGLE minority region (1 of 40-75) inside a coloring-dominated body
  (hitDetect_800667ec frame×1, objBboxFn_800640cc via-r0×1, fn_800659A8 via-r0×1,
  mapLoadUnloadObjects branch-over-branch×1 [shader.c team-hot], ObjHits_Update frame×1). NO cold
  fn has a standalone structural cap. The frontier scanners have been exhaustive.

### VERDICT
  The project is at a coloring/coalescing ceiling. The reachable frontier is NOT "find the
  overlooked structural fn" (there are none) — it is the compiler-internal register-allocation
  wall already mechanistically decoded and banked. NO COMMIT this session: the one small
  isolated single-instr candidate (voxmaps_resetLoadedMaps, gVoxMaps r0/r3-detour) IS the
  canonical banked-unavoidable case (line 1395). Census is the completion map; no lever found.
  (Working tree: src/main/tex_dolphin.c shows modified from a concurrent session — NOT this
  agent's edit, left untouched per one-owner-per-.c.)

## SS76 session (2026-07-05) — semantic-recovery + fuzzy sweep

### Batch scan (git log -120)
NO genuinely-new decompiled fns in the last 120 commits — all "Improve"/"Match" refinements,
data-attribution, naming, or the objRenderFn_8003b8f4 6-arg signature propagation. The "Match X"
commits (saveGame_doWrite, crawler_updateB, dll_15_func0A, hagabonMK2_updateB, wmwallcrawler_update,
Checkpoint_func10) are close-outs of already-in-progress units, not fresh fns to attack.

### Overlay opportunity space — EXHAUSTED (cloudprisoncontrol was the one clean case)
Grepped `int/u32 lbl_[HEX]\[N\]` defined arrays + `*(T*)((char*)lbl_...)` raw-cast sites project-wide.
The only clean contiguous-.data-array overlay (the 3eeda8f489 CPTargetEntry/CPDeferredMsg pattern) was
cloudprisoncontrol, already done. Remaining lbl_ derefs are POINTER-to-runtime-struct offset accesses
(newshadows lbl_803DCFBC+0x44, lightmap lbl_803DCEA0+0x19, minimap lbl_803DBBC8[1]+173) — need full
struct defs to be byte-neutral and are conversion-adjacent/risky. dimbossicesmash lbl_ externs are
already typed u8[] buffers passed as args (no casts). No safe byte-neutral overlay win available.

### model.c :: modelLoad_calcSizes 93.53% — ATTEMPTED, BANKED (resistant coloring cap)
Diff = size-accumulation `total = sizes[6]+(sizes[1]+8)+(sizes[3]+(sizes[4]+100))` where TARGET keeps
`total` in r6 throughout + the two branches (morphTarget true/else) use DIFFERENT association:
  - true:  sizes[4]+100; +sizes[3]; +(sizes[1]+8); +sizes[6]  (sizes[6] loaded early into r8, added last)
  - else:  (sizes[4]+100) seeded r6; +(sizes[6]+sizes[1]+8); +sizes[3]  (sizes[6]+sizes[1] grouped)
TRIED: reconstructing each branch's exact grouping/operand-order. ndiff regions dropped 13->11 BUT
FUZZY REGRESSED 93.53->90.73 (region count != score; the restructure introduced more mismatched body
instrs). Operand-swap (sizes[4]+100)+sizes[3] on true branch: 11->12 regions. All reverted to baseline
(93.529 confirmed, model.c byte-clean, no git diff). Root cause = `total` colored r7/r3 not r6 — a
downstream saved-reg cascade the association levers can't reach without regressing. #108-class cap.

### Other cool candidates confirmed resistant (not attempted deep)
- object.c :: objFreeObjDef 96.67% — ENTIRE diff is the obj(r30)/flag(r31) param saved-reg SWAP
  cascade (mine gives obj->r31). Exactly the flat-dll BANKED "obj param -> low saved reg" resistant
  class (opt_level/register/decl-reorder all documented inert). Skipped.
- shader.c :: mapBlockFn_80059354 97.23% (T=209/C=211) — param r28/r29/r30 coloring swap + 2 extra
  mr copies from `li r4,0` staging. Same param-swap root; shader.c also team-touched. Skipped.

### Structural (count-mismatch) leads for a future pass
gameTextRun (textrender T=452/C=451, 1 off), voxmapsFn_80010ff4 (T=598/C=599), render fn_80007F78
(T=589/C=581, 8 off), shader doPendingMapLoads (T=954/C=943, 11 off) — real structural gaps worth a
dedicated look, but in larger/hotter units.

Build: EXIT=0, main.dol links clean. No source drift from this session (model.c reverted).
Note: dll_00EF_pushable.c shows `M` in git status — ANOTHER agent's in-flight work, left untouched.

## dd75 session (Jul5) — 4 fns attacked, all coloring/reassoc wall, NO COMMIT
Re-measured sub-98 O4p vein via private proto report. Targeted the biggest-impact
coloring-capped fns with the array-respell/walker-split + reassoc + pragma kit:
- **newshadows.fn_8006A028 95.75%** (5424B, 197 diff regions): ONE-extra-saved-reg
  cascade — target keeps `nfill`(window>>3) in r31 + `nfill-8` r30 + `row+window` r29;
  mine spills nfill to volatile r12, shifts to r31/r30. Frame(320)+_savegpr_24 IDENTICAL.
  TRIED: `int nfill[1]` array-respell (INERT, remainder still wins r31);
  `#pragma opt_strength_reduction off` (REGRESSED 89.88). #67d resistant.
- **model.modelLoad_calcSizes 93.53%** (612B): `total` accumulation load-order —
  target loads sizes[3] BEFORE sizes[4] then keeps `sizes[4]+100`/`sizes[1]+8` unfused,
  sizes[6] loaded early (r8) added last. TRIED: `total=sizes[3]+(sizes[4]+100)` +
  nested `sizes[6]+((sizes[1]+8)+total)` (REGRESSED 91.95 — MWCC reassociator folds
  +100/+8 into +108, collapses chain); single-nest variant (REGRESSED 90.44). The
  sizes[3]-first load is a SCHEDULER decision, source-parenthesization triggers
  reassociation instead. Baseline 4-statement form is best.
- **dll_000B_dll0b.dll_0B_func04 94.22%** (2432B, 113 regions): param-staging window —
  target stages 7 params r23-r29, slot=r21(low), gPartfxActiveEffects base=r22; mine
  stages params r25-r31, total=r21, slot=r23. Same _savegpr_21/frame112. The low-reg
  contest is priority-COLORING (total accumulates in loop = high freq wins r21 in mine;
  slot's many gPartfxActiveEffects[slot] indexes win r21 in target). TRIED: move
  `total=0` init past the slot call to reorder webs (REGRESSED 93.89). Internal
  priority-coloring, no decl lever flips it.
- allocLotsOfTextures 95.05% (5948B) surveyed: pure within-loop volatile r4/r5-vs-r7/r8
  counter perm + FP f-reg renumber (f1-f6 scramble), frame/savegpr identical. Deferred
  (fully-cascaded, i/j shared across 4 loops).
VERDICT: re-confirms the coloring/reassoc ceiling. array-respell (which cracked
curves.dll_15_func0A's walker-init mr's) does NOT transfer to spill-vs-save or
priority-coloring contests where the init is li/computed, not an mr copy. No commit.

## WALKER-SPLIT SWEEP (2026-07-05, Opus) — 0 wins/6 tested, class boundary mapped

Extracted the team's cap-crack techniques and swept sub-99.5 count-parity DLL fns.
TECHNIQUES catalogued from commits:
  - 86e0b61a30 (curves.dll_15_func0A): walker->T[1] array so element-init copy keeps
    retail `mr` (element->element mr survives, element->scalar folds to li). Contiguous
    array objects number as one block -> aligns saved-reg order.
  - b69ea9fdd3 (wmwallcrawler): `u32 ob=obj;` straddle copy blocks IroPropagate; param
    dies at entry so local web colors correctly + dead-decl drops.
  - df71b9452d (crawler_updateB): (u32)obj vs (int)obj VN-split to unpool conv-temp webs;
    (tbl+i)[k] byte-arg spelling to place shared add at arg-eval position.
  - f990e2d5d1 (saveGame_doWrite): DROP loop-local temp, read p[i[0]] directly so CSE
    creates load-temp at first use (swaps volatile homes).

WHY THE SWEEP FOUND 0 WINS: curves' win profile = ALL walkers are LOCALS in one
contiguous block, the unmatched diff IS the walker element-copy fold, and surrounding
coloring already aligned. None of the remaining candidates fit:
  - expgfx_resetAllPools 95.29: target hoists 5 zeros as `mr rX,r27` copies (shared zero
    live across textureFree call); current folds to `li 0`. Array-respell (zero[4]) and
    chained-init BOTH REGRESS to 93.91 — MWCC folds provable-constant zeros regardless of
    spelling. Resistant VN/CSE class.
  - GameUI_release 97.24: `mr r30,r27` vs `li r30,0` where r27 = loop-counter j's fresh 0
    reused for *tex=NULL store (first loop only, asymmetric). Not source-reachable.
  - waterfx_func05 96.91: triple walker oPool/o32/o64(+=1c/20/40) w/ o64=oPool copy.
    o64=oPool ALREADY tries to share; target `mr r29,r27` vs current `li`. oPool[1]/o64[1]
    -> 96.88 (neutral), w[3] all-array -> 96.26 (REGRESS). Dominant diff is loop-counter
    reg renumber (r25/r26) coupled deeper, NOT the walker copy.
  - dll_80136a40 fn_80137A00 97.60: grid-param(r29) vs row0/row1 walker(+=1280) coloring
    swap. decl-reorder (row-first) -> 96.93, row[2] array -> 96.93. Param won't demote
    below walkers (boundary-class 1, confirmed again).
  - dll_0041 fn_801343CC 97.60: 4-walker loop (dst+60/yoff+42/idp+4/k+1) full saved-reg
    permutation, BUT src/dst PARAMS interleave the walker block (target r28=idp,r27=src,
    r26=dst,r25=yoff,r24=n,r23=k) so no contiguous local block for arrays to capture.
    Swept 5 decl orders (97.06-97.60, none beat baseline) + idp[1] array (neutral). Welded.
  - expgfx_onMapSetup 96.39 / expgfx_addremove 95.84: r0-detour (named-saved-reg ptr init,
    intrinsic per prior banks) + _savegpr_22-vs-23 (current wastes one saved reg). Both
    resistant classes, not walker-copy.

BOUNDARY REFINED: array-respell wins ONLY when (a) walkers are ALL locals in a
contiguous block, (b) the copy-fold IS the dominant diff, (c) no interleaved param
walkers, (d) surrounding coloring pre-aligned. Shared-constant-zero hoists, param-vs-walker
swaps, r0-detours, and savegpr-count deltas do NOT respond. No commits (all reverts clean,
build EXIT=0).

## #130 STRADDLE-COPY TECHNIQUE — extracted from team matches + applied (Jul5 obj/state agent)
### TECHNIQUE EXTRACTED (git show b69ea9fdd3 / df71b9452d / 9364abb518)
The team's three #130 matches (wmwallcrawler_update, crawler_updateB, hagabonMK2_updateB)
each used a BESPOKE multi-lever combo, NOT one transferable lever:
  - wmwallcrawler_update 98.5->100: `u32 ob; ob = obj;` STRADDLE-COPY of the int obj param
    (blocks IroPropagate so param DIES at entry, local web colors r28 like retail) + `st` decl
    hoisted above bestIdx (r30/r29 homes) + hitReactState deref inlined lazily into the
    short-circuit condition + DROP dead walk/list2/hitState decls. FOUR coupled levers.
  - crawler_updateB (df71): `(u32)obj` VN-SPLIT at ONE call (fn_8014C11C) so the (int)obj
    convs stop pooling into an early web that stole obj's r24 home + t10 decl-first
    (r31-descending) + sibling-style (tbl+i)[k] byte-arg spelling + embedded q/i2 assigns.
  - hagabonMK2_updateB (9364): mostly FP/arg-order/semantic (engineLight missing arg, *(f32*)&
    snapshots, compound -=/*= to unfuse fnmsubs). NOT a param-coloring case at all.
PRECONDITION for the straddle to WIN: the param must currently be INLINE-PROPAGATED with an
EXTRA removable copy/pooled-conv web (r0-detour, hoisted obj-copy, or pooled (int)obj conv).
The straddle/VN-split REMOVES that web. If the diff is a UNIFORM whole-web saved-reg SHIFT with
NO extra removable copy, the straddle only ADDS a live-range and REGRESSES.

### APPLIED to banked candidates — ALL REGRESS/INERT (0 wins/6 tries, all Edit-reverted)
Re-measured via private proto report: the ORIGINAL banked list is ALREADY MATCHED by the team's
byte-identical sweeps + other agents (fogcontrol_init, wallanimator_init, fn_80185868,
texscroll2, checkpoint, groundanimator, magicdust_update all now 100% or team-improved & owned).
Tried the technique on the LIVE sub-100 obj/state _update frontier:
  - scarab_update 98.90: uniform obj-web shift obj r31(cur) vs r27(tgt), +4 all uses. `u32 ob`
    straddle REGRESSED to 98.18 (added live-range, pushed web to r30 — still off, worse). No
    dead decls to drop (diff/hits/vsub/fang all live). Pure #108 count-driven coloring shift.
  - pushable_hitDetect 98.06: obj r29(cur)/r23(tgt) + state 184(obj) r31/r27, uniform -6 shift.
    `u32 ob` straddle moved state->r27 (MATCH) but obj->r28 (still !=r23); target uses
    _savegpr_22 (one FEWER low saved reg) — the extra live-range from `ob` flips the savegpr
    boundary. Net 98.06->98.10 (marginal, state fixed, obj not; not twice-confirmable gain).
    `int ob` variant: inert (98.06). Reverted.
  - shield_update 99.48: THE canonical r0-detour (`addi r31,r3,0` tgt vs `addi r0,r3,0;mr r31,r0`
    cur) — 1 extra mr, only real diff (rest #70 reloc). `int* ob=obj` INERT (detour persists);
    `u32 ob=(u32)obj` REGRESSED (two copies now, state r29 vs r30). r0-detour CONFIRMED resistant
    even to the straddle here (param has only a state-deref, no web to re-anchor). Banked-unavoidable
    line 1395 holds for THIS shape.
  - animatedobj_update 99.50: seq(184(obj))/params(placementData) 2-web r30<->r31 SWAP, obj r29
    matches. Both derive from obj; decl-order swap INERT->REGRESSED (14->15 regions). Allocator
    orders by use not decl. Within-class banked.
  - timer_update 99.10: state(184(obj)) r30(tgt)/r31(cur) vs textureId(512-loop counter) swap,
    obj r28 matches. state-first / textureId-last decl reorders BOTH inert/regress (30->30->36).
  - tumbleweed_updateStateMachine 99.33: NOT param-coloring — FP load-sched (lfs f1,36 position +
    fsubs f3 vs f1) + one staging mr r29,r30. FP-perm + mr-copy class, different domain.
VERDICT: the straddle-copy is a REAL lever but only where an extra removable copy-web exists. The
remaining obj/state banked caps are UNIFORM count-driven coloring shifts (obj/state both in
saved regs already, no removable web) — the straddle adds a live-range and regresses. Confirms
the frontier ceiling: these are #108 coloring, not IroPropagate-copy, caps. NO COMMIT (0 gains).


## SESSION Jul05 (render/effect/objprint removable-web sweep) — 0 gains, all banked-resistant
Fuzzy specialist re-measured render/effect/objprint scope for removable-web fits (walker-split,
u32-straddle, VN-split, cache/drop-temp). render.c FULLY matched (no sub-99.5 fns). Candidates
attacked, all pre-filtered and BANKED as unreachable classes:
- objprint_dolphin.objRenderFn_8003edf4 (99.40): UNIFORM +1 whole-web coloring shift (T r26=C r25
  across every reg, one extra saved GPR renumber). SKIP — unreachable per pre-filter.
- objprint_dolphin.renderOpMatrix (99.39): pure r0-detour on NAMED .data-symbol ptr init
  (`u8* tbl = gObjGxPosMtxIdTable`, `addi r23,r3,0` T vs `addi r0,r3,0; mr r23,r0` C). MEMORY-
  confirmed intrinsic VN-coalescing ceiling. SKIP.
- dll_000A_expgfx.expgfxRemove (99.46): 2-web transposition (resBase r30/poolMask-addr r28 SWAPPED
  vs target). TRIED technique#4 named `u32* poolMaskPtr` — REGRESSED (held-address becomes fused
  `lwzx r31,idx` + shifts more regs). #108 within-class, no lever. BANKED.
- objprint.modelCalcVtxGroupMtxs (98.90): named `0.25f`/`1.0f`->lbl_803DEA18/1C (#127) removed two
  @-pool relocs but BYTE-NEUTRAL (98.90->98.90 — relocs were #70-neutral). Dominant diff = saved-reg
  web transposition + downstream FP f0-vs-f28 temp. Reverted (neutral churn). u32->double bias
  lbl_803DEA20 is compiler-emitted, not injectable.
- dll_0018_boneparticleeffect.boneParticleEffect_update (99.26): r0-detour on NAMED .data
  `base = gBoneParticleConfigTable` + separate FP-const (lfs f30/f31) scheduling block. Both banked
  classes. SKIP.
- objprint_dolphin.modelRenderFn_setVtxDescr (98.94): param-vs-counter saved-reg priority transposition
  (target params r24-r29 LOW / next,back counters r30,r31 HIGH; current inverted). `register` on
  next/back INERT. #108, no lever. BANKED.
- expgfx.expgfx_updateSourceFrameFlags (98.15): leaf temp-reg renumber (r9/r10/r11 vs r10/r11/r12) +
  loop-incr position swap. Non-saved temp coloring, #108. BANKED.
VERDICT: render/objprint/effect residuals are dominated by (a) uniform whole-web coloring shifts,
(b) intrinsic r0-detours on named .data-symbol ptr inits, (c) #108 within-class param/counter/web
transpositions. Removable-web levers (walker-split/straddle/named-const) find NO fit here — the
named-const #127 attempt was byte-neutral, the named-ptr #4 attempt regressed. NO COMMIT (0 gains).
Working tree: my scope files (objprint.c, objprint_dolphin.c, dll_000A_expgfx.c) clean at HEAD.

## CSE-first-use / DROP-LOOP-LOCAL-TEMP sweep (Jul05, 0 wins/4 tries — all Edit-reverted)
Applied the maketex saveGame_doWrite lever (`git show f990e2d5d1`: drop `u64 v = p[i[0]]`
loop-local, read `p[i[0]]` directly so CSE materializes the load-temp at first-use, swapping
the volatile home) plus decl-reorder / bound-reshape variants to the live sub-99 frontier.
Re-measured via private proto report (dec.py, unit-doubled dedupe). RESULT: the technique's
natural shape is EXHAUSTED and the remaining caps are coloring, not CSE-placement.
  - maketex.saveGame_prepareAndWrite 98.01: THREE checksum loops with the SAME `u64 v=p[i[0]]`
    cache as doWrite. Dropping the cache (all 3, or loop-3-only, or loops-1+2) REGRESSED to
    97.90 every way. Unlike standalone doWrite (100%), the three loops share x[0]/acc[0]/p
    across a large register-pressured fn; baseline diff is count-parity (568=568) whole-fn
    volatile-accumulator renumber (r5/r6 vs r7/r9 accum, r6 vs r3 base) = #108 coloring, not
    a CSE-home miss. The cache is ALREADY correct here. Reverted to baseline (98.01).
  - gameloop.GameBit_Set 98.55: baseline diff = loop-bound reassociation. Target emits
    `add r4,r0,r5(width+start); addi r4,r4,1; subf r0,r5,r4; ...bge` (exclusive end+1, `<`);
    current `add r4,r5,r0(start+width); ...addi r0,r4,1; subf r0,r5,r0; bgt` (`<=`). Reshaping
    `end=width+start+1; i<end` FIXED the subf/bge (7->5 regions) BUT reassociated the add wrong
    (`addi r3,1; add r5,r4` binds +1 to width) AND left the r4/r5 `start`-load volatile swap
    => net REGRESS 97.91. Dropping the `start` local (double `*(u16*)(...)` read) WRECKED it
    (91.03, killed CSE). Reverted. Residual = add-order + start-load-home coloring, no lever.
  - dll_0136_waveanimator.fn_801923F8 99.32 (above band, tried anyway): baseline = pure integer
    induction-var renumber (src/byte/heightIdx/x + 2 loop counters r5/r6/r8/r9/r10 permutation)
    + companion FP f3/f4 swap. Count-parity 277=277. Outer decl-reorder (x before heightIdx)
    INERT — the inner-nest vars color by USE-position not decl. #108 within-class.
VERDICT: the DROP-LOOP-LOCAL-TEMP CSE-first-use lever only wins on the isolated checksum-
reduction shape (load-once, xor+add reuse) where the value's volatile home is genuinely
mis-CSE'd AND the fn isn't register-pressured enough to force a coloring cascade. That shape
lives ONLY in the maketex save-checksum family (grep confirms NO other `acc=acc+v; x=x^v`
reduction loops project-wide), and it's now fully mined: doWrite 100%, loadMemCardImages 99.33
(committed), prepareAndWrite a confirmed coloring cap. The frontier's other sub-99 loop caps
are whole-web #108 coloring permutations (verified on modelCalcVtxGroupMtxs, BlendSecondary-
VertexStream, waveanimator) where dropping/adding a temp only reshuffles the same web. NO COMMIT.

## WS78 walker-split specialist — main-lib + flat low-ID DLL sweep (Jul5, 0 wins/4 tries, all reverted)
Applied the wb[1]/off[1] walker-array-split lever (ref: curves.dll_15_func0A `git show 86e0b61a30`)
across sub-99 main-lib + dll_00xx/dll_01xx fns. Private proto report + own decoder (scan.py) enumerated
candidates; ndiff --context filtered for T-`mr`-copy-at-walker-init vs current `li`/direct. KEY FINDING:
in this scope EVERY T-mr-vs-C-li region is a **copy-of-a-just-materialized-CONSTANT (usually zero)**
coalescer artifact, which MWCC constant-folding collapses to `li` in our build. Array-respell is INERT
for these — it only preserves copies of a genuinely OPAQUE runtime value. The ref win worked because its
source `loopIdx[0]` was a heavily-reused induction var (indexed into localPointWorld[0][loopIdx[0]+1/+2])
AND was read by TWO siblings (loopIdx[1] AND off[0]) right after its store, pinning it in a reg so both
copies emit mr. None of the scope's copy-of-zero cases have that "one live zero read by multiple siblings"
shape. Tried + reverted (all baseline-restored, no regression):
  - dll_0000_gameui GameUI_release 97.24%: target `mr r30,r27` (NULL-store val seeded from j's zero) vs
    current `li r30,0`. Tried nullVal=(void*)(int)j + array nullv[1]=(void*)j; both fold to `li` AND the
    extra local decl bumped `g` off its r31 home -> cascade. INERT (copy-of-known-zero).
  - dll_0013_waterfx waterfx_func05 96.91%: 3 parallel byte-offset walkers oPool(+0x1c)/o32(+0x20)/
    o64(+0x40); target seeds o64 via `mr r29,r27` from oPool's zero, current `li r29,0`. Tried o64[1]=oPool,
    oPool[1] array + o64=oPool[0]; both fold (oPool==0 compile-known) and DELETE the walker mr / add stray
    li (32 regions vs 30). The offset walkers lack the ref's reuse-pinning. INERT.
  - worldplanet worldplanet_init 98.75%: target `li r27,0(mask); mr r26,r27(i)` vs current 2x li. Tried
    `for(i=mask;...)` chained + iv[1] array counter seeded from mask; mask==0 folds, array added a reg-perm
    (12 regions vs 11). INERT (single-read copy-of-zero).
  - dll_000A_expgfx expgfx_resetAllPools 95.29%: NOT walker-split — it's a named-base-hoist/#108 coloring
    case (target parks gExpgfxRuntimeData in saved r24 via `addi r24,r3,0`, current leaves in r3 + stray
    `mr r22,r3`). Tried decl-reorder (runtime before poolIndex) to swap saved-reg homes: REGRESSED
    95.29->88.71 (region count dropped 130->9 but fuzzy tanked — count-parity != gain confirmed). Reverted.
SPILL-class (T-mr-copy vs C-stw/lwz r1-spill = #67 save-vs-spill, NOT our lever, skipped): shader
doPendingMapLoads 93.09, render fn_80007F78 94.03, expgfx_updateActivePools 97.33, worldplanet_update
97.74, scarab_update 98.90, objhits ObjHits_CheckHitVolumes 99.29, spiritprize SpiritPrize_update 99.38.
CONCLUSION: the walker-array-split lever needs a SOURCE that is either (a) a runtime pointer/param
(`wb[0]=(u8*)collision`) or (b) a live induction var read by multiple siblings — NOT a scalar known-zero.
No such matchable candidate found in the main-lib / flat-low-DLL scope this pass.

## cr77 creature-cluster walker-split/coloring sweep (Jul5, Opus 4.8) — 1 WIN, rest banked

WIN COMMITTED:
- **dll_0250_ktrex.ktrex_update 99.43->99.54** (d5bef9d0b8): the two parallel bit-packing
  loops (`zm[0] |= 1<<zc[0]`) init the shared zc[0] counter / zm[0] accumulator single-element
  arrays. Retail materializes the COUNTER first: `zc[0]=0; zm[0]=zc[0]` (counter=li-origin,
  accumulator=mr-copy). Source had `zm[0]=0; zc[0]=zm[0]` (accumulator-origin). Flipping BOTH
  loops to counter-origin trimmed a redundant init in each (T=C=219) and colored one step closer.
  LEVER GENERALIZED: for a `counter/accumulator` pair init from one zero in a bit-pack loop,
  make the COUNTER the li-origin. Remaining diff = resistant r25-r28 within-class transposition.

BANKED (creature #108/#130/#82 coloring caps — no source lever this pass):
- **drlasercannon_aimAtTarget 97.66**: yaw/clamp coloring (clamp wants saved r27 = maxRate's
  home). `s16 yaw` REGRESSED 97.02, clamp/negClamp decl-swap REGRESSED 97.57. #108/#82 mix.
- **wcpressures_update 98.95**: `s2=184(obj)` base reload r6-vs-r10 + tracking-loop triple-zero
  CSE (`found`/`j`/store-null want one `li r5,0`; MWCC splits differently-typed zeros). i/off
  decl-swap REGRESSED 98.86; nullObj-hoist INERT. Confirmed-resistant obj/state base pattern.
- **DR_CloudRunner_stateHandler05 99.09**: getAngle-loop compare-swap (`*p != move`) INERT/noise;
  rest is dense fcmpo-swap + f2/f3/f4 #82 FP-perm.
- **arwbombcoll_update 99.04**: textbook obj->r29-vs-r31 + arw/state swap (46 regions, ONE swap).
  Team's `(u32)ob=obj` straddle-copy REGRESSED 98.27 (+3 instrs — the copy didn't die here,
  unlike wmwallcrawler). Moving `arw=getArwing()` later REGRESSED 98.30. Resistant.
- **DR_EarthWarrior_stateHandler02 99.47**: all 26 regions = `lbl_803E82E0`-vs-`@131` = the
  u32->double bias const (xoris magic). #70 compiler-emitted NEUTRAL, not injectable. Near-capped.
- **drmusiccont_update 99.48**: 4 `(u8)GameBit_Get` bit-vars (bit0..3) uniform r27-r30 rotation.
  Same _savegpr_27 both sides; pure #108 transposition. bit3-first decl-reorder INERT.
- **sc_totembond_update 99.79**: 1-instr #110 — target `mr r26,r25` (availableCount copies
  orbIndex's zero) vs current `li r26,0`. Source ALREADY chains `availableCount=orbIndex=0`;
  copy-prop refolds to `li`. Split-statement form also folds. Other region = neutral pool-reloc.
- **nw_tricky_update 99.79**: loop-2 (`ip`/`i` walker/counter) r27/r28 swap. `int* ip[1]`
  array-split REGRESSED 99.51 (ids.ids struct-array addressing bloat), incr-order swap
  `ip++,i++` REGRESSED 99.70. Walker-split does NOT transfer to a struct-member-array walker.
- **arwarwing_updateBarrelRoll 98.69**: `mid=hi-0x7fff` chains from hi(r6) vs target's fresh
  `addis r7,tgt,1` re-derivation, coupled to fcmpo-swap + `zero` FP store coloring. `mid=tgt+0x8000`
  REGRESSED 95.79 (collapsed hi too). #66/#82 coupled.
- **controllight_update 99.67**: bit/lightObj r26/r28 swap (4 regions). decl-split INERT.
- **fn_802BB4B4 (dimsnowhorn1) 98.93**: matchFrame(bool r29)/state(184-deref r30) swap, 24
  regions ONE swap. state-first decl-reorder REGRESSED 97.68 (shifts viewSlot 3rd web). Resistant
  obj/state coloring (memory's dominant flat-dll pattern).

KEY GENERALIZATION: the team's `T[1]` walker-split + `(u32)obj` straddle win on SPECIFIC shapes
(runtime-ptr walker read by multiple siblings; obj param with downstream int-conv that the u32
straddle kills). They do NOT transfer to: struct-member-array walkers (ids.ids), scalar bool/state
coloring swaps, or obj params without the int-conv web. The ktrex WIN worked because it was a true
counter/accumulator zero-origin choice in a bit-pack loop (a NEW micro-lever, banked above).

## OBJ-FAMILY + flat dll_02xx removable-web sweep (Opus fuzzy specialist, Jul5)
WIN (committed afe5d4abf3):
- **bossdrakor_update** (dll_024D) 97.48->97.72: shakeX/shakeY were `int` stored into
  `s16* uvec` inside a do-while(i<5) loop -> per-iteration `extsh` before each `sth`.
  Retyped both as `s16` with `(s16)` casts on the `fctiwz` conversions; narrow happens
  ONCE before the loop, loop stores reuse pre-narrowed value (target had `mr r25,r3`
  staging + no in-loop extsh). LEVER: int->s16-array store inside a loop = hoist the
  narrow by typing the source local s16, not the store cast.

BANKED (no source lever, reverted to baseline):
- **vortex_render** (dll_02B3) 98.69: dominant diff = named `lbl_803E73F0/F8` (u32->double
  bias consts, `extern double`) vs current anonymous `@196/@200` pool doubles = #70
  named-vs-anon, UNINJECTABLE (compiler-emitted). Drives the whole f28/f30/f31 coloring
  cascade. Hoisting `radiusScaleDiv` above the particle-div REGRESSED 98.69->98.20.
- **fn_8023A3E4** (dll_02BB gflevelcon) 99.35: target loads `hp[0xAE]` once into r3, reuses
  for `!=0` compare AND `-=1`; current loads r0 for compare + reloads r3. Caching
  `u8 ae=hp[0xAE]` REGRESSED 99.35->98.61 (over-promotes). 1-instr reload, resistant.
- **hightop_stateHandler04** (dll_0272) 99.63: duplicate `fmr f1,f2` from the abs
  `(dy>=0?dy:-dy)` appearing in TWO if-conditions (lines 922/926). BASELINE DELIBERATELY
  spells them differently (`lbl_803E6AA8` vs `*(f32*)&lbl_803E6AA8`) — making them textually
  identical REGRESSED 99.63->99.13; hoisting a named `ady` local REGRESSED 99.63->97.55
  (saved-FP over-promote). Baseline already optimal.
- **kytesmum_animEventCallback** (dll_0266) 98.40: pure #108, 0 insert/delete, obj r27 vs
  r31 + sub r28 vs r27 3-way saved rotation. UNREACHABLE.
- **dbstealerworm_stateHandlerA0B/A0C** (dll_0242) 98.70/99.05: whole-fn saved-reg
  transposition (r24/r27 in A0B, r24/r25/r26 in A0C); the `mr rNN,r3` insert/delete are
  DOWNSTREAM of the transposition. UNREACHABLE (#108 uniform).
- **timer_update** (dll_02B5), **waterflowwe_calcCurrentVector** (dll_02AE): 0 insert/delete,
  pure perm+pool. UNREACHABLE.
- **cmbsrc_init** (dll_02B1), **gameTextBoxFn_80134d40** (dll_02C0): 20/22 and 19+28/52
  regions are pool-reloc (#70 named-vs-anon FP color/RGB tables) + #108. UNINJECTABLE.
SWEEP VERDICT: flat dll_02xx removable-web fits are RARE. Only genuine fit found = the
int->s16-in-loop extsh hoist (bossdrakor). Everything else is #70 pool-reloc, #108
transposition, or an already-baseline-tuned duplicate. Confirms prior agents: most fits
team-cleared; the residual is uninjectable coloring/pooling. (two-letter clusters WC/DR/
ARW/DIM/LGT = other agents' scope, not touched.)

## S16-NARROW-STORE-IN-LOOP sweep #2 (Opus fuzzy specialist, Jul5) — 0 wins, class exhausted
Systematic tree-wide sweep for the bossdrakor lever (int/u32 local stored to s16*/s8*
narrow field INSIDE a loop -> per-iter extsh the target hoists via one pre-loop narrow).
METHOD: scan_bug.py (brace-split fns, detect raw `dest = intLocal;` stores inside loop
regions) x imperfect-fuzzy(<99.5) x function_objdump --diff NET-extsh-excess counting
x ndiff --classify ext-delete tagging. ~44 candidate fns examined.
VERDICT: NO clean injectable candidate remains in scope. Every hit was one of:
  - **int-array destination false-positive** (offsets[20], chanFade[3], sizes[7] in
    model.c/object.c; RouteState.cur is `int` not s16 in engine_shared.h) -> int store
    emits NO extsh, nothing to hoist.
  - **reg-perm-coupled ext-delete** (doPendingMapLoads shader.c 93.09%: 90 reg-perm
    regions, the lone ext-delete is `extsh r18,r12`->`extsh r18,r8` src-reg rename from
    the cellCursor[0/1] `lbl+zb[1]`/`lbl+row` stores, NOT the `layer` store; extsh COUNT
    already matches 12=12. doLotsOfMath track_dolphin 95.15%: NET+3 extsh all `extsb
    r18,r0`->`extsb r29,r0` pure saved-reg renames. gameTextRun textrender 95.15%: 6
    ext-delete all r27<->r29 coupled; `dirId=pending[0x24]` is a SINGLE store per iter +
    the extsh is from `sMapDirectoryNameTable[dirId]` index use, not the narrow store).
  - **already team-worked** (doLotsOfMath had 3 recent commits incl an s8 extsb recovery
    `flag1=(s8)!(flags&1)`; track_dolphin already banked the `counts[tt]++` s16 win;
    objprint objMathFn_8003a380 NET+2 = banked #82 FP-perm).
Only 2 fns tree-wide showed genuine current-extsh-EXCESS (doLotsOfMath, objMathFn) and
both are reg-perm/#82 residuals, not loop-invariant narrow-store hoists. CONFIRMS the
prior sweep verdict: the int->s16-in-loop lever is a rare fit and bossdrakor was the
only genuine instance; the class is now exhausted in obj-family + flat-dll scope.

## BANKED 2026-07-05 (Opus, audio cap-crack sweep — 8 fns, 0 wins, all resistant classes)
Applied team cap-crack catalog (base-hoist/walker/type/VN-split/straddle) to fresh audio
sub-100 fns not in the prior 2 banked audio sessions. Every candidate resolved to a
NON-injectable class under 1.2.5n (no peephole/scheduling/opt/unroll pragmas). Confirmed:
- **voice_manage/voiceInitPriorityTables 92.42**: target folds np=&lbl_803BD150[0x210]
  into `lbzu r5,528(r3)` (update-form, np shares base r3, reused for 2nd read) + parks
  vidListNodes in scratch r12 whole-fn (2 saved regs, frame 32). Current pins np in saved
  r29 + recomputes vidListNodes mid-fn (3 saved, frame 40). TRIED+INERT/REGRESS: inline
  `lbl_803BD150[0x210]` drop-np (92.13, still CSEs +528 into saved r31, no lbzu), remove
  the load-bearing `(VoiceListNode*)(u32)` casts (81.26 REGRESS — casts force the target's
  addressing). lbzu is a scheduling/addressing-mode artifact, unforceable in source.
- **data_tables/dataInsertSDir 97.31**: r0-detour — target `addi r31,r5,0` (dataSmpSDirTable
  direct into saved r31=t) then p=r3 derived FROM r31; current `addi r0,r5,0` (pre-prologue
  delay slot) then `mr r31,r0`+`mr r3,r0` (both t and p from r0, +1 mr). sdir@off0 so p=t->sdir
  == t. TRIED+INERT: t as SDIR_TAB*=dataSmpSDirs macro + t[i] indexing (97.31), split
  `p=t;for(...)` out of for-init (97.31). r0-detour on named saved-reg .data-symbol init
  (MEMORY-confirmed resistant; INERT here too under 1.2.5n).
- **audio.c/Sfx_AllocObjectChannel 98.00**: shared-zero cap — the sndFXStartEx(a,b,c,0) arg
  0 stays live in r6, reused for the 5 ch-> field clears (target uses fresh `li r0,0`) AND
  for the u64 age+1 high-word adde (target uses addic/addze increment idiom, no zero reg).
  TRIED+REGRESS: recompute (age+1) twice dropping `next` temp (94.50 — next is load-bearing).
  Root = ABI arg-zero liveness, not source-controllable.
- **inp_ctrl/inpInit 97.85**: LOOP-UNROLL-FACTOR — the `row=p+i*16; row[0..15]=0xff` clear over
  i<8: target unrolls 1x (stride 64, 8 ctr iters, walker r8 copy, frame 48/2 saved) vs current
  2x (stride 128, 4 iters, r3 in-place, frame 40). TRIED+INERT: `&p[i*16]` vs `p+i*16` (97.85).
  Unroll pragma FORBIDDEN in audio; factor not source-forceable.
- **synth_job_init/synthInitJobTable 98.00** & **aram_data/aramInitStreamBuffers 97.96**: both
  emit ONE extra unreachable trailing `blr` after the loop back-edge (`b 84`/`b 180`). Target's
  addr-calc block (synthJobTable[i] mulli*100) is a hoisted continuation ending in the back-branch
  = last instr; current tail-duplicates the fallthrough return. TRIED+REGRESS: pointer-walker
  `job=synthJobTable;++job` for synthInitJobTable (32.66 — catastrophic recodegen). Tail-block
  layout artifact, not source-controllable.
- **synth_jobs/synthRefreshJobVolumes 99.39**: scratch-reg renumber + `@123`-vs-named
  `lbl_803E77E0` = the u32->double bias const for `volumeScale*volume` int-conv (#70 NEUTRAL,
  compiler-emitted anon pool, non-injectable per prior audio banks).
- Also gap-classified (within-class, not pursued): salCalcVolumeMatrix 90.20 (FP f20-f31 +
  stmw base-reg scheduling perm), StartKeymap 94.08 (frame 128/136 #67 + 210-line renumber),
  hwSetVolume/inpGetAuxA/Sfx_RemoveLoopedObjectSound/Sfx_InitObjectChannels/mcmdStartSample/
  s3dInsertActiveEmitter/voiceAllocate/Sfx_UpdateLoopedObjectSounds (all #108/#66/#82 coloring
  or scheduling, extsb/extsh + cmp counts MATCH both sides = no type-lever fit).
VERDICT: audio scope now confirmed across 3 sessions (this + 2 prior) to be dominated by
coloring(#108)/operand-order(#66)/scheduling/unroll/frame(#67)/tail-layout/#70-bias caps with
NO source lever under the 1.2.5n no-pragma constraint. The base-hoist/walker/type/straddle
levers that win in the main -O4 tree do NOT transfer (salActivateStudio remains the lone audio
base-hoist win; its runtime-macro-indexed .data array shape is not present in remaining fns).

## Race87 pass (Jul5 ~03:57 PDT) — freshest-commit technique scan, 0 fresh fits
Freshest cracks inspected (all within-family variants of KNOWN/mined techniques):
- c17adca09d (9min) bossdrakor_update 97.48->97.72: `s16 shakeX/shakeY` + `(s16)`
  casts on fctiwz results narrows extsh ONCE before do-while(i<5), reused by in-loop
  uvec[0]/uvec[1] sth stores. = s16-narrow family, applied to fctiwz->sth-in-loop.
  SIBLING HUNT: only bossdrakor has the `uvec` dual-sth shake-loop shape. hightop
  hightop_stateHandler02 has `(int)(gHighTopDegToAngle*x)`->`(s16)conv` BUT already
  99.79% (conv lives r28 saved, extsh-at-use already matches, NOT in a loop). No fit.
  arwarwing shakeYaw uses u16/mathSinf, not the sth-loop. NO fresh sibling.
- 0d4f910bc9 (16min) ktrex_update 99.43->99.54: dual counter/accum single-elem-array
  origin swap `zc[0]=0; zm[0]=zc[0]` (counter=li-origin, accum=mr-copy) in 2 bit-pack
  loops. = walker-split/array-origin family (mined). No other file has the dual-origin
  bit-pack counter/accumulator pair. NO fresh sibling.
- 6e0e67af03 (73min) firecrawler crawler_updateC 98.74->99.18: byte-arg spelling
  `((u8*)seq+i)[8]` / `(t8+i)[k]` instead of `*(u8*)((char*)seq+i+8)` places shared
  +i add at arg-eval for CSE. SIBLING HUNT: all Baddie_SetMove callers (newseqobj,
  duster, magicplant, wispbaddie, fall_ladders) use struct-typed `rows[..].anim`/
  `.flags` or const literals — already in the good form, no raw `+i+K` byte spelling
  to convert. NO fresh sibling.
- 73e7c56c4e (73min) front gameTextBoxFn: 3 front-specific recoveries incl. a
  generalizable `cy=global` FP-CSE snapshot lever (pin single lfs across compare+expr,
  let later use re-read global). Broad HUD-draw sibling hunt = low fit, not pursued.
CONCLUSION: freshest cracks are all mined-family variants keyed to their own unique
local shape; no untouched live sibling found. No commit made. Build untouched.


## FIT-SIGNATURE SCANNER + walker-split win (2026-07-05, Opus) -- 1 win (Objfsa +0.89)
Built a tree-wide fit-signature scanner (private proto report -> objdump both objs ->
normalize branch-addrs -> difflib-align -> categorize the DOMINANT diff). Scanner files
in scratchpad/fit82/: dec.py (proto decoder, no fnfz race), scan4.py (categorizer + clean-
small ranker). Categories: MRLI (target `mr` where current `li` = folded copy), ADDRSR
(current `add rX,rY,rZ` per-iter where target strength-reduces to a single-stride pointer),
MRARG (target `mr rArg,rSaved` = param staged into different saved reg), PURERENUM (same
mnemonic stream, only reg numbers differ = pure #108, auto-skipped).

### WIN (committed d38733c3aa): dll_0014_unk walker-split
- **Objfsa_GetPatchGroupIdAtPoint 98.36->99.25**: the plane-scan walker `j = i = 0;` (i
  counter, j=2*i byte-index) folded to two independent `li` because the seed is const 0.
  Retail emits `li r8,0; mr r7,r8` (i is the li-origin, j=i a real `mr`). FIX = the ktrex
  T[1] single-element-array respell: `u8 i[1]; u8 j[1]; i[0]=0; j[0]=i[0];` + `i[0]`/`j[0]`
  everywhere. The array laundering defeats copy-prop -> the `mr` survives. Residual = pure
  r7<->r8 within-class transposition (decl-swap inert).
- **mathFn_800dbff0 99.16->99.18**: same walker inside WALKGROUP_TRY_RETURN macro (3
  expansions). Array respell recovered the `mr` in the first expansion (others already had it).
  Marginal but real + non-regressing.
- KEY LESSON confirming MEMORY: a walker `mr`-seed only survives the array-respell when it
  defeats a copy-prop fold. `i=0; j=i;` split ALONE is INERT (folds identically to `j=i=0;`).
  The single-element-array is the required launder.

### TRIED+FAILED this session (all reverted, banked):
- **shader.c defStartFn_8005972c 98.75 [ADDRSR]**: min-scan unrolled loop, `q=(int*)tbl+j+n2`
  builds `add r5,r4,r3` per-iter; target strength-reduces to `addi r3,r3,32` single pointer +
  keeps a dead `addi r4,r4,7` counter. Decoupling q (`q+=8` in for-incr) FIXED the addressing
  (pointer walk matched) BUT dropped the dead j counter -> `m` accumulator shifted r5->r4 across
  16 sites -> NET REGRESS 98.75->98.48. The strength-reducer won't collapse `j+n2` while n2 is
  both loop-bound and addr-term. SR-shape cap, banked.
- **dll_801c0bf8 fn_801C0BF8 98.63**: loop `vertex+=8` (body) vs `i++` (for-incr); target emits
  vertex+=8 BEFORE i++, current after. `for(;i<6;vertex+=8,i++)` and body-reorder BOTH INERT --
  MWCC schedules the counter (feeds cmpwi) before the pointer regardless of source order. 1-instr
  scheduling cap.
- **sandworm_turnTowardTargetAnim** (dll_014C, [extsh]): re-confirmed the prior session's banked
  coupled 1-instr extsh cap (split recomputes shifted; u16-store swaps extsh->clrlwi). Same verdict.

### SCANNER VERDICT (293 sub-99 fns scanned, clean-small ranked):
The overwhelming majority of MRLI/MRARG/ADDRSR hits are WHOLE-FUNCTION saved-reg RENUMBER
cascades (#108) or scheduling, NOT crackable folded-copy fits -- the scanner's flagged `mr`/`add`
is incidental to a uniform r{N}<->r{N+1} shift. Objfsa was the rare genuinely-isolated fold.
Confirms the prompt's "~7 sweeps -> 1 win" fit-rarity. The MRARG param-staging class (target
`mr r3,r17`-style: param lands in a different saved reg) = the #126/#108 boundary already banked.

### REMAINING SCANNER HITS (ndiff-ranked, [tag]; for next session -- most are #108/sched, verify each):
ndiff=  2 fz= 98.878 ni=  49 [ADDRSR              ] main/dll/DF/dll_0175_dfropenode.c :: dfropenode_func0B
ndiff=  4 fz= 94.390 ni=  41 [ADDRSR              ] main/audio/hw_dspctrl.c :: salActivateVoice
ndiff=  4 fz= 98.321 ni= 134 [ADDRSR              ] main/tex_dolphin.c :: mapBlockRender_drawLightmapIndirectPasses
ndiff=  6 fz= 98.053 ni= 131 [MRARG               ] main/dll/dll_024D_bossdrakor.c :: bossdrakor_updateHeadTracking
ndiff=  7 fz= 97.018 ni=  57 [MRARG               ] main/mm.c :: mmAllocateFromFBMemoryStore
ndiff=  7 fz= 98.958 ni= 120 [ADDRSR              ] main/dll/firecrawler.c :: fn_80157CDC
ndiff=  9 fz= 95.461 ni=  76 [MRARG               ] main/audio/mcmd_exec.c :: mcmdVarCalculation
ndiff=  9 fz= 98.614 ni=  83 [ADDRSR              ] main/maketex.c :: objSeqInitFn_8007feac
ndiff= 11 fz= 98.026 ni=  76 [ADDRSR              ] main/lightmap.c :: drawFn_8005cf8c
ndiff= 11 fz= 98.855 ni= 345 [ADDRSR              ] main/pad.c :: padUpdate
ndiff= 12 fz= 97.880 ni= 158 [MRARG,MRLI          ] main/pi_dolphin.c :: fn_8004B31C
ndiff= 15 fz= 97.566 ni=  76 [ADDRSR,MRARG        ] main/audio/snd3d_calc.c :: s3dInsertActiveEmitter
ndiff= 15 fz= 98.009 ni= 108 [ADDRSR              ] main/audio.c :: Sfx_UpdateLoopedObjectSounds
ndiff= 16 fz= 98.934 ni= 319 [ADDRSR              ] main/dll/dll_0000_gameui.c :: highScoreScreenDraw
ndiff= 17 fz= 97.159 ni= 176 [MRARG               ] main/model.c :: objUpdateHitSpheres
ndiff= 17 fz= 98.436 ni= 179 [ADDRSR              ] main/shader.c :: mapDebugRender
ndiff= 18 fz= 98.087 ni= 183 [ADDRSR              ] main/camera.c :: Camera_UpdateProjection
ndiff= 19 fz= 97.406 ni= 160 [MRARG               ] main/dll/dll_0138_groundanimator.c :: fn_801932C8
ndiff= 20 fz= 97.250 ni= 180 [ADDRSR,MRARG        ] main/objprint_dolphin.c :: objRenderFn_8003d980
ndiff= 20 fz= 97.518 ni= 139 [ADDRSR              ] main/rcp_dolphin.c :: mapInstantiateObjects
ndiff= 20 fz= 98.187 ni=  91 [ADDRSR              ] main/shader.c :: mapInitSetRects
ndiff= 21 fz= 97.403 ni= 196 [ADDRSR              ] main/audio/data_tables.c :: dataInsertMacro
ndiff= 21 fz= 97.500 ni=  98 [ADDRSR              ] main/objprint_dolphin.c :: modelLoadMtxsToGx
ndiff= 22 fz= 98.792 ni= 283 [ADDRSR,MRARG        ] main/track_dolphin.c :: objDrawFn_80061f0c
ndiff= 25 fz= 96.223 ni= 372 [ADDRSR              ] main/audio/inp_midi_set.c :: inpSetMidiCtrl
ndiff= 27 fz= 94.495 ni= 198 [ADDRSR              ] main/dll/dll_000A_expgfx.c :: expgfxGetSlot
ndiff= 29 fz= 90.044 ni=  91 [MRLI                ] main/audio/hw_init.c :: snd_handle_irq
ndiff= 30 fz= 96.272 ni= 338 [MRARG               ] main/track_dolphin.c :: intersectModLineBuild
ndiff= 31 fz= 93.529 ni= 153 [ADDRSR              ] main/model.c :: modelLoad_calcSizes
ndiff= 36 fz= 98.787 ni= 301 [ADDRSR              ] main/voxmaps.c :: fn_800119FC
ndiff= 37 fz= 95.009 ni= 107 [ADDRSR              ] main/audio/hw_init.c :: hwInitSamplePlayback
ndiff= 40 fz= 98.787 ni= 375 [MRARG               ] main/dll/dll_0138_groundanimator.c :: groundanimator_update

NOTE: dfropenode_func0B, salActivateVoice, fn_80157CDC, fn_8004B31C VERIFIED this session
as pure reg-transposition/renumber/scheduling (NOT source-lever fits). The [ADDRSR] tag
over-fires on reg-swaps that keep `add` on both sides -- treat as a weak prior, confirm
the current-side really recomputes an address the target strength-reduces before attacking.


## dd88 session (Opus 4.8) — track_dolphin renderGlows 94.72->94.72 (u8 array WIN, tiny) + banks

### WIN: renderGlows (track_dolphin.c) getAmbientColor u8 amb[3]
Block-scoped `u8 ar,ag,ab;` -> `u8 amb[3]`, call `getAmbientColor(0,&amb[0],&amb[1],&amb[2])`,
read `amb[0..2]` in `_gxSetTevColor2`. Target addresses the three color bytes ASCENDING
contiguous (r1+16/17/18); scalars gave DESCENDING (r1+10/9/8). Array fixes direction AND
lands fogCol's GXSetFog by-value struct-arg copy at r1+8 (matches target). Fuzzy +0.0024
only (3 instrs in a ~400-instr fn) but a real structural match. Committed ef0628599d.
RESIDUAL (banked): fogCol-home@16 vs target@12 is a fogCol<->amb frame-slot SWAP -- MWCC
packs the deep block temp BELOW the early struct local; target reverses. Confirmed-resistant:
optimize_for_size (REGRESSED 94.72->92.34), fogCol decl-reorder to top (94.66), amb->function
scope (inert 94.72). Plus GXWGFifo 20x quad-store FP const-coloring (fneg f2 vs f0, lbl_803DEBCC
zero/lbl_803DEBDC in swapped f-regs = #82) and whole-web reg-perm (base=r30 vs r29). Cap ~94.7.

### BANK: doPendingMapLoads (shader.c) 93.09% — uniform whole-web #108
Frame 2592 + `_savegpr_18` (r18-r31, 14 saved) IDENTICAL both sides; 91/109 diff regions =
reg-perm from base landing r29 (mine) vs r28 (target), uniform renumber of the whole r18-31
web. Inner k8 loop already mtctr/bdnz-matched. eBase/aBase/cBase init-reorder REGRESSED
(93.089->93.079). No source lever -- classic #108. Skip on sight.

### Other candidates surveyed (all reg-perm dominated, skipped):
render.c fn_80007F78 (59rp/70), gametext textMeasureFn (68/81, hot 9h), dll_0B_func04
(113/122, hot 5h), expgfx drawGlow (heavy rp), newshadows (hot 5h). pi_dolphin zlbDecompress
42% is FOREIGN-compiler (line 8013 comment) -- NOT MWCC, skip. audio/snd3d_room skip (audio).

### SESSION Jul05 (creature/mid-id dll multi-sig scan — 0 wins, all fits banked)
Fresh scanrank over FLAT MID-ID DLL (dll_02xx) + creature clusters (DR/DIM/SB/SH/SC/WM/WC/VF/NW/MMP/LGT/IM/CF/CC/ARW/DF). Only **14 sub-99 fns in scope**; every one probed = pure #108 reg-perm / #82 FP-perm / banked obj-state coloring swap. No source lever landed. Report: /tmp/ms90_*.binpb + scratchpad/scanrank.py (sub-99), scanrank2.py (99.0-99.9 tier).

FITS PROBED + BANKED this session (all Edit-reverted, tree clean, build EXIT=0):
- **drlasercannon_aimAtTarget** (DR/dll_0261) 97.66 [s16/extsh]: target double-extsh `extsh r0,r3; extsh r28,r0` on BOTH yaw+pitch (getAngle results); current folds to single `extsh`/`mr`. `s16 yaw` decl AND `(s16)yaw=` cast BOTH fold to one extsh (C 253->251, moved AWAY from T=255 — the double-extsh is the MISSING instrs). The 2nd extsh is a coupled reg-perm on the getAngle-result live-range (transient-in-scratch + saved-copy), no clean lever. `@143`/`lbl_803E68D8` = #70 bias-double, neutral. BANKED #82/#108.
- **kytesmum_animEventCallback** (dll_0266) 98.40 [obj-state swap]: EXACT dominant flat-dll `obj->r27(low) + runtime=184(obj)->r31(high)` vs current `obj->r31, runtime->r28`. runtime genuinely dead until line 287 -> tried late bare init: REGRESSED (broke _savegpr_27 grouping -> individual stw, C 61->62). Confirms memory "deref MUST stay early". BANKED (the 0/13 resistant class).
- **drshackle_updateSwingBlend** (DR/drshackle) 98.42: uniform +1 saved-reg renumber (params want r29/r30, current r30/r31), T==C=... all reg-perm. #108. SKIP.
- **arwarwing_updateBarrelRoll** (WC/dll_0298_wcfloortile) 98.69 [fcmpo-swap]: `fcmpo cr0,f1,f0`(T dir>zero) vs `f0,f1`(C) — zero-const live-range wants f0, direction f1; hoisting `zero=lbl_803E6ECC` out of the `(zero=...)` compare-assign changed load sched but NOT the operand-reg swap. Also `stfs f0 vs f1` @908 follows same coloring. +1 instr = `addis+addi` vs folded `addi` 0x8000 sign-adjust. Coupled #82, BANKED.
- **vortex_render** (dll_02B3) 98.69 [FP const-web]: `radiusScaleDiv` local + gVortexRadiusParamScale/lbl_803E73E8/EC consts — target CSEs into saved f28/f30/f31, current reloads (insert lfs). f30/f31 const assignment swapped vs bias-double. #82 FP-perm + #70 anon-pool. 536-instr, no single lever. BANKED.
- **fn_8023A3E4** (dll_02BB_gflevelcon) 99.35 [VN-reload, CLEANEST]: 2 regions, C has ONE extra `lbz r3,174(r4)` — target CSEs the `hp[0xAE]!=0` compare load (r3) into the `hp[0xAE]-=1` RMW; current loads compare->r0(scratch) + reloads RMW->r3. `u8 hits=hp[0xAE]` temp REGRESSED (u8 arith -> clrlwi masks, C 180->181). `--hp[0xAE]` INERT. Pure 1-instr VN/coloring (compare-load reg != RMW-load reg), BANKED.
- **DIMwooddoor_updateShardAim** (DIM/dimwooddoor) 99.15 [FP-perm + branch]: `distSq` wants saved f31 across sqrtf; current keeps f3(volatile) everywhere -> cascade of fmr-direction + fcmpo f31/f3 swaps. Flipping clamp ternary `(distSq<C)?C:distSq` -> `(distSq>C)?distSq:C` MATCHED the ble/bge branch region (11->10 regions) BUT REGRESSED 99.15->98.67 (distSq forced to f3 globally, worse web). Min/max operand order is load-bearing for the f31 live-range. BANKED #82. REVERTED.

VERDICT: creature/mid-id scope is picked-clean at sub-99 — 14 fns, 0 crackable. The 99.0-99.9 tier (26 fns) top candidates (timer_update 29x reg-perm, fn_802BCA10 21x, dbstealerworm_* all T==C reg-perm, controllight r26/r28 swap) are uniform #108. The ONE genuine structural fit (fn_8023A3E4 VN-reload) resists every u8/decrement spelling. bossdrakor_update/updateHeadTracking = team-hot (skipped).

## SESSION (Jul05, multi-sig scanner #2 — 0 wins, all fits confirmed mined-out)
Ran 4 fresh scanners over MAIN-LIB + flat low-id DLL (90-99.5 band, sz 80-1200):
- **MRLI walker-fold** (equal-len, target `mr` vs current `li`/`mr` at loop seed): only 2 hits,
  both gameui (textureFreeFn_8012fcec 98.82, GameUI_release 97.24). textureFreeFn ALREADY has the
  z[2] array-launder walker; remaining diff is a pure 3-way #108 saved-reg ROTATION {counter r27,
  base r28, zero r29}(T) vs {r28,r29,r27}(C). Decl-reorder (g last) INERT (98.82->98.82). Init-order
  controls, not decl-order. Capped.
- **s16-store extsh-in-loop**: 1 hit = sandworm_turnTowardTargetAnim (dll_014C, creature-agent
  file, already banked 2x as coupled 1-instr extsh cap). Scope exhausted.
- **base-hoist** (current HA-reloads a .data sym target doesn't): 1 hit = gameUiLoadResources
  (dll/tricky.c 96.99). NOT a clean hoist: target addresses lbl_803DD868[] via SDA21 (`li r4,0`+stw,
  1 instr) AND RELOADS each subscript after store (`lwz r3,0(r4)`), current uses HA/LO (2 instr) +
  CSEs the stored value. Both the SDA-addressing and the reload-vs-CSE are driven by lbl_803DD868
  being SDA (small-data) in retail — a link-SECTION property NOT controllable from this .c (target
  itself mixes SDA@160/162 + HA for same sym). 13-region cascade (r25/r28, f29/f31 renumber) hangs
  off it. Capped (SDA-section, not a source lever).
- **saved-GPR COUNT mismatch** (T savegpr != C savegpr — the crackable class): 3 hits, ALL confirmed
  #67/#108 cascades NOT folds:
  * modelCalcVtxGroupMtxs (objprint.c 98.90, T=25 C=27 target saves 2 MORE): matrix-blend
    `ma[k]*w+mb[k]*wi` unroll; real sub-diff is FP-temp `fsubs f0`(scratch,T) vs `fsubs f28`(direct,C)
    for wi=1.0-w, coupled to a 6-way saved-reg (r24-r29) renumber. objprint heavily-tuned already. #82.
  * boxDrawFn_8012975c (gameui 99.02, T=29 C=27): pervasive r24-r29 renumber + #70 named/anon reloc
    (lbl_803E1E78 vs @308, neutral). No lever.
  * snowCloudUpdateFlakes (newclouds 98.41, T=30 C=29): base-ptr r28(T,contiguous w/params) vs
    r31(C) + #70 relocs. #67d extra-live-range, no source lever (per memory).
- **MRARG straddle** re-confirmed mmAllocateFromFBMemoryStore (mm.c 97.02): target `mr r5,r4` stages
  `size` param out of r4 so the gMmStoreArray induction base takes r4; current keeps size in r4,
  base in r5 (r4<->r5 swap + missing mr, else byte-identical). TRIED: `int sz=size` copy (copy-prop
  FOLDS, inert), MmStore** pointer-walk (REGRESSED — adds r0-detour `addi r0,r5,0;mr r7,r0` + extra
  saved reg). Confirmed-resistant #126 param-stage boundary. Reverted.

VERDICT: This scope's crackable MRLI/MRARG/s16/base-hoist folds are MINED OUT. Every sub-99 hit the
4 scanners surface is a #108 uniform saved-reg renumber, a #67 saved-COUNT cascade, a #82 FP-perm,
or an SDA/section property with no source lever. Objfsa (last session) was the last isolated fold.
0 source-lever wins this session; tree left clean (all experiments Edit-reverted, mm.o+gameui.o
rebuild clean to baseline).

## CONTIGUOUS-SCALAR->ARRAY lever sweep (Jul05, this session)
Swept the renderGlows array-recovery lever (u8 ar,ag,ab -> u8 amb[3] forcing ascending-contiguous
slot assignment) tree-wide. Grepped all local same-type scalar groups passed by-address to one call
(`&a,&b,&c` / `&a,&b`, lowercase locals only, excluded lbl_/g-globals/_funcs). Candidate live fns
(fuzzy<100) and their ACTUAL divergence class:
  - track/intersect.c doDistortionFilter 98.48%: proj5..proj0 (`&proj5..&proj0`) ALREADY
    ascending-contiguous r1+56..76 in BOTH target+current (byte-identical addressing). Real diff =
    `mr r9,r3` pos param-stage + GXColor c0-c3 byte-store REORDER + a +4 frame shift in the indMtx/
    TevSwap int-store block (NOT a scalar-by-addr group). INERT for this lever.
  - main/dll/tricky.c fearTestMeterDraw 98.89%: sc0-3 (`&sc0..&sc3`) slots MATCH. Diff = RELOC
    lbl_803E1E78 vs @294 (#70) + one lbz gFearTestMeterMarkerHalfWidth sched reorder. INERT.
  - main/textrender.c textRenderStr 98.34%: scisX/Y/W/H slots match. Diff = broad r20<->r21 renumber
    cascade + FP const/reg perm (#82) + RELOC naming (#70). INERT.
  - main/newshadows.c renderShadows 97.54%: blkArr/blkCount at r1+84/+64 (20 apart, NOT adjacent).
    Diff = f24/f31 + r19/r25 + r20/r21 + r28/r26 saved-reg coloring cascade (#108). INERT.
  - main/shader.c mapLoadUnloadObjects 95.57%: ObjList_GetObjects(&i,&n) = known #108/#126 idx/count
    saved-reg pattern (banked family). INERT.
  - shaderFuzzFn_8003cc1c 99.89% (sx,sy contiguous already), doDistortionFilter proj already match.
ALREADY-100% (MWCC decl-order-to-slot already ascending-matches target EVEN WHEN decl order is
REVERSED vs arg order): cloudaction renderClouds (clipX/Y/W/H + savedClip), intersect doBlurFilter
(pz,px,py,pw), newshadows updateFrameState (nearDepth/farDepth reversed), renderQueuedShadowCasters
(tmpOutB/tmpOutA reversed), pi_dolphin logGpuHang (GXReadXfRasMetric 4-int reversed), objprint
modelRenderCb_8003c268 (a174/b178/stk380), objprint_dolphin objRenderFuzzFn (shadowTable/Stride/Param
mixed-type), tex_dolphin drawDimmedAabbLights, objprint shaderFuzzFn (sx,sy).
VERDICT: array-recovery lever is MINED OUT in this tree. renderGlows was the rare case where slot-order
WAS the sole divergence; every other clean same-type-scalar-by-address group is either already
ascending-contiguous-matched by MWCC (the decl-order->slot mapping happens to agree with target arg
addressing, including when C decl order is reversed), or the fn's residual is a DIFFERENT class
(#70 RELOC / #108 saved-reg coloring / #82 FP-perm / byte-store sched). 0 new wins. Tree left clean
(no edits made — all candidates confirmed inert by objdump BEFORE any source change).

## dd93 session — shader.doPendingMapLoads (93.08->93.37, committed 2017db65cc)
WIN: split `lbl_803DCDD0 = (gx + lbl_803DCDD0) - 7` into two statements
(`lbl = gx+lbl; lbl = lbl-7`) for both X/Z recenter. Fused form reassociates
to subtract-then-add (addi r0,r3,-7; add); split forces add-then-subtract
(add r3,r21,r0; addi r5,r3,-7) matching target #66 operand order. +0.29.
INERT: reordering eBase/aBase/cBase decl+init to match target addi order
(16864,16884,16844) — changed addi ORDER correctly but score-flat (reverted).
BANKED residual (large, resistant): the layer-loop uses SPLIT walkers — target
keeps BOTH a base-copy (r24/r30/r29 saved, =bp2/ap2/cp2 walkers +4/layer) AND a
staged working copy (r5/r6/r7 via mr, also +4). My source collapses base+walker
into one pointer set = #126 obj-split/param-stage family, no source lever. Also
the gShaderCurMapEventId==-1 path has a reverse rom-list cleanup loop at 0x418C
(3110-31c0: defStartFn/mm_free, addi r24,-8; addi r26,-1; bge) that my source
does NOT model — genuine missing-loop structural gap (candidate for future
structural recovery, not attempted this session). Rest = uniform #108 reg-perm.

## Free large-fn frontier triage (2026-07-05, Opus dd91) — 0 wins, all banked #108/#70
Ranked all sub-97% >900B fns via private proto report. Active agents held dll_0014_unk,
bossdrakor, track_dolphin, animobjd2 (live uncommitted change) — skipped per one-owner.
Examined the cold free candidates; every one is a within-class register-coloring cap:
- **lightmap renderSceneGeometry 96.67% (1260B)** — PICKED, deep-dive, BANKED. Diff = 4x
  identical box-fill loops (`for y: p=map+(y+7)*16+box[0]; for x0=box[0]..box[1]: p[7]=1`)
  each a pure reg transposition: target value`1`->r5, box[0]->r8, box[1]->r7, ptr->r6;
  current value`1`->r6, box[1]->r5(LOW), box[0]->r7, ptr->r8. Root: MWCC trip-count
  `n=box[1]+1-box[0]` evaluates box[1] FIRST -> binds it to a low reg; target keeps the
  loop-carried value/ptr in low regs instead. TRIED+FAILED (all inert, box[1] still loads
  first, still `li r6,1`): cache `int lo=box0[0]` + use lo in ptr & init (folds); shared
  `u8 one=1` fn-level named var used in all 4 `p[7]=one` (copy-props back to per-loop li r6,1);
  `#pragma scheduling off` (load order is a COLORING decision not scheduling — inert).
  Plus 2x `gLightmapU32ToDoubleBias` reloc = target NAMED sda21 sym vs current `@132`
  anonymous pool const — SAME instr form (`lfd f,@sda21`), pure #70 neutral (the int->double
  bias 0x4330000080000000 is compiler-auto-generated per-conversion; the named global lives
  in auto_11 sdata2, referenced by-name only from hand-asm units like tex_dolphin.s — not
  injectable from C). Plus one `li r24,0` (col/ii init) scheduled a few instrs early, coupled
  to the (f32)row conversion sched. NO source lever.
- **render fn_80007F78 94.03% (2212B)** BANKED: 64-bit bit-unpacker (addc/adde/subfc/subfe
  pairs, `*q/=2` shift-emulation loops). Whole-fn renumber from ONE extra saved GPR
  (target `_savegpr_15`/`_restgpr_15` vs current `_restgpr_14`) + target SPILLS the frac.v
  sign-ext hi word to stack (`srawi;stw 40(r1)` then `mullw r0,r4,r0` reload) where current
  keeps it in r28. #67d spill-vs-keep + #108 cascade.
- **newshadows allocLotsOfTextures 95.05% (5948B)** BANKED: 153 reg-perm regions, T=1698
  C=1699 (~equal count) — huge whole-fn coloring cap + Yachuff/Vdchuff FP-const CSE reloc
  ordering (#70). render modelRenderFn 95.98% = 28/30 reg-perm T=C=256 pure #108.
- **expgfx drawGlow 95.03% / expgfx_addremove 95.84%** BANKED: 88/131 & 57/85 reg-perm;
  non-regperm regions are all single-instr mr/li reg shadows + `gExpgfxU16ToDoubleBias`
  #70 neutral reloc + FP-conversion coloring. `li -1 x4; li 0` cluster = pure r20-16(T) vs
  r23-27(C) renumber.
VERDICT: the structural veins in the cold large-fn files (render/newshadows/lightmap/expgfx)
were harvested by prior sessions; the sub-97% residual there is now uniformly #108 within-web
transposition + #70 neutral bias-const relocs. Confirmed resistant by direct experiment on
lightmap box loops (3 levers inert). No injectable win this pass. lightmap.c left byte-clean.

## Jul5 near-match (97-99.5 band) triage — model/camera/mm/sky/newclouds — 0 wins, all resistant caps
Swept 351 fns in 97.0-99.5. Picked cold units (mm 2d, camera 2d, model 14h, sky/newclouds 15h).
Every tractable low-region fn resolved to a CONFIRMED-RESISTANT class. Experiments Edit-reverted,
all owned .o rebuilt to byte-clean baseline. Files touched+reverted: model.c, camera.c, mm.c.
- **model.c ObjModel_Load** 99.20% (1 region): target `mr r28,r30` (off=i copy) vs mine
  `li r28,0` (const-remat). #110 const-copy-fold. `#pragma opt_propagation off/reset` INERT
  (fold is in another pass). Source already `i=0; off=i;`. Cap.
- **model.c modelInitBoneMtxs2** 97.70% (1 non-regperm): the inlined modelGetBoneMtx return
  `((int*)m)[(*(u16*)(m+0x18)&1)+3]` — target `add base,m,idx*4; lwz 12(base)` (keeps +3 as
  disp) vs mine `lwzx` strength-reduced. But SIBLING caller modelInitBoneMtxs's TARGET itself
  uses lwzx (same as mine) — the +3-as-disp is caller-context-specific in a shared static helper,
  can't spell per-caller. #112 context-dependent fold. Cap.
- **camera.c Camera_UpdateProjection** 98.09%: extra `clrlwi` from `resolution & 0xffff` dup.
  Fn is deliberately wrapped `#pragma opt_common_subs off` (prior tuning). Flipping to `on`
  REGRESSED 98.09->93.83 (confirmed the pragma-off is the lesser evil). Rest reg-perm. Cap.
- **mm.c mmAllocateFromFBMemoryStore** 98.x (1 seed region): target `mr r5,r4` parks `size`
  param in r5, loop base in r4; whole diff is the r4<->r5 cascade from that. Pointer-walk
  `void** store=gMmStoreArray` REGRESSED 98->79.9 (broke indexed addressing). #110 param-stage
  copy (copy-prop folds any injected `int sz=size`). Cap.
- **mm.c mmFreeDeferred** 98.x: PURE #108 r3<->r4 renumber, T=C=74 byte-identical. Cap.
- **mm.c mmFreeTick** ~98%: unroll r3/r5 addressing swap + target keeps separate `addi r3,r3,7`
  induction mine drops (T=229 C=231). #108+strength-reduction. Cap.
- **pad.c initControllers** 98.x: `base=(PadStateBlock*)gPadStateBlock` -> target `addi r31,r3,0`
  direct vs mine `addi r0,r3,0; mr r31,r0` r0-detour. Confirmed #107 intrinsic (memory-banked
  for named saved-reg init from .data symbol). Cap.
- **sky.c fn_8008C9F4** 99.38%: `li r0,0` vs `mr r0,r6` (#110 z[0]=0 const-share, 1 instr) + 3x
  `RELOC @546` vs named `lbl_803DF128` = the 0x43300000 u32->double bias const, #70 NEUTRAL
  (mine already CSEs all 3 to one @546). At cap. Cap.
- **model.c ObjModel_BlendPrimary/Secondary, modelAnimUpdateChannels, newclouds snowCloudUpdateFlakes**:
  pure #108 (regperm/regperm counts 20/20, 32/32, all-regperm, 17/21 w/ r28<->r31 web swap). Cap.
VERDICT: this band slice (cold model/camera/mm/sky clusters) is harvested; residual is uniformly
#108 coloring / #110 const-remat / #70 neutral reloc / #107 r0-detour / #112 SR. No source lever.

## dd96 deep-dive session (Opus, 07-05) — model.c banked, no wins
- **modelLoad_calcSizes (main/model.c) 93.53% BANKED**: whole-fn structure matches;
  residual = MWCC constant-sinking reassociation in the `total` accumulation +
  joint-block. Target keeps `(sizes[1]+8)+total` and `(x+0x1c)+total` fused (const
  before +total); MWCC always sinks: `(A+K)+total -> (A+total)+K`. TRIED+FAILED:
  single-expr fold `sizes[3]+(sizes[4]+100)` (REGRESSED 90.44 — drops sizes[4] reload),
  full tree `sizes[6]+((sizes[1]+8)+(sizes[3]+(sizes[4]+100)))` (91.95), `int hitPlus8`
  temp (INERT 93.53 folds back), joint-block `jc`/`jointBytes` temps (INERT 93.53).
  Two-statement baseline `total=sizes[4]+100; total=sizes[3]+total; total=(sizes[1]+8)+total;`
  is best. Pure canonicalizer cap, no source lever.
- SCAN: 88-94% non-audio band nearly exhausted. Structural big-gap fns (shader
  doPendingMapLoads 93.37, track_dolphin, dll_0014) all TEAM-HOT. Remaining accessible
  candidates all reg-alloc caps: render fn_80007F78 94.03% (#67d `_savegpr_15` vs
  `_savegpr_14` extra-saved-reg + spill cascade, 76 regions all reg-perm — bank),
  expgfxGetSlot 94.49% (whole-web #108 li r10/r9 top-cascade, 46 regions reg-perm).
  No source lever found; 0 wins this pass.

## DD94 pass Jul05 (DLL structural deep-dive, 3 targets, 0 wins — all banked #108)
Ranked sub-97% >1KB DLL fns via private proto report. Top fresh (non-team-hot) DLL
targets all resolved to coupled whole-web reg-perm caps where the identifiable
structural seed's source-fix lands the WRONG coloring, costing more than it saves:

- **animobjd2/fn_8013E0D0 96.92%**: obj/st param base r31<->r29 whole-web swap (#108).
  Decl-reorder t-before-gobj REGRESSED (96.92->96.70; allocator re-colors partially).
  Two real structural seeds coupled: (1) extra `srawi r0,r3,31` at stateFlags store
  = the `s32*` cast + 64-bit `LL` flag mask in TRICKY_RETARGET (line 128) promoting
  s32->i64 for the AND; fixing via `u32*` OR dropping `LL` BOTH regress (96.92->96.35/
  96.48, re-colors the whole flag web). (2) `0xFF`->`-1` at TRICKY_RESET_TAIL offset
  0xd (unkD is s8) matches target `li r0,-1` but is byte-NEUTRAL (96.925). (3) `stb r5,10`
  small-const-reuse = #108 GVN. BANK.
- **dll_0013_waterfx/waterfx_func05 96.91%**: ripple/splash/wake loops. Ripple init
  `mr r29,r27` (o64=oPool copy) vs mine `li r29,0` (all-zero copy-prop FOLD). Wake loop
  target uses INDUCTION accumulators (addi r27,+28 etc) vs mine i*0x20/i*0x40 MULTIPLY.
  Rewrote wake to induction w/ ripple's exact init order: applied induction correctly
  BUT wrong coloring (oPool->r25 vs target r27, whole-web shift) 96.91->96.21. Split-init
  + opt_propagation off BOTH regress (96.86/96.47; prop-off kept the mr but broke other
  CSEs). The mr-vs-li and induction-vs-multiply are genuine but every source form mis-colors.
  BANK.
- **tricky/gameUiLoadResources 96.99%**: lbl_803DD868[] read 5x/elem. Target base-hoists
  the SDA symbol into r4 (`li r4,0`[SDA21] + `stw/lwz 0(r4)` x6 reuse). Mine (unsized
  extern) uses `lis/addi` absolute (worse per-instr) but coincidentally COLORS closer
  (96.99, 13 regions). Sizing extern to `[2]` enables direct-SDA `lwz 0(0)` (looks closer)
  but MWCC WON'T reuse the base in a reg -> 17 regions, 96.63. Local `char** podium=`
  hoist puts base in a SAVED reg (function-wide live range, prologue cost) 96.16; late-init
  same 96.63. MWCC's SDA optimizer re-emits SDA-relative per-use, never the target's
  store-forced-base-reuse. No source lever forces the r4-reuse. BANK; kept unsized baseline.

## BANKED (effect/UI deep-dive, dll_000B) — dll_0B_func04 94.22%
Target/current diff = uniform whole-web #108 saved-reg renumber (target `_savegpr_21`,
web based r21-r31; current based r22-r31, off-by-one shift on every saved reg) PLUS
base0-coloring. base0 = `(c*3<<4)+(e*3<<4)` (line 1949), live across mmAlloc + line 2079
emitterCommands use: target parks it in saved r31 and adds it FIRST in the mmAlloc size
expr (`add r3,r31,r0` right after `mulli r0,n,24`); current computes whole
`n*24+total*2+576` then adds base0 last (`add r3,r22,r3`) into low r22.
TRIED+FAILED: rewrite emitter loop to index dest by `cmdBase + m*0x18` (hoisted base +
m*24) dropping the `off` induction var — REGRESSED 94.22->88.55 (also killed the
`st->pendingSpawns + off` source-side induction; target keeps `off` induction for source,
only the base0/mmAlloc side differs). This fn already iterated 3x by prior session
(slot-scan inline helper, opt_propagation off, walking-ptr scan). Residual is the
resistant #108 whole-web shift + base0 saved-reg number — no source lever to force the
allocator's off-by-one `_savegpr_21` vs `_savegpr_22` boundary. Kept BASELINE (no change,
tree clean, all_source EXIT=0).

## Jul05 dd97 session — 5 targets probed, 0 wins, 5 banks (all confirmed caps)
- **dll_0017_savegame.saveGame_saveObjectPos 98.62** (2hr cooled, "cast-array positions store block"):
  residual = store-displacement fold. Target `stw r5,360(r4)` (base=gSaveGameData, +360 folded
  into disp) vs current `addi r4,r4,360; stw r5,0(r4)` (+1 instr). Rewriting stores as
  `((SaveGameImage*)gSaveGameData)->positions[i].field` (matching the read side at L914) DID fold
  the +360 into disp AND hit count-parity T=95=C=95 — BUT REGRESSED 98.62->97.61: the fold forces
  the array index `slwi r5,r7,4` to schedule BEFORE the objectId value load, pushing the value into
  r6 and mis-ordering vs target's `lwz r5,20(r4)` (value)-first. Hoisting the RHS to a temp `v`
  folded away (inert). COUPLED TRADE (fold gains 1 region, loses the slwi/value scheduling region).
  Baseline `(SaveGameObjectPosition*)(gSaveGameData+OFFSET)[i]` cast is best. BANK.
- **dll_0017_savegame.SaveGame_gplaySetObjGroupStatus 97.56** (2hr, "transient loop recovery"):
  residuals = (1) r0-detour on `s=&gSaveGameMapState` base (`addi r0;mr r29` vs target `addi r29`);
  (2) loop-1 transient scan pointer-walk vs target index+displacement. Index-form `s->transient[i]`
  / invariant-base `t[i]` BOTH strength-reduce to a walking base (r3+=3) 97.56->97.32; global-array
  `gTransientMapBits[i]` 97.56->96.73 (re-derives base worse). decl-reorder inert. Target keeps
  STATIC base+disp (3,4/6,7/9,12) walking +15/group — MWCC won't emit static-base disp here.
  Pointer-walk baseline is best. BANK (r0-detour + walker strength-reduction, banked classes).
- **dll_02B3_vortex.vortex_init 98.77** (2hr, "2D-row cast gVortexScaleParams"): uniform saved-reg
  renumber cascade = banked obj/state coloring swap. Target obj->r28, setup->r29, state(184)->r30,
  base->r31; current shifts all -1. state-before-setup decl reorder INERT; base-last decl REGRESSED
  97.66. No lever. BANK (#108 obj/state param-stage).
- **dll_02C0_front.gameTextBoxFn_80134d40 98.72** (2hr, "three source-shape recoveries"): residual =
  saved-reg renumber (r22-r31 uniform perm) + `@203/@528` vs `lbl_803E22E8/lbl_803E2310` = the
  u32->double bias-double const (lfd + xoris magic), #70 compiler-emitted NEUTRAL not injectable.
  BANK (#108 + #70).
- **firecrawler.fn_80157CDC 98.96** (2hr, sibling crawler_updateC/B fixed not this fn): count-parity
  T=141=C=141, entire diff = param-stage swap (obj->r27,arg->r28 target vs obj->r31,arg->r27 current)
  + `@169` vs `lbl_803E2B90` (#70 bias-double neutral). Banked #126 param-stage. BANK.
- **dll_0158_gunpowderbarrel.gunpowderbarrel_triggerExplosion 98.64** (2hr, VN-split fixed): count-
  parity T=200=C=200, residual = def/i #108 coloring swap in returnHome generator-scan loop
  (target def->r26 held, i->r29; current def->r29, i->r26). def-first decl INERT, i-last decl
  REGRESSED 98.53. BANK (#108 walker/counter swap).

## Jul05 fresh-technique survey (fuzzy-specialist agent) — no NEW mineable win landed

### Freshest team techniques classified (git log top-80, last few hrs):
- **KNOWN-CATALOG** (already mined): doPendingMapLoads `(gx+lbl)-7` two-statement split (#66);
  renderGlows `u8 amb[3]` contiguous-array; Objfsa walker-`T[1]`-split; bossdrakor s16 shakeX/Y
  narrow-store; crawler_updateC `(u32)obj` VN-split-cast; saveGame_saveObjectPos cast-of-sum-base
  (contiguous-array); saveGame_doWrite drop-u64-loop-local; maketex byte-arg spellings; skeetla
  dedicated-blend-local (base-hoist/CSE); trickyFindReachableRouteIndex loop-var retype (drop-temp).
- **GENUINELY-NEW #1: goto-fail-guards** (dll_0014 RomCurve_get/func2C, hashes 7a1dee6f2e/38751f0082,
  98.28->98.85 / 97.94->98.75). Rewrite MULTIPLE early-return guards that return the SAME value as
  `goto fail;` to a shared tail `fail: return <const>;`. Forces the target's `bne body; b tail` island
  instead of MWCC's `beq`-fold. FIT-SIGNATURE: ndiff shows `T:[bne;b]` vs `C:[beq]` at an early guard.
  PRECONDITION (critical): the shared tail must MATERIALIZE a real return value reached by >=2 guards.
  Does NOT apply to a single void-tail guard (folds back — see pollen below).
- **GENUINELY-NEW #2: dead-store / redundant-store restore** (partfx partfx_spawnObject, many hashes
  d3788347d3/07b96e1ec6/etc). Restore stores the retail compiler emitted from a still-live register
  that the optimizer would normally kill: a value written-then-immediately-overwritten
  (`cfg.behaviorFlags=0x80000201; cfg.behaviorFlags=0x100201;`) or a redundant default re-store at a
  case head the init block already wrote. FIT-SIGNATURE: ndiff `insert T:[<lone stw/stfs/sth to a
  struct-field disp>]`. NOTE: inherently per-fn target-reading, NOT a mechanical tree-wide scan (you
  must read the target to know WHICH dead store to inject). Both new techniques are being actively
  mined by their originating agents in HOT files (dll_0014 50min, partfx recent) — left alone.

### Tree-wide scan for goto-fail-guard fit (`bne;b` vs `beq` at guard), cold non-hot files:
- **dll_00D9_pollen.fn_8016A660 98.92 (2hr batch-rename only, eligible)**: clean 1-region fit
  `T:[bne;b]` vs `C:[beq]` at the `if(Obj_IsLoadingLocked()==0) return;` guard. ATTACKED with the
  new goto-fail technique: `goto done;`+empty `done:;` tail FOLDED back to beq (empty tail = dead
  label, MWCC drops it); `if(...!=0){body}` branch-if-true-into-block ALSO folds (nothing after
  block). CONFIRMED the goto-fail precondition: a SINGLE void-tail guard has no materialized shared
  return to anchor the island, so it always folds. Same class as ObjGroup_AddObject 99.25 beq-fold
  cap. Reverted to baseline. BANK (goto-fail inapplicable to void-tail single-guard).

### Other cold sub-99 fits surveyed (not attacked — coloring/owned):
- voxmaps.voxmaps_updateActiveMap 98.78: scanner false-positive (punned s16 store is post-loop, not
  in-loop). Real diff = #108 r24/r28 saved-GPR uniform renumber + found-loop block reorder. BANK.
- sky.sky2_run 98.98: 44-region max-reduction/clamp block, `fmr f31,f0` vs `f1` const-load-CSE inside
  a big interleaved unroll — too diffuse for single lever.
- model.fn_80026308 98.93: mostly #108 r4/r5 renumber + one `gModelDotClampMax` const-load placement
  (target loads later than C's `cap=` hoist). Coloring-dominated.
- newshadows.shadowCreate 98.94: inlined sqrtf rsqrt-Newton-Raphson refinement — target has 2 iters
  (`fnmsub;fmul` chain) vs source fewer + FP reg-perm. Real algebraic shape but file is another
  agent's active rotation (5-11hr commits). Left alone.
- dll_0015_curves.fn_800E58FC 98.85: `lfsx f2,r3,r0` vs `r4` slwi-index reg perm, #108. BANK.

RESULT: 0 commits. No clean UNMINED fit for the two new techniques in cold non-hot files this pass;
the pollen goto-fail attempt refined the technique's precondition (needs materialized shared tail).

## Jul05 newshadows.shadowCreate 98.924 — COOLED (6hr since last commit), ATTACKED, BANKED #82
Target = plausible-C sqrtf rsqrt-Newton inline (extern inline sqrtf @L1686, __frsqrte + 3 Newton
iters, shared by 15+ sibling call sites in this file). ENTIRE residual = ONE FP register perm:
the squared-length sum `dx*dx+dy*dy+dz*dz` (== inline arg `x`, live across the whole Newton block
AND into the trailing `shadowScale/dist` fdivs) lands in **f2** (current) vs **f4** (target). Baseline
is otherwise BYTE-IDENTICAL to target — same instr count, same clean single-merge (the `return x`
else-path folds into the Newton result reg, `fdivs f0,f0,f2` direct, no fmr). The two constants
(TokenCB_803DED58 / DrawDone_803DED60 lfd) cascade off that choice (f3/f4 current vs f3/f2 target).
- COUPLED-LEVER TRAP (the reason this is a cap): introducing `f32 sq = dx*dx+dy*dy+dz*dz; dist=sqrtf(sq);`
  DOES move the sum to f4 and makes the frsqrte/lfd/fnmsub block BYTE-MATCH the target (frsqrte f0,f4;
  lfd f3=TokenCB; lfd f2=DrawDone; fnmsub f0,f4,f0,f2 — all correct) — BUT it simultaneously splits the
  inline's two return paths into a merge: `ble ->fmr f1,f4` (return-x path) + `stfs/lfs->f1` (Newton
  path) + `b` + `fdivs f0,f0,f1`. Net REGRESSED 98.924->97.278 (extra fmr + branch merge outweighs the
  matched sqrt-block regs). The clean single-path merge REQUIRES passing the expression inline (no
  named local), which forces f2.
- INERT: decl-reorder `f32 dist,dx,dy,dz` (dist-first) = identical 98.924, does NOT lift the sqrt reg.
- CANNOT edit the `extern inline sqrtf` body (volatile-y staging etc.) — shared by ~15 sibling sqrtf
  call sites (L1730-2045), any change risks tree-wide regression. `#pragma opt_common_subs on/reset`
  already wraps shadowCreate (L2358/2389) — deliberately tuned; the clean merge depends on it.
- CONCLUSION: coupled #82 FP-perm cap. f4 and clean-merge are mutually exclusive via any call-site
  lever. BANK at 98.924. RESULT: 0 commits, source reverted byte-identical to baseline.

## Session dd101 (2026-07-05) — 3 cands evaluated, 0 wins, all whole-web #108 caps
- **animobjd2::fn_8013E0D0** 96.92% (3508B) BANK: 180 regions, 158 pure reg-perm
  from str<->t param-web transposition (target: t->r31, gobj->r30, str->r29, bestd f28;
  mine: t->r29, str->r31, bestd f29). Decl-reorder t-first REGRESSED 96.92->96.70
  (t->r30/gobj->r29 wrong dir). Real li-const seed: TRICKY_RESET_TAIL `*(u8*)(st+0xd)=0xFF`
  emits `li r0,255`x6 vs target `li r0,-1`x6; `(s8)-1` cast FLIPS all 6 to li -1 BUT
  regressed 96.92->95.48 (adds extsb x? + perturbs coloring, 180->183 regions) = coupled
  trade, banked. `-1` w/ u8 dest folds back to 255. srawi count already parity (6=6),
  the LL-suffix flags are inert (net). BANKED.
- **render::fn_80007F78** 94.03% (2212B) BANK: _savegpr_15 (r15-r31, 17 GPRs) 64-bit
  long-long math (addc/adde/subfc/subfe). Entire r14-r31 web renumbered vs target
  (target webs base r30/r27/r25, mine r16/r19/r14) — identical instr structure, def
  whole-web #108. Not grindable.
- **lightmap::renderSceneGeometry** 96.67% (1260B) BANK: 22 regions, T=C=336 (no
  instr delta). 4x-repeated box[]-fill loop; whole-loop reg-perm r5<->r6 (const-1),
  r7/r8 (box lo/hi), r6/r8 (p walker). Root = box[0]/box[1] load order (target 64
  then 68 ascending; mine 68 first). Hoisting `int lo=box0[0],hi=box0[1]` FLIPPED
  box0 order to ascending BUT regressed 96.67->96.42 (added var, shifted stack slots,
  only fixed 1 of 4 loops). Whole-loop coloring transposition, #108 cap. BANKED.

## COLD-FIT SWEEP Jul05 04:50 — dll_0014 goto-fail + partfx dead-store: NO cold fit ready
Both home files COOLED (dll_0014 59min, partfx 2h since last touch).
- **partfx (dll_000E)**: only ONE sub-100 fn remains = partfx_spawnObject 99.599%,
  the exact fn the team just matched (dead-store technique). NO sibling case to attack.
- **dll_0014 goto-fail siblings**: ALL harvested. Checked every sub-100 RomCurve_*
  (func20 98.03, func13 98.28, func1C 98.52, func1C, getAdjacentWindow 98.71,
  goNextPoint 99.02, getRandomLinkedOfTypes 99.02, func16 99.01, func11 98.62).
  Guard regions ALREADY match byte-for-byte: func1C's two `return -1` guards emit
  target-identical `bne;li -1;b <shared tail 6b08>` — no beq-fold to fix. goNextPoint
  already has clearAndReturn materialized tail matched. The `mr rX,r?`-vs-`li rX,1`
  hits in ndiff are the mask=1 loop-const REUSE (within-block coloring), NOT guard
  tails — resistant #108 class, no goto-fail lever.
  Dominant residual across ALL RomCurve siblings = walker/counter saved-reg
  renumber cascade (#108) in the scan loops (e.g. func1C r23/r25/r26/r27 transposition,
  getAdjacentWindow/func16 r7/r8/r9 perms). No source lever; not the two new techniques.
- **dead-store tree-wide**: partfx sibling exhausted; no other cold non-hot file
  surfaced a live-reg extra-store signature in this pass.
VERDICT: both new-technique fits are MINED in their home files; no cold sibling ready.
The fits will re-open as the team matches more fns exposing fresh guard/store shapes.
No edits made, no commit. Build untouched (report-only, no .o rebuilt).

## Jul05 deep-dive pass (small-fn 96-99.8 band, dd-agent) — 0 wins, all BANKED
Scanned all 159 small fns (<1KB) in 96-99.8% via proto report + ndiff --classify.
Band is CAP-DOMINATED (matches predecessors' frontier notes). Every non-reg-perm
seed I tried regressed via reg-perm cascade or was a coupled trade. Specifics:
- **Camera_UpdateProjection (camera.c) 98.09%**: target computes screenWidth
  (resolution>>16) BEFORE screenHeight (&0xffff) — swapping the two u32 decls
  (line 723/724) DOES remove the extra `clrlwi r5,r3,16` dup BUT triggers a 16-region
  reg-perm cascade in the gCameraViewportScreenParams s16-store body -> 98.09->98.06
  net-neutral/tiny-regress. The resolution split is coupled to the store coloring. BANK.
- **Lightfoot_UpdateButtonTimingChallenge (player.c) 99.58%**: `int w=(int)(scale*...)`
  the fctiwz result should be u16-masked (target `clrlwi r26,r0,16`). Both `u16 w` and
  `(int)(u16)(...)` inject the clrlwi (fixes the ext-delete, hits T=284 C=284 count-parity)
  BUT r26's masked value perturbs the saved-reg web -> 26-region cascade, 99.58->99.23.
  Count-parity != gain. BANK (coupled truncation-vs-coloring trade).
- **ObjModel_Load (model.c) 99.x, T=90**: single #110 li-vs-mr — target `li r30,0;
  mr r28,r30` (off=i copy), current `li r30,0; li r28,0` (copy-prop folds off=i to li).
  `off=i=0` chain and `i=0;off=i;` both fold. Same cap as saveSelectSetupMenuItems. BANK.
- **drawWorldMapHud (dll_0000_gameui.c) 99.60%**: #66 `n+=t` -> want `add r28,r29`
  operand order; writing `n=t+n` gives right order BUT explodes to 28-region reg-perm
  cascade (99.60->regress). BANK. (2nd region: extra `lbz 0(r3)` via based gGameUiTaskHint
  addressing — coupled to same web.)
- **fn_8002B758 (object.c) 98.46%, T=72**: single trailing DEAD `blr` (current C=73 vs
  target 72) after a backward `b LBL` loop tail. Under intentional peephole-off/scheduling-off
  block (383-428). Scoped `#pragma peephole on` around just this fn made it WORSE (65 instrs,
  3 regions, blr persists). Epilogue-shape cap. BANK.
- **sandworm_turnTowardTargetAnim (dll_014C) 98.86%**: single extra `extsh r0,r0` before
  `sth 0(r28)` in `*(s16*)a += (shifted>>=3)` under peephole-off. Splitting the >>=3 out
  KILLS the CSE (target reuses shifted in r4 for later `extsh r0,r4` compares) -> regress.
  The extsh is intrinsic to peephole-off + the shared-shifted web. BANK.
CONFIRMED-RESISTANT this pass (pure #108 whole-web / #82 / reloc, no lever, opened only):
  controllight_update 99.64 (r26/r28), modelLightStruct_loadChannelLight 99.72 (r29/r31,
  both params ABI-fixed), staff_update 99.71 (r4/r5 loop-counter), worldobj_render 99.58
  (r9 cmpwi chain), mapBlockRender_setShader 98.99 (r6/r7 fog-temp + li-placement),
  Obj_BuildTransformMatricesForYaw (r27/28/29 whole-web + #66), Obj_UpdateModelBlendStates
  98.46 (j/walker r26/r30 + #110 mr/li), mmFreeDeferred 99.45 (r3/r4), waterfx_drawFn 98.73
  (r22/r24 + #70), voxmaps_updateActiveMap 98.78 (found/counter loop coloring),
  treasurechest_SeqFn 99.68 (mr r28,r5 param-stage position, sched), fn_801EAE4C 98.52
  (drhightop: srawi-vs-and schedule order in signed-avg + r3/r4).
NOTE: dfropenode_func0E 99.75% has ZERO instr-level regions (pure #70 reloc, effectively matched).

## Session Jul05 (small-DLL 96-99.8% deep-dive) — 0 wins / 15 triaged, all BANKED caps
The small-DLL band is DOMINATED by cflags_dll_noopt units (~90% of candidates). In noopt,
the structural levers that need a pass (load-CSE, scheduling, in-place-clamp coloring, branch-
island un-fold) DO NOT APPLY — MWCC noopt has no CSE/scheduler and its branch simplifier always
reverses/folds. Confirmed-resistant this session:
- **pollen fn_8016A660** 98.92% (NOOPT): target `bne body;b end` un-collapsed 2-branch island vs
  my folded `beq`. Positive `!=` guard, `if(){}else{return;}`, and explicit `goto` ALL fold back
  to `beq` in noopt (its branch simplifier reverses unconditionally). Only real diff + #70 reloc.
- **gflevelcon fn_8023A3E4** 99.35% (NOOPT): `hp[0xAE]` load-CSE — target loads u8 once into r3,
  reuses for `!=0` compare AND `-1` decrement (no reload). Baseline reloads (+1 instr). EVERY temp
  form (u8/int/(u8)-cast) trades the reload for a clrlwi-narrow + cmpwi-signed + r3/r4 coloring =
  net WORSE. noopt won't CSE the load; baseline reload is the least-bad. BANK.
- **titlemenuitem TitleMenuItem_update** 98.31% (NOOPT): li-const call-arg (`li r3,0;li r4,953`)
  scheduled after cmpwi in target, hoisted-before in mine — noopt arg-materialization schedule, no
  lever. +4 #70 relocs (bias double).
- **dll_801c0bf8 fn_801C0BF8** 98.63% (NOOPT peephole-on): loop `vertex+=16` increment placed by
  target right after store, before counter `addi;cmpwi`; mine defers it past. Comma-operator
  `vertex+=8,i++` in for-clause INERT (counter addi;cmpwi still fuses ahead). noopt increment-sched.
- **camshipbattle5c fn_8010AC48** 99.07% (NOOPT): f25/f26 FP-perm in two symmetric vector-normalize
  blocks + #70 (`@165` vs `lbl_803E1888` zero-compare const). Naming the `0.0f` compare as
  `lbl_803E1888` (proven pattern in dll_0047:49) REGRESSED 99.07->97.55 (over-perturbs whole FP web).
  FP-perm cap.
- **dimwooddoor DIMwooddoor_updateShardAim** 99.15% (NOOPT): `distSq` clamp ternaries — target keeps
  distSq in saved f31 across the two `?:` clamps; mine copies to volatile f3. Converting either/both
  ternaries to in-place `if(distSq<K)distSq=K;` REGRESSED (99.15->98.20 one, ->97.67 both): the if
  changes distSq downstream coloring, deletes instrs target keeps. Ternary IS correct; fcmpo-swap/
  f31-vs-f3 is pure coloring. BANK.
- **drlasercannon_aimAtTarget** 97.66% (NOOPT): heavy s16/int extsh + r3/r4 coloring web (16 regions).
  `s16 clamp/negClamp` REGRESSED 97.66->95.72 (over-narrows). s16-field coloring cap.
- **arwarwing_updateBarrelRoll** (wcfloortile) 98.69% (NOOPT): fcmpo `f1,f0` vs `f0,f1` — `zero`
  value's f0/f1 home fixed by allocator. Hoisting `zero=lbl` out of the embedded-assign condition
  REGRESSED 98.69->98.05. fcmpo/FP-coloring cap.
- **babycloudrunner sandworm_turnTowardTargetAnim** 98.86% (O4,p, fn has peephole OFF): extra
  `extsh r0,r0` before `sth` on `*(s16*)a += (shifted>>=3)` that peephole-off can't remove (sth
  truncates → dead). `#pragma peephole on` for THIS fn removes the extsh (C102->100) BUT restructures
  the `t=shifted>>2` branches + adds extsh/cmpwi region = REGRESSED 98.86->93.52. Split/explicit-add
  forms INERT (extsh intrinsic to s16-deref-compound-add under peephole-off). Coupled trade, BANK.
- Pure whole-web reg-perm / mr-ordering (no lever): warpstoneui fn_801343CC 97.60, kytesmum
  animEventCallback 98.40 (obj/state 184-swap, memory-confirmed), dfropenode_func0B 98.88 (r7/r8
  index-ptr), treasurechest_SeqFn 99.68 (mr r28,r5 stage order — init-at-decl INERT), waterfx
  fn_80095164 98.73 (#66 commutative fmul `4.0*x` const-slot fixed + #84 arg-addr sched — operand
  swap in source INERT), optionsMenu_openGeneralPanel 98.91 (lhzx/sthx base/index r3/r4 swap).
KEY TAKEAWAY: for this band, noopt is the wall. Highest-EV remaining small-DLL work is the few O4,p
units (expgfx[team-hot], babycloudrunner, credits, skeetla, warpstoneui) where CSE/peephole levers
CAN fire — but the ones checked are coloring/coupled-trade caps. The #70 named-vs-@NNN bias-double
reloc is pervasive and score-neutral; ignore it.

## Jul05 dd108 session (opus 4.8) — 3 banked, 0 wins
- **model.c modelLoad_calcSizes** 93.53% (O4,p): the `total` additive-accumulator chain
  (`total=(sizes[1]+8)+total; total=sizes[6]+total`) lands in r6 (target) vs r7 (current);
  the r6-vs-r7 accumulator home cascades to the ENTIRE downstream (154=154 instrs, ~11 of 13
  regions are pure r6/r7 renumber). Target's two branches (if morphCount||forceBlend / else)
  even group the adds DIFFERENTLY (if: `s6+((s1+8)+(s3+(s4+100)))`; else: `s3+((s6+s1+8)+
  (s4+100))`) — a scheduling-derived re-association from the `sizes[4]+=0x30` perturbation.
  TRIED: hoist `hs8=sizes[1]+8` temp (FOLDS via copy-prop, inert 93.53); single-expr
  `sizes[6]+((sizes[1]+8)+total)` (13->10 regions BUT fuzzy 93.53->92.06, r6/r7 got worse).
  Pure #66/#108 accumulator-coloring, no source lever. BANK.
- **newshadows.c fn_8006CB50** 94.48% (O4,p): target addresses the sdata2 float consts as
  `Udchuff_803DEDA0 + 0xc/0x10/0x14/0x18/0x1c` (one base+disp) vs current's 5 individual
  extern symbols (Udchuff_803DEDAC/B0/B4/B8/BC). Looked like struct/array recovery. TRIED
  `extern const f32 Udchuff_803DEDA0[]` + index [3..7]: REGRESSED 94.48->88.66 (array form
  makes MWCC load a base pointer reg + `base+idx*4` = +3 instrs; the individual symbols use
  direct r2/sda `lfs offset(r2)` loads). The base+offset-vs-symbol is #70 reloc-naming
  (neutral); rest is the sqrt/rsqrt Newton-iteration FP-perm (#82, f2/f3 renumber). BANK.
- **pi_dolphin.c loadDataFiles** 96.82% (O4,p): CONFIRMED the prior banked note (@7025) was
  MISATTRIBUTED — the 2-instr residual (`subfic 87-vi;mtctr` + `bge;bdnz` vs `addi;blt`) is
  the EMPTY `vi=0x50 do{}while(++vi<0x57)` loop (lines 7005-9), NOT the big indexed loop.
  Target strength-reduces the empty spin loop to a counted `bdnz` (guard `cmpwi 87;bge` +
  `bdnz`); current keeps it as a `blt` compare loop. TRIED: `for(vi=0x50;vi<0x57;vi++){}`
  and `while(vi<0x57)vi++` (both DCE-ELIMINATE the empty loop entirely, C=101, WORSE);
  `volatile int vi` (keeps loop but stack-spills, no bdnz); `#pragma optimize_for_size on`
  around fn (REGRESSED whole fn to 12 regions + `_restgpr_29` epilogue); `#pragma
  opt_loop_invariants off` around the for (still DCE'd). The counted-empty-loop is a
  pass-ordering artifact (counted-transform ran BEFORE empty-loop-removal in target build;
  mine runs DCE first). do-while is the only form that keeps the loop at all. No source
  lever. BANK.

## STRUCT-RECOVERY (state-block field naming) Jul05 — 1 WIN + fresh-unit vein exhausted (Opus struct-recovery)
- **WIN dll_00EF_pushable (663bd9fb18)**: `*(f32*)(state + 0xc)` in pushable_func0B
  reads PushableState.cullDistance (offset 0x0C, named). Retyped to
  `((PushableState*)state)->cullDistance`. Conversion-free fn (no sinf/(f32)(int)/bias);
  `state` is `int` from `*(int*)&extra`. .o md5 IDENTICAL (24f94a2c...). all_source EXIT=0.
- **FRESH DATA-SPLIT UNITS EXHAUSTED for clean named-field fits**: swept the prompt's
  named units (skeetlawall/texscroll/explodeanimator/attractor/lightsource/staticcamera/
  wallanimator/fogcontrol/animsharpclaw) + cooled *State-bearing siblings. vfpladders/
  dimtricky/sbshipmast/ccqueen no longer exist under those names (matched/renamed).
  Residual raw casts DO NOT map to named fields:
  - dll_0117_appleontree: `*(float*)(state+4/0x10/0x20)` all land in unk00[8]/unk10[]
    UNNAMED padding of AppleOnTreeState. No field to map. SKIP.
  - dll_00ED_collectible: `*(f32*)(state+0xb8/0xbc/0xc0)` inside pathState[0x50..0x2B1]
    gPathControl blob (unnamed sub-region). SKIP.
  - dll_00D1_tumbleweedbush: `*(u16*)(state+0x4e)`, `*(s16*)(state+0x27c..0x280)` beyond/
    in pad of TumbleweedBushState (struct ends 0x54). SKIP.
  - dll_00EF_pushable line 482/484 `*(u32*)(extra+0xa8)` = padA8[4]+gameBit region
    (u32 view over padding, not a field). SKIP (only 0xc was a clean fit).
  - dll_0104_smallbasket `*(s16*)(data+0x1c)`, dll_010D_portalspelldoor
    `*(s16*)(data+0x1c/0x1e)` = SETUP/DEF descriptor reads (data=placement, not the
    state block); no *State type for that def. Out of the state-cast pattern. SKIP.
  - dll_0127 `*(short*)(obj+0xf8)` = per-unit s16 view of shared s32 field — precondition
    says LEAVE (cross-file struct risk).
  - dll_0184_animsharpclaw: line 168 already `((GameObject*)o)->extra` with `*(int**)&`
    launder (NEVER touch); line 118 vtable call.
  VERDICT: the clean named-field state-cast vein is mined out for the current struct maps.
  New fits re-open only when a struct's unk-padding gets behaviourally named by another pass.

## dd109 tricky/curve/follow deep-dive (Jul05, 0 wins — all banked)
Ranked sub-99.5 tricky*/curve*/follow* via proto report. All tried fits are coloring/
FP-perm/SR caps with NO source lever; every experiment Edit-reverted, files left clean.
  - dll_0015_curves.curves_getCurves 96.96%: uniform 3-reg rotation r3->r4->r6->r3
    (walker=hitPointCursor r4, inner-deref r3, count=sCurvesCachedHitCount r6 in target;
    mine walker r6/deref r4/count r3). #108 whole-web, count is a global re-read not a
    local -> no cache/decl lever. BANKED.
  - dll_0015_curves.dll_15_func08 97.63%: clean r30/r31 param swap at entry
    (target curveObj->r30, state->r31; mine reversed). collision=state alias (280 uses)
    copy-prop-merges the web; decl-reorder of `collision` INERT. #108, BANKED.
  - dll_0015_curves.dll_15_func06 98.84%: idx3(+3)<->ptsWalk(+12) saved-reg swap
    (target idx3=r23/ptsWalk=r30; mine reversed). TRIED: ptsWalk decl-before-idx3
    (regress 98.26 — perturbs whole r24-27 chain), func0A-style loopIdx[2]/ptsWalk[1]/
    byteOff[1] array-split (regress 96.10 — func06 structure differs from func0A). BANKED.
  - dll_0015_curves.curves_updateLocalPointCollision 99.23%: SR walker r29(+12) emitted
    BEFORE loop-counter r27++ in mine, AFTER in target (first loop) + r4/r5 #108 second
    half. Swapping source `zoff+=4`/`pointIndex++` order INERT (SR pass owns walker
    position, not source stmt order). BANKED.
  - trickyfollow.trickyUpdateApproachSpeed 98.44%: td/dec FP-perm — target td->f3(high)/
    dec->f2; mine td->f2/dec->f3. Whole-fn f-perm + fcmpo swaps all cascade from this one
    swap. TRIED: inline td into dec (regress — reorders const loads), operand swap
    td*K vs K*td (INERT — flips fmuls operands but not dest regs). #82, BANKED.
  - trickyfollow.trickyFn_8013b368 99.40%, tricky_rollroute.trickyFn_80141290 99.27%,
    tricky_substates.trickyFn_801430e0 98.82%: all obj/state param coloring swaps
    (r29/r30 + state@184(obj)->r31), the confirmed-resistant flat-dll #130 pattern. BANKED.
  - dll_00C4_tricky.Tricky_update 99.14%: REAL seed at TRICKY_RESET_COMMAND macro
    `*(u8*)(state+0xd)=0xFF` -> mine `li 255`, target `li -1`. Changing to `= -1`
    stays 255 (u8 folds -1->255); `(s8*)` cast DOES give `li -1` and kills the 255 diff
    (0 remaining) BUT introduces `srawi r0,r3,31` sign-extend on a read elsewhere ->
    NET REGRESS 99.14->98.09. The offset-0xd field is read as s8 at line 2940 (other fn);
    coupled li-const trade. Rest of diff = obj/state r26/r27 coloring. BANKED.

## dd-agent session (Jul05) — small-fn fuzzy triage, 15 fns, 0 wins (all banked caps)
Triaged small (<1KB) fns 96-99.8% across -O4,p DLL/main units. Every candidate resolved
to a documented resistant cap; no working source lever found. Details:
- **dfropenode_func0E** (dll_0175) 99.75% #82 FP-perm: localZ/phase f27<->f31 transposition
  (localZ delta wants f31, loop `fmr` phase temp wants f27). Decl reorder localZ-first REGRESSED
  99.75->99.46; phase-last INERT. Loop-created temp web colored by allocator, no source lever.
- **staff_update** (dll_00E2) 99.71% #108 reg-perm: coherent r4<->r5 scratch swap through the
  whole swipe loop (`j`/vertexData mulli operands + vertexCount/startIndex RMW temps). `j*20+base`
  operand reorder INERT (commutes back).
- **treasurechest_SeqFn** (dll_011D) 99.68% param-staging mr-order: target `mr r27,r3(obj);
  mr r28,r5(animUpdate)` vs mine reversed. obj-inline (drop `o` alias) REGRESSED 99.68->98.31;
  for-loop INERT. Banked #126-family param-stage (shop_init/sfxplayer_free class).
- **removeButtonObject** (gameloop) 98.09% peephole-fusion cap: target `srwi;cmplwi` (unfused)
  vs mine `srwi.` (dot-fused) in an 8x-unroll trip-count guard (T=60 C=59). `#pragma peephole off`
  REGRESSED to 87% (wrecks body). Coupled peephole trade.
- **fn_8002B758** (object) 98.46% dead-trailing-blr: identical body, mine emits +1 dead `blr`
  after the cold loop-preheader's `b`. Unit needs `peephole off` (body matches); peephole ON
  removes blr but REGRESSED 98.46->85.85 (reschedule damage). Coupled.
- **mapLoadBlock** (shader) 99.44% copy-prop-const-fold: target `li r28,0; mr r27,r28` (byteOff
  copies i=0) vs mine `li r27,0`. Source already `i=0; byteOff=i;`. O4 folds the const-copy.
  for-comma dual-induction REGRESSED 99.44->99.24. Banked saveSelectSetupMenuItems class.
- **sandworm_turnTowardTargetAnim** (dll_014C babycloudrunner) 98.86% spurious-extsh: `*(s16*)a+=`
  RMW emits dead `extsh r0,r0` before truncating `sth` (T=101 C=102) because unit is `peephole off`.
  Non-compound assign INERT; `peephole on` drops extsh but REGRESSED 98.86->93.52 (body tuned for off).
- **fn_801EAE4C** (drhightop) 98.52% sched-order: signed `(x>>1)-(x&absDelta)` idiom, scheduler
  emits `and` before `srawi` vs target `srawi` first (+r3/r4 perm). xDelta-temp hoist REGRESSED
  98.52->97.16. Scheduler.c ordering cap.
- **r0-detour cluster** (BANKED on sight, no attempt): voxmaps_resetLoadedMaps 99.x,
  initControllers, modelLightChannels_applyGXControls, subtitleBuildLineTable, fn_8011EF50,
  shield_update — all `addi r0,r3,0; mr rN,r0` vs target `addi rN,r3,0` direct named-saved-reg
  param init. Documented resistant.
- **mmAllocateFromFBMemoryStore** copy-prop: target extra `mr r5,r4` + r4-base vs mine r5-base
  materialized. Same fold-const class.
Build EXIT=0, 0 FAILED, tree clean (all experiments Edit-reverted). No commits.

## STRUCT-RECOVERY (spawn-setup + message-buffer sweep) Jul05 — 0 wins, veins confirmed EXHAUSTED (Opus struct-recovery)
Swept the 3 assigned patterns across all non-team-hot DLLs; every candidate is already
recovered, conversion-trapped, or a load-bearing launder. NO byte-neutral fit landed.
- **spawn-setup buffers**: the `Obj_AllocObjectSetup`/`Obj_SetupObject` + head-seed vein is
  fully mined. All buffer-seeding sites with head writes ALREADY use named struct casts:
  firepipe (FirePipeEffectSetup w/ ObjPlacement head), icebaddie (IceBallSetup.head),
  chukchuk/kaldachom ((ObjPlacement*)setup), hightop/mmshscales/ecshcreator/gpshobjcreator
  (per-family *Setup/*Spawn/*Placement). The 22 "no-cast" alloc files
  (headdisplay/minimap/dll_b4/cloudaction/dll_016C/dll_0031/etc.) alloc-then-Obj_SetupObject
  with NO buffer field writes (kind 4, defaults) — nothing to recover.
- **message buffers**: no ObjMsg *buffer struct* exists — `ObjMsg_SendToObject(target,msg,from,value)`
  is scalar-arg only. Pattern does not apply in this tree.
- **fixed-offset state-field casts** — the clean candidates all fail a precondition:
  - dll_015A_explodable explodable_update L198/206/207 `*(int*)(p+0x690)` = DrExplodableState.children[]
    BUT it's a POINTER-WALK induction (`p=state; ...; p+=4`) — retyping to children[i] changes
    addressing mode (base+idx vs induction ptr) = NOT byte-neutral (#112/#108 launder). SKIP.
  - dll_011B_landedarwing L260 `*(int*)(def+0x14)` (ObjPlacement.mapId slot) — value switched on as
    event-key (0x43775/0x451b9), semantic mismatch w/ mapId; def is int local (per-site int->ptr
    cast materializes addr temp per header note). SKIP.
  - dll_0287_spscarab L192-193 `*(int*)(def+0x14)` repurposed as vendorObj (class-specific, not mapId). SKIP.
  - dll_0243_dbholecontrol1 L189-195: buffer written via GameObject anim overlay + class-specific
    +0x1a; enclosing fn has `(s32)(s8)*` conversion (bias-double trap) — SKIP whole fn.
  - dll_00EA_sideload L246 / dll_00F7_dllf7 L276 `*(u8*)(placementData+0x19)` = class-specific byte
    past ObjPlacement head (ends 0x18); no *Placement struct names 0x19. Not a named-field fit.
- VERDICT: spawn-setup + message-buffer + fixed-offset-state veins are EXHAUSTED for byte-neutral
  per-site recovery. Re-opens only when a *State/*Placement struct's class-specific region gets
  behaviourally named by another pass. NO COMMIT this session.

## STRUCT-RECOVERY unk-region-naming Jul05 (opus 4.8) — 2 WINS + drpickup negative
Angle: NAME unnamed unk/pad sub-regions of *State structs where raw casts land
(behavioral inference), then convert the raw casts -> byte-neutral.
- **WIN dll_0117_appleontree (6df16f1361)**: split AppleOnTreeState.unk00[8]
  -> unk00[4]+f32 phaseDuration@0x4, and unk10[]-> f32 growThreshold@0x10 +
  unk14[12] + f32 fadeThreshold@0x20. Converted the 3 `state`-based raw
  `*(float*)(state+4/0x10/0x20)` casts in appleontree_update (frac=elapsed/period
  denominator + GROWING/KNOCKED phase-cutoff `frac>thr` compares). .o md5 IDENTICAL
  (130c03b1...). Sole includer. NOTE: the `val+N` raw reads (val=laundered
  *(int*)&obj->extra, offsets 4/8/0x14/0x18/0x24/0x54) left raw — different int base,
  no interference; only the canonical-`state`-base casts converted.
- **WIN dll_00D1_tumbleweedbush (24ac21cc7f)**: split TumbleweedBushState.pad4D[3]
  -> pad4D[1]+u16 spawnedCount@0x4E. Converted the 2 `*(u16*)(state+0x4e)` casts
  (spawn counter ==6 test + post-spawn increment; state is u8*, cast to
  (TumbleweedBushState*)). .o md5 IDENTICAL (27348ab1...). Unit-local struct.
  The 0x27c/0x27e/0x280 s16 casts are BEYOND struct end (0x54) = untyped trailing
  alloc, no field to map, left raw.
- **NEGATIVE dll_drpickup (reverted)**: DRPickupState fields angle40C/angle40E/
  angAccum410/liftZVel (0x40c/0x40e/0x410/0x430) ARE already named in DRpickup.h,
  but fn_801EC1AC keeps them as raw `*(TYPE*)((int)state+off)` casts (mixed with
  named-field access elsewhere same fn). Converting raw->named CHANGED the .o md5
  (06c94cda->7ef60352) = NOT byte-neutral. The raw `(int)state+off` re-cast /
  `(s32) * (s16*)` launder form the author deliberately kept produces different
  CSE/coloring than `->field`. Reverted all, md5 restored. These launder-form raw
  casts are a #130-style deliberate-launder — LEAVE.
- **SHARED-BADDIE-BLOCK caps (skipped, not mine)**: duster/fireflylantern/newseqobj/
  magicplant/wispbaddie/dll_000F etc. — their high-count raw casts land in
  pad00[0x2F8...] = the shared BaddieState prefix (include/main/dll/baddie_state.h).
  Offsets like 0x2A0 (per-family UNION, moveSpeed for some) and 0x323 (per-family
  scratch unk323[]) are documented per-family regions in the shared header. Naming
  them in a per-unit overlay conflicts cross-file. baddie_state.h owner's domain. SKIP.
- fireflylantern `state+0xc2` etc: state is int* so `+0xc2`=byte 0x308 (int-arith
  trap), inside the BaddieState prefix. Its 0x344 planeNormal already documented
  "stays raw, passed by address". Fully curated already. SKIP.

## dll_02BC andross — struct recovery (byte-neutral) [commit ec48ec4392]
- AndrossState.unkB6 -> startupDelay (u8 @0xB6): init=5 in andross_init;
  andross_update gates on it (decrement+early-return until 0, spawn settle).
  Respelled 2 raw *(u8*)(state+0xb6) accesses -> arrow. .o BYTE-IDENTICAL
  (md5 f692d1ba). updateModelAlpha & andross_update unchanged (100 / 99.520).
- DISQUALIFIER left raw: `*(f32*)(state + 0x68) = lbl_803E74D4;` (line 167,
  andross_updateModelAlpha). 0x68 IS fadeAlpha (proven by adjacent read), but
  the arrow respell REGRESSED updateModelAlpha 100% -> 94.595% (bytes changed,
  md5 ffa50c6e). The raw *(f32*)(state+0x68) write is the CANONICAL form for
  this store; leave raw. All other fadeAlpha reads/writes already arrow-spelled
  and fine — only this one setup-write must stay raw.

## FUZZY sweep — bossdrakor s16-hoist siblings SWEPT; fn_80137A00 fill-loop BANKED #108 (2026-07-05, Opus)
Freshest genuine fuzzy cracks (last ~8-9h, all other older commits are naming/data-split build-linking):
- **c17adca09d bossdrakor_update 97.48->97.72** (s16 hoist): typing the fctiwz-conversion result
  `s16` (with `(s16)` casts) narrows the extsh ONCE before the shake do-while(i<5) loop, so the
  `uvec[0]/uvec[1]` sth stores reuse the pre-narrowed value. Technique = "extsh-hoist-out-of-loop
  via s16-typing an fp conversion stored to s16 fields."
  RACE RESULT: siblings SWEPT. Grepped every shake/uvec/DegToAngle/`(s16)(fp*)` conversion site:
  dll_00E0_swarmbaddie (all fns 100%), dll_000F_unk (all 100%), dll_0272_hightop hightop_stateHandler02
  (99.79% — its `int conv`/`(s16)conv` sites are straight-line `(s16)(x>>n)` shift-narrows the target
  ALSO emits via lwz+extsh, i.e. already matched, NOT a loop-hoist miss). No cooled sibling with the
  loop-store-of-fp-conversion shape remains. Technique is fully applied.
- Other genuine cracks (08a215d753 walker-split, 201aa8b1e8 transient-loop, 73e7c56c4e/ObjHits family)
  = known catalog, siblings already swept by prior sessions.

BANKED (no source lever) — **dll_80136a40.fn_80137A00 97.60%** (#108 param-staging transposition):
  Debug-font pixel-fill loop (4 parallel `debugDrawFrameBuffer[]` sthx column-walkers, DCStoreRange
  flush per row). Normalized-register diff proves the ENTIRE residual is one 2-reg within-class swap:
  target r27=row1 / r29=x(base), current r27=x / r29=row1 — plus the driving cause: target STAGES
  `grid` (`mr r26,r5`) BEFORE the two row0/row1 mullis; current schedules that `mr` AFTER the mullis.
  TRIED+INERT (all 113/113 instr, byte-neutral, coloring unmoved): decl-reorder row0<->row1 (moved
  row0->r29, wrong direction), `int px=x` capture placed first + used in c0/c1 (x still r27), `u8* g=grid`
  captured first + used as g[i] (grid `mr` STILL scheduled after mullis — MWCC scheduler fixes the
  param-stage position independent of source statement order). This is the documented flat-dll
  param-staging `mr r*,r5`-placement class = no source lever. Sibling fn_80137DF8 (same unit) is
  team-hot (13h, actively cracked via fill-backdrop/paired-walker/relational-while) — left untouched.
  fn_80137A00 left at clean baseline (build EXIT=0, file diff empty).

## #127 extern-const FP-load lever sweep (2026-07-05, Opus fuzzy+semantic) — FRONTIER SATURATED, 0 wins
Systematic hunt for the #127 signature (a read-only FP const loaded >1x that would load-CSE into
one saved fN reg if const-qualified, dropping a redundant load). Method: private proto report
(1223 units), decoded fuzzy per-fn, ranked 90-99.7% non-audio main/track/dll units. Scanned 382
candidate fns two ways: (a) ndiff reload-vs-fmr / insert-lfs-from-reloc pattern (parallel xargs),
(b) per-symbol reloc-load COUNT imbalance target-vs-current via function_objdump --diff.
RESULT: ZERO clean #127 hits. For EVERY candidate the named-FP-const load COUNTS already match
target exactly (e.g. dll_0B_func05 lbl_803DF430 x7 in BOTH T and C; lbl_803DF434 x3 in BOTH).
The +/- deltas in --diff are pure position-shift artifacts of moved blocks, NOT extra loads.
The low-hanging #127 fruit (RomCurve_find, ObjHits_ProjectPointToTaperedCapsuleXZ) was harvested
in prior sessions; the lever is now exhausted at this match frontier.
BANKED (triaged, no #127 lever — residuals are the listed class, not redundant FP loads):
  - dll_02AE waterflowwe_calcCurrentVector 99.76%: #82 FP-perm (f24/f25/f26 renumber, same load
    count) + #70 @119/@120 anon relocs. gWaterFlowBandMax/StrengthScale ALREADY extern const
    (prior commit); the @119/@120 are different compiler-pool consts, INERT.
  - modellight modelLightStruct_loadChannelLight 99.72%: #108 GPR renumber (r29<->r31), same count.
  - DF/dll_0175 dfropenode_func0E 99.75%: #82 FP-perm (f27<->f31) + gRopeNodeS32ToDoubleBias
    bias-double reloc trap.
  - dll_0272 hightop_stateHandler02 99.79%: #108 GPR + lbl_803E6AF8 bias-double (xoris 32768) +
    cmpw operand-order/branch-sense swap.
  - DR/dll_0261 drlasercannon_aimAtTarget 97.66%: s16 extsh-vs-mr narrowing trade (C=253<T=255) +
    lbl_803E68D8 bias-double + blt;b vs bge branch-island. Extsh-removal trade (coupled), banked.
  - objseq ObjSeq_ApplyFrameCurves 97.61%: #108 r25<->r26 + one extra extsh r0,r0 (s16), not FP.
  - Curve_AdvanceAlongPath 99.81%: lbl_803DE688 named in T vs anon @38 in C, 1:1 (#70 neutral).
  - player/fn_802B1E5C, dll_0B_func05, expgfx_addremove, newclouds/snowPrintSnowCloud: --diff
    FP-load delta flagged but per-symbol counts prove no true reload; broad structural/bias-double
    divergence in big fns, other agents' clusters (expgfx=mine but data-hot 9h, no FP lever here).
No source edits made; no commit. Build untouched.

## dll_011D_treasurechest — seqId raw cast recovered (2ba8279f7d)
- WIN: `*(short*)(nearestObject + 0x46)` -> `((GameObject*)nearestObject)->anim.seqId`
  in the open-chest trigger path (setObjects arg). Offset 0x46 = ObjAnimComponent.seqId
  (STATIC_ASSERT-anchored, objanim_internal.h:565). s16 sign-extended load unchanged.
  .o md5 IDENTICAL 279db33977fe260d33e333f539cb6458 pre/post. all_source EXIT=0.
- CANDIDATES LEFT RAW (disqualified):
  - fuelcell (dll_0123): `slot = state + i*4` pointer-walk INDUCTION; op+0x43 is foreign
    render-op struct. Disqualified (induction / foreign base).
  - firepipe (dll_0273): glowLight+0x2f8 shared-prefix; effectObj+0x68 foreign obj launder.
  - fireflylantern / magicplant: base is BaddieState (shared pad00[0x2F8] prefix; 0x323-0x345
    per-family CONFLICTING scratch, maintainers left raw). Cross-file, not this domain.
  - restartmarker/flamethrowerspe staticCamera_init: placement+0x19/0x1a bias-double trap
    ((double)(u32)*(u8*)) at same site. Disqualified.
  - dllce chukchuk: setup+0x2e is ChukChuk-specific placement field PAST ObjPlacement's
    0x18 common head; header warns per-site int->ptr casts materialize addr temps. No
    ChukChukPlacement struct exists. Left raw.
  - partfx/effect7/effect3: `*(u32*)(command+4)` is a deliberate raw-u32 float-bitcopy
    launder AND the ModgfxVertexGroupCmd struct is shared across 3 .c owners. Skip.
  - modgfxfunc03 obj+0xf2: u8* sprite/model byte view, no named struct.

## SEMANTIC-RECOVERY sweep of UI/HUD/MENU/CAMERA/VEHICLE(arwing) cluster (2026-07-05, Opus) — 0 wins, cluster SATURATED
Swept the entire in-scope cluster for pad-run splits (the appleontree/tumbleweedbush/andross
pattern: raw `*(T*)(state+off)` reads INTO an anonymous `padNN[]`/`unkNN[]` run, split+arrow-ify
byte-neutrally). FINDING: every accessible clean pad-split has already been harvested by prior
struct-recovery passes; all remaining raw casts in this cluster are on documented DISQUALIFIERS.
Files surveyed + why no clean win:
- **cmenu.c** (20 raw casts, richest target): the `base + wordOff + 0x848` / `base + count + 0x448`
  / `base + halfOff + 0x948` writes in cMenuSetItems are a hand-tuned PARALLEL-INDUCTION loop
  (`count`/`wordOff`/`halfOff` are separate induction vars the compiler must keep distinct to
  match the 97.881% target another agent is actively tuning). CMenuHud fields exist (ids848[],
  itemFlags[]) but arrow-ifying to `->ids848[count]` collapses the 3 inductions -> byte-change.
  INDUCTION disqualifier. Other cmenu casts (tricky/model/shader/rec/obj +off) = GameObject-core
  shared. Leave raw.
- **dll_0000_gameui.c**: GameUiHud/CMenuHud already typed; the `g->itemTextures + k*4` table-clear
  loops are deliberately hand-tuned byte-offset walks (comment: "both loops are in the asm").
  `sprite`/`box` (+0x2/0x8/0xa/0x14/0x1e) = `gameTextGetBox()` void* = SHARED engine text-box
  struct (engine_shared.h, cross-file). Leave raw. (File actively named-tuned today, busy.)
- **ARW/dll_029A_arwarwing.c** (26 raw casts): already fully arrow-ified vs ArwingState. Remaining
  raw casts = `wingVec[i]+0/+4` and `vec+0x6/0x8/0xa` (s16 writes into objModelGetVecFn result
  pointers = SHARED model-vector/bone struct, cross-file) + cam/pathBlock/mev shared cores. Leave.
- **camera-mode state files** (worldmap/combat/shipbattle/cannon/npcspeak/bike/viewfinder): State
  structs FULLY recovered (named fields + STATIC_ASSERTs). Trailing `unkNN[]` are alignment
  padding only (never accessed). Remaining raw casts (`view+0xc`, `cur+12`, `camObj+0xa4`) = shared
  CameraObject/GameObject core (+0xc worldPosX etc). Cross-file. Leave raw.
- **warpstoneui.c** `dst+6/0x1a/0x1b` = `dst += 0x3c` byte-stride INDUCTION walk over a 0x3c-entry
  array (u8* param). Pointer-walk induction disqualifier. Leave raw.
- minimap/titlemenu/pausemenu/picmenu/menu: 0 constant-offset state casts (clean or shared-core).
VERDICT: this cluster is SATURATED for pad-run struct recovery. The un-deciphered residue here is
either (a) already-distinct `unkNN` FIELDS whose SEMANTICS are unknown (naming = judgment task, not
byte-neutral pad-split) or (b) hand-tuned induction / shared-core casts that are byte-change traps.
No commits this session (nothing byte-neutral to change).

## SEMANTIC-RECOVERY survey (Jul05, Opus 4.8) — 0 new wins, field exhausted for clean unit-local candidates
Surveyed all src/main/dll for raw `*(T*)(state|obj|self + 0xNN)` casts against unit-local
State structs with anonymous pad runs (the tumbleweedbush/appleontree winning shape).
Candidates ranked + all DISQUALIFIED:
- **dll_019D_dll19d** (torch): `*(int*)(self + 0xf4)` @L225-226. self is `int`. TRIED
  `((GameObject*)self)->unkF4` (s32@0xF4, width-exact) — .o md5 CHANGED
  (3f820cbc->e83ea665). Reverted, md5 RESTORED to 3f820cbc. This is a #130 raw-int-offset
  LAUNDER: casting self->GameObject* at THIS site alters coloring/scheduling even though
  sibling `((GameObject*)self)->anim.*` accesses in the same fn are fine. DISQUALIFIED.
- **seqobj11d / newseqobj / duster / dll_000F_unk / tricky / wispbaddie / enemy**: all use
  GroundBaddieState/BaddieState (baddie_state.h) — SHARED cross-family struct (scarab,
  mediumbasket, treasurechest, lightfoot). Offsets seen (0x2a0,0x2b6,0x338,0x2f2) fall in
  BaddieState prefix (<0x2F8) or route35C[] anonymous route buffer. SHARED-PREFIX, not this
  domain + claimed baddie/creature cluster.
- **dll_0190_ecshcup** (ecsh cup minigame, unclaimed, unit-local EcshCupState @0x30):
  `ecsh_cup_update` ALREADY fully `state->field` (well-recovered). `fn_801C8B68` casts
  `*(short*)(state+0xe/0x10/0x12)` where state=`register int` from ->extra; offset 0xe sits
  INSIDE velX (f32 @0xC-0x10) = per-unit NARROW s16 view of a wider float field. DISQUALIFIED.
- **dll_000B_dll0b** (partfx/modgfx — flagged heavily-worked): `*(s16*)(state+0x46)` in large
  PartfxEffectState. Left (cluster policy).
- **dll_801e66dc** (shopkeeper aux): `state+0x9d6/0x9b0` into cross-file spshopkeeper state
  block, no local struct, raw-int launder from ->extra. No unit-local struct to attach.
- **dll_0107_unused / dll_026F_drgenerator / dll_00C9_enemy**: 1 raw cast each, shared/claimed.
CONCLUSION: the clean unit-local anonymous-pad recoveries appear harvested by prior cycles
(appleontree/tumbleweedbush/andross/treasurechest). Remaining raw casts are dominated by
#130 int-offset launders and shared-struct prefixes — both hard byte-changers/out-of-domain.

## SEMANTIC-RECOVERY world/gameplay-system sweep (2026-07-05, Opus) — 0 wins, all candidates disqualified
Swept world/gameplay/item/save DLLs for arrow-able raw casts over pad/unk runs. EVERY remaining
raw cast in this cluster hit a documented byte-changer or out-of-scope condition. Confirmed the
`int`-launder base form (`int extra=*(int*)&...; *(T*)(extra+off)`) is NON-neutral for arrow-respell.
All builds md5-restored to baseline; NO source edits committed.
  - dll_00E2 staff.c: `*(f32*)(state+0x98)`->progress and `*(u8**)(state+0x48)`->activeSlot in
    staff_update's hot swipe loop. TESTED both + progress-alone: baseline .o md5 f15d956b...,
    ANY arrow-respell -> f035cf.../2211e6... (bytes change). Load-bearing #130 launder in the
    hot loop despite `((StaffState*)state)->moveSpeed` arrow being used elsewhere in same fn.
    Reverted, md5 restored. DISQUALIFIED (hot-loop launder-sensitive).
  - dll_00EF pushable.c pushable_modelMtxFn: `*(u32*)(extra+0xa8)` r/w bitmask; padA8[4] is a
    clean u32-sized pad (named it modelMtxSetMask, tested). baseline 24f94a2c..., arrow-respell
    -> b2fe884b... NON-neutral because base is `int extra=*(int*)&obj->extra` (#130 int-launder).
    Reverted both .c + .h, md5 restored. DISQUALIFIED (int-launder base).
  - dll_00ED collectible.c line 721-723: `*(f32*)(state+0xb8/0xbc/0xc0)` px/py/pz collision-normal
    read. Offsets land INSIDE CollectibleState.pathState[0x50..0x2B0] — the opaque
    gPathControlInterface bounce/path blob (passed wholesale via state+0x50). Mid-blob field-carve
    is semantically wrong (foreign-interface blob). Left raw.
  - dll_0017 savegame.c line 893: `*(f32*)(base+0x684..0x691)` restart coords, but
    base=gSaveGameData+currentCharacter*16 (per-character INDEXED base, not a fixed struct offset).
    NOT a struct field. Left raw. (File also actively WIP this session; init-store block 380-402 is
    canonical-raw-setup + already partly fielded by owner.)
  - dll_023F dbegg / seqobj11d / dll_0190 ecshcup(fn_801C8B68): state=GroundBaddieState*, raw
    offsets (0x27a, 0x2a0/0x2a4/0x2f2/0x33a, 0xe/0x10/0x12) ALL inside SHARED BaddieState
    (baddie_state.h, boss/creature sibling domain) OR mathSinf/int-launder bob-rotation trap.
    Cross-file / disqualified.
  - dll_000B dll0b line 1336: `*(s16*)(state+0x46)` where state=gModgfxSpawnContextStorage+idx*2
    (pointer-walk INDUCTION). Disqualified.
  - dll_0104 smallbasket data[0x1c]/data[0x1e]: incoming placement-descriptor blob, no per-object
    struct covering these class-specific fields past ObjPlacement head. Left raw.
NOTE: a concurrent sibling agent has an in-progress edit to include/main/dll/sclevelcontrolstate_types.h
(pad18->gameBitLatches, SC/level-control cluster) present in the tree — NOT mine, left untouched.

## Struct-recovery session (env/terrain/water scope) — Jul05

- **dll_01C4 dimicewall** (6bd6ffb0c8): DimicewallState pad0[1] -> s8 hp at 0x0.
  Push-through hitpoint byte: init store from placement, decremented in
  fn_801B17F4, tested <=0 to trigger shatter. Respelled *(s8*)(inner+0) init,
  inner[0] decrement/compare (retyped local to DimicewallState*), *(s8*)extra
  test. .o md5 IDENTICAL 5ba2653648e7bba5ed724bab162d3619.
- **dll_0132 waterfallspray** (8a69b2c801): WaterFallSpray_update viewed extra
  as raw u32* and read state[0]/state[1]. Retyped local to WaterFallSprayState*,
  used named sfxIdA/sfxIdB. .o md5 IDENTICAL bbdc8156c877c85e4ef495f43a891dd5.
- **sclevelcontrol** (0701e32773): ScLevelControlState pad18[4] -> gameBitLatches[4]
  at 0x18 (matches sibling DfpLevelControlState.gameBitLatches[4]). HEADER-ONLY
  rename; .o md5 IDENTICAL 28228e6c18f8e981bfa0e34f65459a64. The `state + 0x18`
  int-arithmetic call sites to SCGameBitLatch_Update LEFT RAW — arrow-ifying the
  address computation `(int)&(...)->gameBitLatches` changed codegen (md5 differed),
  so reverted the .c respell. Load-bearing address-arith disqualifier.

## Field-naming session (ExplodableFragmentSetup color block)
- dll_015A_explodable: ExplodableFragmentSetup.unk04..unk07 (0x04-0x07 of the
  Obj_AllocObjectSetup buffer) -> colorR/colorG/colorB/colorA. These are the
  standard ObjPlacement RGBA tint block (color[0..3], see obj_placement.h and
  the 2/1/0xff/0xff color fill in matched snowclaw.c:225-228). Pure rename,
  .o md5-identical (5522cb665805b47772a10a5c4a50a910). Commit bb4944ea0d.
- Surveyed but left as unk (write-only-in-TU or opaque, no read site to pin
  meaning): EnemyState FP cluster (unk2FC/304/308/310/324/328/32C/330 all
  init-write-only), BackpackState (unk279/298/29A/29C message-payload trio),
  TreasureChestState (unk25F/270/349/405 init-only), CampfireState.unk270
  (read-only compare, shared BaddieState offset), CfDoorlightState
  (unk3E8/3EC write-only). CfperchState.unk0/unk2 pack into a player message
  (0x100010) but the packed value's role is unproven (angle vs force vs code)
  -- left as unk rather than guess.

## Field-naming (semantic-recovery) session — high-range sweep
- **snowclaw.c SnowClawBombSetup unk19 -> launchMode** (commit 4f3765307b): bomb
  launch/aim mode. snowclaw_spawnDropBomb writes param `b` into it then switches on
  (u8)b to select launchAngle (0=default drop angle, 1=aim at player). .o md5
  IDENTICAL (f8a2e0be71154081ddc771f182af0693 before+after). Full all_source EXIT=0.
- SWEPT dll_02xx+ unit-local structs; confirmed NO further justifiable renames remain:
  - AndrossState (dll_02BC): already exhaustively named; residual unk18/22/9A/B1/BD are
    pad-runs, unk20/23/43/44 are the foreign-object union overlay (deliberately opaque).
  - SnowBike{Mount,SetType}State (dll_0255): unk3D3 write-once-never-read; unk414 reset-to-0
    + read as ratio/sign but no local accumulator to justify a name; unk420 is on multi-owner
    SnowBikeState (out of one-owner scope).
  - HightopPlacement unk19 (dll_0272): placement flag forcing initial state index 0xa vs
    gamebit-driven 5/8 — real behavior but state-10 role not determinable, left opaque (a
    wrong name is worse than none).
  - GmmazewellState unk0, Dll200State unk14/18/1C, bossdrakor unk0C/16C/1C, tree unk1E:
    all write-only / never-read-locally, genuinely opaque.
  - dbstealerworm/dbegg/drakorenergy unk04/08 etc.: on multi-owner shared struct headers
    (4-5 owners) — skipped per one-owner rule.

## SEMANTIC-RECOVERY sweep — NPC/cutscene/minigame/scripting/trigger cluster (Jul05)
WIN (2 commits, both .o md5 IDENTICAL 02b053f5…):
- dll_0126_trigger.c: named TriggerPlacement fields typeId(0x0,s16),
  gameBitSrc(0x44,s16), gateBitSrc[4](0x48/4a/4c/4e,s16); respelled all raw
  *(s16*)(params/def/tbl +off) placement casts. Commits d841449a88, 704ecb3f02.
Surveyed, left RAW (disqualifiers):
- seqobj11e.c / seqobj11d.c / newseqobj.c: high-offset state casts (0x324-0x338)
  are the BaddieState 0x323-0x345 PER-FAMILY UNION (header explicitly warns "keep
  RAW spellings here" — narrow shared s16 stateTimer/cameraYaw/turnRate overlap the
  f32 timers/u16 angle these families use). def casts (0x1c/0x2a/0x2e) are the shared
  placement descriptor (ObjPlacement head + baddie-family extension) — sibling-owned
  baddie cluster, no unit-local placement struct to extend safely. Left raw.
- dll_0112_seqobject.c: already fully typed (SeqObjectState/SeqObjectPlacement); lone
  cast is a laundered narrow store.
- dll_0045_camTalk / dll_004D_cameramodenpcspeak / cutcam / dll_010E_deathseq /
  dll_0194_gpshscene: already typed or setup-store/float-const-launder disqualifiers.

## Semantic-recovery pass — SHOP/MAGIC/WARP/PICKUP/GATE cluster (Jul05)
WIN (committed f1610365): dll_00ED_collectible.c — respelled 5 raw
`*(u8*)((char*)((GameObject*)obj)->extra + 0x1d/0x1e)` accesses (func0F,
func0E, render2, launch-event x2) to already-named CollectibleState fields
bounceTimer(0x1D)/visibilityBitClear(0x1E). .o md5 IDENTICAL
c1c7639e195f316a8cdabea96bfec483. all_source EXIT=0, no FAILED.

DISQUALIFIED (left raw):
- dll_0106_scarab.c velocity writes `*(f32*)((int)obj + 0x24/0x28/0x2c)` ->
  anim.velocityX/Y/Z: TESTED, .o md5 CHANGED (4b53->44213c), REVERTED +
  restored to 4b53858638c406e123419198714ad0e0. The `(int)obj + N` int-cast
  base is a proven byte-changer (int-launder family). def+0x1a (mode) has no
  named ScarabSetup field.
- dll_00FF_magicgem.c: obj+0xc4 (ownerObj) is `(int)obj+N` int-base
  (magicgem_free takes obj as int); ref+0xb reads via heavily-reused `int ref`
  overload (setup/modelState/player/bounceCount) — int-launder/shared-reuse.
  model+0x34+8 = external texture accessor.
- dll_0284_shopitem.c: obj+0x37 int-base (fn_801E832C); lightningHandles+0x20,
  renderOp+0x43 = external object accessors.
- collectible state+0xb8/bc/c0 (bounce normal px/py/pz) fall inside the
  pathState[0x50..0x2B1] shared path blob — per-unit narrow view, left raw.

Cluster files with 0 raw casts (nothing to recover): warppad, spiritprize,
trickywarp, magicplant, warppoint, spshopkeeper, spscarab, spshop,
warpstoneui, magicmaker.

## Jul05 flat-dll sweep (semantic-recovery specialist)
WIN: dll_80136a40 (Tricky) TrickyImpressState — named 3 pad-run fields
(unk14 @0x14 f32, unk24 @0x24 u32, unk414 @0x414 s16); retyped 3 raw
`*(T*)(*(u8**)&extra+off)` getters (fn_80138F78/F84/F90) to typed
`((TrickyImpressState*)obj->extra)->field`. .o md5 IDENTICAL
62241db1f49fa9061db9a121013a5573. Commit a153d36412.

Flat DLLs surveyed w/ raw casts, left RAW (disqualifiers):
- dll_80174438 fn_80174588: `int data=*(int*)&...placementData; *(int*)(data+0x14)`
  = INT-LAUNDER base + placement-data (no named struct).
- dll_80198a00 L72/229: placementData+0x38 / data+0x14 = map placement-data,
  no named struct (MmpTriggerPlaneState is a diff struct = obj->extra).
- dll_801e991c fn_801E991C: `char* p=table; ...; p+=8` pointer-walk INDUCTION +
  char* param, no named struct.
- dll_801e66dc fn_801E66EC: `int state=(int)obj->extra; *(u8*)(state+0x9d6)` =
  INT-LAUNDER base; arg2 raw int param no struct.
- dll_80136a40 fn_80138D7C/Tricky_updateBlendChannelWeight: p2/state accesses at
  0x828/0x82c/0x82e/0x830/0x834 are PAST TrickyImpressState end (0x810) =
  different/larger struct, already macro-named.
- dll_801ac01c: vtable dispatch, not a struct-field target.

## Semantic-recovery (shared-struct field naming) session — 2026-07-05 — 0 wins (legitimate)
Surveyed every shared (2+ owner) struct with remaining unkNN fields. No field met the
bar of "identical clear role across ALL owners" for a pure rename. Findings:

- **LinkLevControlState.unk04** (5 owners, int, init -1): referenced by ONLY dll_0173
  (`state->unk04 = -1;`), write-only, no reads. Other 4 owners include header for size
  only. No role evidence. SKIP.
- **MagicLightState.unk10** (4 owners, s16, "301 at init"): referenced by ONLY dll_016B
  (`= 0x12d` twice), write-only, no reads. SKIP.
- **CfGuardianState.unk4..unk28** (real 2-owner: cfguardian + pressureswitchfb): primary
  owner cfguardian.c does NOT touch these; pressureswitchfb.c only zeroes all 10 at init,
  no reads. No role evidence. SKIP.
- **PartFxSpawnParams.unk0/2/4/6** (96 owners): already a UNION with rotX/rotY/rotZ and
  arg0..arg3 overlays — the slots are deliberately context-dependent per effect DLL
  (color/scale/alpha in effect8, textureId in effect7, rotation elsewhere). Role DISAGREES
  across owners by design. SKIP (union is the correct representation). unk24/unk2C: not
  referenced by field name anywhere (raw-offset only). SKIP.
- **FxNode9.unk0/2/4/6** (8 effect owners): s16 quad, either zeroed or bulk-copied from
  src[0..3] (boneparticleeffect). Raw 4-slot copy, no per-slot role. SKIP.
- **RomCurveWalker.unk04/unk14**, **BaddieState.unk304+** (per-family scratch, comment
  states 0x323+ is PER-FAMILY = differing semantics), **ObjModelChain/ObjModel/DfpSeqPoint/
  DfpLevelControl**: all remaining unks are opaque `u8 unkNN[...]` padding BLOCKS, not
  scalar fields — naming needs block reverse-engineering, out of scope for a pure rename.

- **FuelcellState.unkBit5** (dll_0123, unit-local bitfield) — suggested fallback, EVALUATED,
  LEFT UNNAMED. Semantics ARE coherent (latched by animEventCallback fuelcell_func0B
  alongside resetPos; gates a distinct burst color lbl_803E3CD0 vs _CD4; excludes cell from
  the lightning-link network both as seeker `!unkBit5` L279 and as candidate L290; selects
  spread scale _CEC vs _CF0). BUT the precise NAME is ambiguous: the anim event's identity
  is unknown and it co-latches resetPos, so thrown/loose vs detonating vs activated are all
  plausible and the source does not disambiguate. Per strict "unambiguous or leave it", LEFT.

No files edited, no commits. All candidate consumers were clean + old (>15min) at survey
time; no collisions encountered.

## Cycle: projectile/weapon/bomb combat-object cluster (3 wins, all .o md5 IDENTICAL)
- dll_0262_drakormissile.c (ce40fc5bdd): func0B — respelled *(f32*)((char*)from/target + 0xc/0x10/0x14) -> ((GameObject*)from/target)->anim.localPosX/Y/Z (from/target are int params holding GameObject*; anim@0). Kept int params, cast only.
- dll_01FC_laserbeam.c (1a6931804a): split LaserBeamPlacement.pad0 -> spawnYaw(s8@0x18), beamKind(u8@0x19), + firePeriod(s16@0x1c from pad1C). Respelled LaserBeam_free arg casts. Size/offsets unchanged.
- dll_00F2_iceblast.c (e8eddaea06): iceblast_update — respelled *(s16*)((char*)path + 0/2/4) -> ((GameObject*)path)->anim.rotX/rotY/rotZ (path=childObjs[0], GameObject*). Two sites.
- LEFT RAW (disqualified): weapone6.c TRICKY_STATE_* int-launder macros + shared TrickyState prefix; staff.c 60 casts int-launder base; drakormissile_init `arg` setup struct + laserbeam other setup — ObjPlacement 0x0-0x18 shared-prefix zone (drakormissile arg VEL bytes @0x18/19/1a not yet in a struct). blasted e/g/p = map_block (already named).

## Jul05 semantic-recovery sweep (BACKGROUND/HUD-TEXT/CAMERA-CURVE/LIGHTING scope)
- WIN gametext.c (e124acc83c): typed 3 text-box locals (gameTextShowStr,
  gameTextBoxFn_800164b0, gameTextMeasureFn_800163c4) from raw `u8* = &gTextBoxes[box*0x20]`
  + `*(s16*)(box+0x18/0x1a)` to `TextSlot* = (TextSlot*)gTextBoxes + box` with `->f18`/`->f1a`.
  TextSlot (engine_shared.h, sizeof 0x20, f18/f1a already named) already used this way at
  gametext.c:593. .o md5 IDENTICAL (50d86e38c715bd874d2fd00633edd941). Header untouched.
- LEFT RAW (disqualifiers):
  - sky.c: gSkyState (200+ raw casts, SkyState fully mapped but base is u8* global — too
    large/risky for a byte-neutral single win); gSky2State offsets 0x30c/0x316/0x317 EXCEED
    both SkyState(0x258) and Sky2Config(0x5E) -> ambiguous large blob, not either named struct;
    lbl_803DD19C yet another blob global. Base-identity uncertain -> speculative, skip.
  - modellight.c: `light` local read as `*(u32*)(light+0xa8)` (u8[4] diffuseColor read as
    single u32) + `light+0x68` passed to GXInitLight* as raw GXLightObj subobject -> can't
    cleanly retype to ModelLightStruct*.
  - textrender.c boxDrawFn_8001c5ac: `p+0x14/0x16/0x8/0xa` map to TextSlot f14/f16/f08/f0a
    BUT `p+0x1e` alpha is unnamed (inside pad1c[0x1c-0x1f]); naming it = SHARED engine_shared.h
    change requiring cross-unit reverify. Left raw.
  - newshadows.c: texture/GX-buffer + global-manager structs (offsets 0x44/0x60, g+0x3a10) —
    hardware/allocator objects, no unit-local FooState.
  - newclouds.c: `env` base mixes fixed offsets with computed-indexed `p14+idx*0xc` walks
    (pointer-walk disqualifier). params already CloudSpawnParams* at call sites.
  - lightmap.c FUN_/DAT_ fns: `object`/`settings` are raw int/u32* shared engine structs,
    still Ghidra-named/unmatched -> speculative shared, skip.
  - light.c: `state` locals already fully typed; `data+0xNN` reads are the SHARED ObjPlacement
    setup-descriptor (0x18/0x19/0x1a/0x1c/0x1e/0x20) -> shared-prefix disqualifier.
  - dfplightni.c / curves.c / textblock.c / worldplanet_lighting.c / crcloudrace.c: no raw
    base+offset casts (already clean or no state structs).

## Sound-emitter cluster sweep (2026-07-05, semantic-recovery)
WIN: dll_012D_lfxemitter (commit 08d73c8171) — named LfxEmitterConfig.recordCount
(u16 @0x0E, split from pad0E) + retyped global lbl_803AC7B0 from u8[] to
LfxEmitterConfig; respelled *(s16*)/*(u16*)(lbl_803AC7B0+0xe) accesses and the two
(u16*)lbl_803AC7B0 -> (u16*)&lbl_803AC7B0 fn_8018FF48 args. .o md5 IDENTICAL
6d44b5318aef66d19da8b31dd77a5243. all_source EXIT=0, no lfxemitter FAILED.
LEFT RAW (disqualified):
- dll_012B_fxemit / dll_0130_areafxemit: only raw casts are resource-vtable dispatch
  ((void(**)(...))(*(int*)resource+4)) — function-pointer calls, not fields.
- dll_0133_sfxplayer: data local is a u8* PARAM blob (anim.placementData); accesses at
  0x18/0x1a/0x1c/0x1d/0x1e/0x1f/0x20/0x22 are type-specific placement tail but no
  placement struct exists and sfxplayerObj_init(u8*,u8*) is referenced as a fn-pointer
  in gSfxPlayerObjDescriptor across ~4 units — param-blob, byte-changer, left raw.
- lfxemitter fn_8018FF48 config-copy: mixed u16*/(int)+odd addressing, byte-sensitive,
  left raw (retyping to struct-copy would shift bytes).
- seqobj11d/e, newseqobj: state is GroundBaddieState* shared-prefix (0x2f2/0x33a/0x2a0
  in baddie blob) — shared-prefix disqualifier.
- seqobject/seqobj2/feseqobject/deathseq: 0 raw scalar casts, already fully typed.

## Semantic-recovery cycle (GameObject anim-field respell) — Jul05
Hunt: raw `*(f32*)((char*)base + 0xc/0x10/0x14)` / `*(s16*)(...+0/2/4)` where base is a GameObject*
-> `((GameObject*)base)->anim.localPos*/rot*/worldPos*/velocity*`. md5-gated per site.
COMMITTED (5, all .o md5 byte-identical):
- 897098f714 dll_0138 groundanimator: `target` localPosX/Y/Z (setScale distance check)
- 69f5691da1 dll_02BC andross: `spawned` effectHandle localPosZ (fn_8023A87C)
- 404481c213 objprint: `target` localPosX/Z (fn_8003B0D0 getAngle)
- 7a7ef0cdee dll_000B dll0b: `sourceObject` worldPos(0x18/1c/20)+rootMotionScale(8)+rot(0/2/4)+velocity(24/28/2c)
- 61367046c2 player: `p3` rotX/rotY/rotZ (fn_802A9D0C)
SKIPPED (base is NOT a GameObject — offset/type mismatch): newshadows `cam` (view slot pos,
not anim); objprint `p`/`p2` sfx-pitch state (u8@0, f32@4 != anim layout), `curve` (0x4/0xc
!= X/Z pair), `model` (joint matrix), `dstB` (Mtx); snowbike `found` (RomListItem);
track_dolphin `out` (transform struct w/ 0x3c/0x40 writes). player `sub`/`inner` = substate.

## 2026-07-05 SEMANTIC-RECOVERY sweep — NO qualifying target found

Ranked all src/main + src/main/dll .c by raw fixed-offset cast density; verified base
struct mapping + disqualifiers + collisions. Every rich file is excluded:

TOP src/main by raw base+offset cast count:
  shader/track_dolphin/objprint_dolphin/pi_dolphin/rcp_dolphin/tex_dolphin = SDK/GX
    blobs, unmapped base (out of scope).
  objprint.c(291) = ACTIVE OWNER (committed 53s before sweep) — collision, skip.
  model.c(280) sky.c(218 sibling-owned) = engine/owned.
  object.c(96) objseq.c(181-form) = actively fine-tuned <16h; remaining casts on
    u8* byte-index/induction bases (buf/cmd/model/base) not clean mapped structs.
  newclouds.c(61): CloudSpawnParams + NewCloud FULLY mapped, BUT all remaining raw
    params/env casts live in newclouds_update where in-file comments (L1844-1851)
    already document params-raw + env-retype-shifts-codegen as byte-changers. The
    tractable newClouds() body is already typed. Nothing left.
  light.c(16): `data` is an INT param (int-launder base) + offsets 0x19/0x1c/0x1e/0x20
    = ObjPlacement shared prefix. Double-disqualified.
  worldplanet.c(14): seg/nseg route recs + p vertex-writes (+6/+8/+10 short-index
    induction). Small + induction forms. Not rich/clean.
  newshadows.c(122)/lightmap.c(106): bases g/t/h/q/mb = GX/render blobs, unmapped.

TOP src/main/dll by raw base+offset cast count:
  dll_000B_dll0b = ACTIVE OWNER (committed 3min before sweep) — collision, skip.
  player.c(76) = heavily owned (extensive player.c work in MEMORY.md).
  magicplant(52 state) newseqobj(49) seqobj11d(37) dll_00E1_wispbaddie(35)
  seqobj11e(22): ALL BaddieState* `state` bases whose remaining raw offsets
    (0x324/0x328/0x32c/0x330/0x334/0x338/0x33c) sit squarely in the per-family
    scratch UNION 0x323-0x345 (explicit disqualifier; baddie_state.h L98-110 marks
    them "left raw"). Offsets 0x2f1-0x2f4 = eventFlags/core shared prefix. WispBaddieState
    dedicated `->extra` struct is already respelled; the raw casts are on the shared
    BaddieState body only. The 0x2a0/0x2b6/0x308/0x310 outliers = mediumbasket
    whirlpool 0x2A8..0x33B block = per-unit NARROW view of shared wider field (disq).

CONCLUSION: the byte-neutral struct-recovery frontier for rich single-file targets is
EXHAUSTED for this cycle. Prior sweeps consumed the dedicated per-subclass `->extra`
structs; the residual raw-cast density is concentrated in (a) SDK/GX blobs, (b) shared
BaddieState/ObjPlacement/GameObject-core prefixes + per-family union, and (c) int-launder
/ induction / narrow-view disqualifiers. No commits made — no qualifying batch existed.

## Jul05 struct-recovery: sky.c ABORT (exhausted) -> newclouds.c (1 commit)
- **sky.c**: ABORTED as work target. Committed & fully picked-over by prior agents
  (106 SkyState*/SkyBlendStateFlags* casts already named). Remaining 196 raw casts
  ALL disqualified: (a) ~139 gSky2State/s/state/st = large blob EXCEEDING Sky2Config
  (offsets 0x254/0x280/0x30c/0x314) -> ambiguous base, leave raw; (b) ~147 gSkyState
  index-scaled (slot*0xa4 / iofs / idx=i+N / offset / bit / cb / base) -> the 0xA4-stride
  light overlay indexes from gSkyState+0, NOT aligned to lights[]@0x20, so no
  byte-neutral respell without base recompute. ZERO plain-const gSkyState casts left.
- **PIVOT -> newclouds.c** (next clean file: last touch was a data fill Jul4 20:03,
  no struct agent active; track_dolphin/shader/maketex all touched ~8h ago, model.c
  is a delicate active-match file).
  - COMMIT d15ede66ef: newclouds_update, add `CloudSpawnParams* cfg=(CloudSpawnParams*)params;`
    typed-view local; respelled 7 independent u16 reads at 0x24/0x2a/0x2c ->
    cfg->windCount / fillDivisor / drainDivisor. .o md5 IDENTICAL 3e8be9dd...
    (both before batch and after final revert). all_source EXIT=0, 0 FAILED.
  - BANKED (byte-changer, bisected+confirmed): the ~25 `*(u16*)(params+0x26)` reads
    (cloudIndex) are a HEAVY shared-CSE web feeding the NC_CLOUD macro (raw params+0x26),
    the switch selector, env[..+0x41] indexing, and p14/p18/p1c*0xc scaling. Respelling
    non-macro sites to cfg->cloudIndex dual-spells the CSE value vs the macro -> md5
    be836f8f... (CHANGED). params MUST stay raw u8* here (matches prior agent's note
    at newclouds.c:1843). env (saveGameGetEnvState cross-TU blob, no shared header)
    also left raw. newclouds.c now exhausted for byte-neutral respells.

## struct-recovery pass 2 (expanded offset map) — seqId/seqIndex cluster
GameObject offset map built from include/main/game_object.h + objanim_internal.h.
Expanded beyond first-pass (rot/rootMotionScale/localPos/worldPos/velocity).
Landed 6 byte-neutral (.o md5-identical) respells, all anim.seqId (0x46, s16) /
GameObject.seqIndex (0xb4, s16) field reads, one commit per file:
  - dll_0019_dll19func0 (07529757fc): *(s16*)((char*)p+0x46) -> ((GameObject*)p)->anim.seqId
  - DIM/dll_00C7_dim2roofrub (5c9658904a): *(s16*)((char*)match+0xb4) -> ->seqIndex (r/w)
  - dll_01AA_bombplantspore (a69587c0bf): hitObj+0x46 -> ->anim.seqId
  - DIM/dll_01C7_dimlavasmash (03b86dfa42): hit+0x46 -> ->anim.seqId (int hit -> (GameObject*) cast neutral)
  - dll_01CE_dll1ce (5044f6b11e): o+0x46 x2 -> ->anim.seqId
  - dll_016C_dll16c (eeb6077fe3): objs[i]+0x46 -> ((GameObject*)objs[i])->anim.seqId
NOTE: direct (GameObject*)intVar pointer-cast at a KNOWN-pointer value is byte-neutral;
this is distinct from the DISQUALIFIED int-launder `int b=*(int*)&x->extra;*(T*)(b+off)`.
EXHAUSTED in DLLs (excl skiplist): no more clean GameObject-base scalar raw derefs at
classId(0x44)/defId(0x48)/parent(0x30)/objectFlags(0xb0)/currentMove(0xa0)/hitboxScale(0xa8)/alpha(0x36).
Remaining 0x46/0x44/0xb0-shaped hits in model.c/object.c have NON-GameObject bases
(ObjAnimState channel/stk, ModelFileHeader hdr, def/tmpl) = correctly disqualified.
0x68(dll)/0x58(weaponDaTable) vtable-chain sites are ptr-chain calls, not field respells.

## PROBE Jul05 — GX/SDK-struct raw-cast pool: 0-WIN WALL (pool unreachable)
Goal: respell raw `*(T*)(base+0xNN)` → `((GXStruct*)base)->field` byte-neutrally where
base is a DEFINED dolphin-SDK struct (GXColor/GXLightObj/GXTexObj/GXTexRegion/Mtx/Vec/S16Vec).
VERDICT: **pool does not exist for non-foreign engine files.** No commits, no edits.

Classification of the GX-heavy pool (per src/main/*.c commit-age × cast × gx density):
- FOREIGN (Ghidra FUN_/DAT_ or *_dolphin.c SDK reimpl) → ABORT cond 1:
  track_dolphin.c, rcp_dolphin.c, pi_dolphin.c (gx=808), tex_dolphin.c, objprint_dolphin.c,
  and newshadows.c (190 FUN_/121 DAT_ + tuned 13h).
- HOT / match-tuned <24h → ABORT cond 2: shader.c (8h), model.c (22h), objprint.c (0h),
  sky.c (23h), lightmap.c (15h), light.c (10h), modellight.c (34h), maketex.c (10h, save-buf not GX).
- ACTIVE OWNER (uncommitted-recent, sibling agent) → ABORT cond 4: newclouds.c (2min),
  snowclaw.c (22min).

DECISIVE NEGATIVE EVIDENCE (why the pool is empty even ignoring hotness):
1. `grep -rnE '\b(GXTexObj|GXLightObj|GXColor|GXTexRegion|GXTexObjLOD)\b' src/main/*.c | grep -v dolphin`
   = ZERO hits. Non-dolphin engine NEVER declares an SDK GX struct type. GX objects are
   opaque: created as typed locals/globals, passed to GX fns by pointer, never reached into
   by raw offset. There is no `*(T*)(gxTexObjBase+off)` to respell.
2. Mtx/Vec typed locals appear ≤1×/file in engine — used opaquely, never raw-cast into.
3. Every `*(f32*)(base+off)` / `*(u8*)(base+off)` site sampled targets a GAME-INTERNAL
   struct (map-block descriptor obj+3/4/5, sky-state blob gSkyState+bit*0xa4+0xa8 [index-scaled,
   disqualified], shader entry, jointMtx, blendChan, prevSphere, ObjAnimState stk) — NOT an SDK
   struct. These bases are the OBJANIM/GameObject/shader-descriptor pools already worked
   elsewhere, and here they sit in HOT tuned files.
CONCLUSION: the "GX/SDK-struct" pool as framed is a null set — the SDK structs are opaque to
the engine, and the only raw casts present are game-struct casts in hot files. NOT reachable
for byte-neutral SDK-struct recovery. Do not re-probe under the SDK-struct framing.

## Cycle Jul05 (data-split fresh-vein sweep)
- WIN dll_013D_explodeanimator (4e53c86bb9): explodeanimator_init raw `*(s16*)((char*)def + 50)`
  -> `((ExplodeanimatorPlacement*)def)->resultGameBit` (0x32, s16). Struct already declared in-file;
  the update fn used typed derefs, init lagged. .o md5 IDENTICAL 0043c73d7fe15b925b0f0a21c68c413c. build EXIT=0.
- Data-split "linked/complete" batch (81min-2h ago) checked: sbshipmast, ccqueen, cameramodeperv,
  dll_0219, texscroll, staticcamera, vfpladders, skeetlawall, attractor, lightsource, animsharpclaw,
  dll_0127, dimtricky = NO raw offset casts (already clean / sdata2-only splits).
- LEFT RAW (disqualified): animsharpclaw:118 fn-ptr vtable call; animsharpclaw:168 `*(int**)&...->extra + 0x57`
  INT-LAUNDER base. The 3-min-ago anim.seqId sweep files (dll16c, dll1ce, dimlavasmash, bombplantspore,
  dim2roofrub, dll19func0) are actively owned by sibling struct agents (uncommitted/just-committed) — skipped per one-owner rule.

## Jul05 largest-fn 90-97% O4,p deep-dive (fuzzy-structural specialist) — 0 wins, all banked caps
Ranked default-O4,p main-lib fns 90-97% by size DESC (excluded: audio 1.2.5n noopt, *_dolphin
Ghidra-named+sibling-hot track_dolphin[154 FUN_/DAT_,committed 04:13], player/render/shader/gametext/
newshadows/dll_0014/animobjd2 = cflags_dll_noopt). All triaged fns are within-class coloring caps,
NO structural seed (no missing branch / wrong struct access / misshaped loop):
- **drawGlow** (dll_000A_expgfx, 0xba8, 95.03%): 88 reg-perm + 12 fcmpo-swap. Seed = poolIndex(r4
  param)/counter saved-reg TRANSPOSITION at entry (r15/r22 vs r22/r15); both _savegpr same count.
  Uniform #108 whole-web + #82 FP-perm cascade. BANK.
- **expgfx_addremove** (0xa10, 95.84%): 57 reg-perm + 7 deref-via-copy. Target _savegpr_22 (10 saved
  GPRs) vs current _savegpr_23 (9) — target keeps `attachedSource`(config->attachedSource, line 3026)
  in a SAVED reg r29; current in volatile r6. attachedSource has NO call in its live range (loaded 3026,
  last-used 3058, NULL'd 3060) so saving it is a pure allocator preference = #67d spill-vs-keep. The 7
  deref-via-copy are all r29-vs-r6 renumber of the SAME load structure, not a real missing hoist. BANK.
- **gameTextRun** (textrender, 0x5e0, 95.15%): 27 reg-perm + 4 ext-delete + 2 ext-insert. Both
  _savegpr_26. Seed = `cmd`(GameTextSlot* first decl) colored r27(T) vs r29(C); the ext-delete/insert
  are byproducts of load SCHEDULING (target batches switch-case arg loads DESCENDING off r27, current
  ASCENDING off r29). TRIED: reorder case-3 temp decls c3/c2/c1 descending (95.154->95.133, WORSE — decl
  order does NOT flip the batch-load order, scheduler-driven). Within-class #108. BANK.
- **renderSceneGeometry** (lightmap, 0x4ec, 96.67%): 12 reg-perm + 6 li-const. Both _savegpr_17. Seed =
  `p` walker r6(T)/r8(C) + `1` store-const r5(T)/r6(C) in the 4 box-fill loops (2134-2169); box[N][0]/[1]
  load order + reg assign differs per unroll copy. gLightmapU32ToDoubleBias @132 reloc = #70 neutral.
  Within-class coloring cascade. BANK.
- **objFreeObjDef** (object, 0x4e4, 96.87%): 50 reg-perm — pure coloring cascade, no structural. BANK.
- **expgfxGetSlot** (dll_000A, 0x318, 94.49%): 37 reg-perm + 1 ext-insert(inside reg-renumber block) +
  1 sched-order. slw/and web renumber. Within-class. BANK.
- gameTextLoadGraphicsFn(0x44c,96.66% 13rp+2mr-copy), gameTextInitFn(0x3a8,93.38%, committed 19hr) =
  base-reg web + copy-prop renumbers, within-class. BANK.
Tree left CLEAN (textrender case-3 experiment Edit-reverted, rebuilt, gameTextRun back to 95.154). No
commits. All main-lib O4,p large-fn residual in this band is coloring/spill-vs-keep with no source lever.


## SESSION Jul05 (fuzzy-scan, post-45min team commits) — 0 wins, 12 candidates triaged, all banked caps
Method: private proto report, decoded per-fn fuzzy (float32-LE f3 under unit f2/f4). Ranked 96-99.4%
O4,p (skipped MSL/audio/dolphin-noopt-O0; dll_noopt units ARE valid targets = O4,p + peephole/sched off).
Scanned ALL 308 candidates for instruction-COUNT mismatches (tools/ndiff.py, note: macOS has NO `timeout`).
109 count-mismatches found; triaged the cleanest (fewest-region) fresh ones. EVERY structural seed = banked class:
  - dll_02BB_gflevelcon fn_8023A3E4 (99.35, T=179 C=180): the `hp[0xAE] -= 1` reloads the byte the
    `hp[0xAE]!=0` test already loaded; target CSEs into r3 (`lbz r3;...;addi r0,r3,-1;stb`). Temp forces
    the CSE (u32 hpHits gives cmplwi-match) BUT adds a `clrlwi` store-mask -> net 99.35->99.20 REGRESS.
    CSE-vs-mask trade nets negative. BANK.
  - track_dolphin hitDetectFn_800658a4 + fn_80065768 (98.31/98.61, 1-region): `if(cur>=0){}else{cur=-cur}`
    abs-guard. Target keeps unfolded `cror;bne;b` island; mine folds to `beq`. Rewriting as ternary
    (matches the SECOND occurrence's bne;b) REGRESSED 98.31->96.85 (ternary refolds the fneg into f2,
    diverges more). Empty-then/else branch-island fold = BANK (same as #pollen below).
  - dll_00D9_pollen fn_8016A660 (98.x, 1-region): `if(Obj_IsLoadingLocked()==0)return;` -> target
    `cror;bne;b` unfolded guard, mine `beq`. Tried ==0-return, !=0-empty-then-else, goto-ok: ALL fold
    to beq. MWCC branch-simplify collapses every spelling. BANK (empty-guard fold).
  - dll_014C_babycloudrunner sandworm_turnTowardTargetAnim (98.86, T=101 C=102): ONE spurious `extsh r0,r0`
    between `add` and `sth` on `*(s16*)a += (shifted>>=3)`. s16/u16/un-compound all keep a narrow (extsh
    or clrlwi). Removing the fn's local `#pragma peephole off` DROPS the extsh but peephole-ON refolds a
    DIFFERENT abs (`srawi;b;neg;srawi` -> 1 srawi) elsewhere: 98.86->93.52 REGRESS. Coupled peephole. BANK.
  - dll_0017_savegame saveGame_saveObjectPos (98.62, T=95 C=96): store block `(gSaveGameData+OFFSET)[i]`
    computes base+i*16+360 (+1 addi) vs target base+i*16 disp 360. Rewriting stores as
    `((SaveGameImage*)gSaveGameData)->positions[i]` MATCHES count (C=95) BUT reorders slwi/reg (r5/r6) ->
    98.62->97.61 REGRESS. count-parity != gain. BANK.
  - shader mapGetRomListAndOffsets (99.24, T=175 C=174): `(p1*7)*4` folds to `mulli *28`; target keeps
    `mulli r7,*7; slwi r31,r7,2` split (r7 live across a load). `(p1*7)<<2` matches count BUT lands in
    r0 back-to-back not r7-across-load -> 99.24->98.49 REGRESS. scheduling/liveness, no lever. BANK.
  - pi_dolphin loadDataFiles (T=107 C=105): empty `do{}while(++vi<0x57)` -> target strength-reduces to
    `subfic 87-i; mtctr; bdnz`; mine keeps `addi;cmpwi;blt`. `for` form DELETES the loop entirely (worse).
    do/while is closest; CTR-conversion is loop-optimizer artifact, no source lever. BANK.
  - r0-detour named-.data-ptr (BANK-on-sight, confirmed 4x): voxmaps_resetLoadedMaps (gVoxMaps),
    pad initControllers (gPadStateBlock), objprint renderOpMatrix (gObjGxPosMtxIdTable), seqobj11d
    fn_8015165C (lbl_8031F16C). All `addi r0,r3,0; mr rSaved,r0` vs target `addi rSaved,r3,0`.
  - track fn_80061DD8 (#110 shared-zero): target `li r0,0;sth r0` fresh zero vs mine reuse r4. BANK.
  - object fn_8002B758 (T=72 C=73): ×8 unrolled shift-copy loop; my unroll ~identical, 1-instr tail
    re-entry delta (#108/#113). mm mmAllocateFromFBMemoryStore (T=67 C=66): param-stage extra `mr r5,r4`
    + web transpose. modellight modelLightStruct_freeSlot (97.6): pure r5/r6 counter/limit #108, decl
    swap inert. wispbaddie fn_8014FFB4: `&~0x40` -> mine rlwinm(1) vs target li -65;and(2); literal
    0xFFFFFFBF still folds to rlwinm; broad byte-arg web perm besides. BANK.
Tree left CLEAN — every experiment Edit-reverted + rebuilt to baseline, no commits. NOTE: dll_00F7_dllf7.c
and this file showed concurrent-agent edits during my session (NOT mine; left untouched). gametext.c
(M at session start) also another owner. TOOLING: macOS `timeout` absent -> strip from scan scripts.

## Struct-recovery consistency-gap sweep (Jul05)
- WIN dll_00F7_dllf7 (commit 9d194c04a8): dll_F7_init read placement mapEventId via
  raw `*(int*)((char*)params + 0x14)` while siblings pass `((DllF7Placement*)params)->mapEventId`
  to the SAME shouldNotSaveTime interface call. Typed the holdout (s32 @0x14). .o md5 IDENTICAL.
- BANKED byte-changers (reverted, md5 restored):
  - dll_0272_hightop 0x314: eventFlags is u32 in BaddieState but raw is `*(int*)` (signed)
    assigned to `int flags`; typed `((BaddieState*)state)->eventFlags` changes bytes (u32->int
    conversion at the narrow site). Sign/type mismatch is load-bearing. Kept raw.
  - dll_00C6_animatedobj 0x57: `*(s8*)((char*)seq+0x57)` = seq->slot; sibling types a DIFFERENT
    ptr `(s8)otherSeq->slot`. Typing this holdout (s8)seq->slot changed bytes (fresh-deref
    coloring differs). Kept raw.
- DISQUALIFIED (no clean gap): drcloudrunner/hightop 0x334/0x338 (BaddieState per-family raw
  scratch, header comment says keep raw); snowbike found+0x8/0xc/0x10/0x29 (void* from
  mapRomListFindItem, no typed sibling); dim2conveyor/seqobj11e def+0x1a.. (past ObjPlacement
  0x18 end); crrockfall params+0x1e (pad1E unnamed); visanimator desc+0x1B (high byte of
  originY s16, not a distinct field); fireball params+0x19 (high byte of unk18 s16);
  front box+0x16 (void* gameTextGetBox, no typed sibling); msplantings sub+0xc (placement
  posX, but sub not typed); obj+0x37/0x34 across gpshobjcreator/dfshobjcreator/dll19a/ecshcup/
  sbgalleon (unnamed GameObject pad past alpha@0x36); dimexplosion state+0x14 (inside flames[]
  array); tumbleweedbush trickyState+0x728 (unnamed); dll16c SKIPPED (team-touched 11min).

## STATE-descriptor (obj->extra) typed-respell sweep (2026-07-05, Opus) — 0 neutral, 2 tested+reverted
Hunted the intra-file consistency gap where a sibling types `((FooState*)state)->field` while a
holdout reads the same base raw. Swept every `obj->extra`-based raw cast in the repo. RESULT: 0
byte-neutral respells found; the state partition is dominated by disqualifiers, exactly as briefed.
TESTED + REVERTED (md5 restored, confirmed byte-changers):
- **dll_0272_hightop.c** hightop_playMovementSfx `*(int*)((char*)state+0x314)` (2 sites) ->
  `((BaddieState*)state)->eventFlags`. eventFlags is `u32` at 0x314; raw form reads it as signed
  `int` (keeps `cmpwi` on the `& 0x81`/`&1`/`&0x80` mask-compares). Typed u32 flips to `cmplwi`;
  `int flags`, `u32 flags` BOTH change md5 (d0932c9d... base). Width/sign-vs-compare hazard. REVERTED.
- **drhightop.c** line 562 `st->yaw = *(s16*)((char*)st+0x40e) + yawDelta` -> `st->yaw = st->yaw +...`.
  st is already `SnowBikeState*`; 0x40e IS the `yaw` field (self read+write). Arrow form re-derefs
  differently, md5 changes (5b0f286e... base). REVERTED.
DISQUALIFIED without building (all state descriptors, all briefed traps):
- BaddieState UNNAMED per-family scratch region (0x278, 0x323-0x345, 0x334/0x338/0x33C/0x344/0x34C):
  dll_000F_unk (0x2bc/0x33c/0x344/0x34c pad regions), DIM/dll_0256_dimsnowhorn1 (0x334/0x338 baddie
  scratch), DR/dll_0257_drearthwarrior (0x278 setup-store, unnamed), dll_00C9_enemy (0x323 union),
  newseqobj (0x328/0x32c/0x330/0x338 SeqRow16 walker scratch, code-commented file-local), dll_0272
  p+0x334/0x338. No named field exists at these offsets — nothing to respell to.
- INT-LAUNDER base: DIM/dll_01CA_dimexplosion (`state = *(int*)&obj->extra`; `ang[3]=*(int*)(state+0x14)`
  bit-copy of velZ f32 into int array — the #1 false-hope trap).
- CODE-DOCUMENTED intentional raw: drcloudcage (state+0x34/0x44 CheckpointRankItem, comment says
  "stay raw: shifts codegen"), dll_000F eventFlags int-launder form already in-file.
- DIFFERENT alias / not obj->extra: dll_018F_ecshshrine (raw base is `int* state`=obj->extra but
  typed sibling uses `MmShrineAnimState* = obj->state` — different field, offset 0x20 in pad04),
  objprint_dolphin (getCurCharPos, not a state), lightmap (pointer-walk induction), sky (SkyState
  singleton index-scaled), mmsh_waterspike (0x40C reads a pointer, no typed sibling on `state`),
  dll_0019 (placementData, PLACEMENT partition).
player.c and bombplantspore SKIPPED (concurrent owners, touched <30min). No commits this cycle.

## SEMANTIC-RECOVERY vein-mine pass (2026-07-05, Opus) — 0 wins, fresh team units already recovered
Mined the 4 fresh TEAM data-split/linked-complete commits at 18:26 UTC (all others in the 90-min
window were struct-recovery/field-naming = OURS, skipped):
- dll_01EB_sbshipmast.c — only cast is `((GameObject*)obj->anim.parent)->anim.seqId` = named field.
- dll_0187_ccqueen.c — all casts to named GameObject anim/objectFlags fields. Remaining raw-ish:
  `placement[0x1a]` (bare u8* byte-INDEX, no mapped ccqueen-placement struct — index-scaled DISQ);
  `charState + 0x624` (opaque `extra` blob size 0x654, base-pointer PASS to dll_2E_* helper, no
  mapped state struct — not a field deref). Both correctly left raw.
- dll_0055_cameramodeperv.c — `(GameObject*)camera->anim.targetObj` then named anim.worldPosY fields.
- dll_0219.c — fully typed: Dll219Setup* placement / Dll219State* state, named fields throughout.
VERDICT: all 4 fresh units already fully struct-recovered against mapped GameObject / typed
Setup/State structs. No raw fixed-offset cast against a mapped struct exists. Legitimate 0-win pass;
no edits, no commits, working tree unchanged (only this md appended).

## FUZZY 97-99.5 band pass (Jul05, small-fn structural-seed hunt) — 0 wins, all banked caps
Triaged ~20 -O4,p fns in 97.0-99.5% / size 0x100-0x400. Two had REAL structural seeds
that fixed the target shape but REGRESSED net fuzzy (coupled trades — the structural fix
triggers a bigger register/schedule cascade). Everything else = known banked classes.

STRUCTURAL-SEED-BUT-COUPLED (fix worked, fuzzy dropped — reverted):
- gameloop.c GameBit_Set 98.547: loop `end=mask+start; for(i<=end)` → target materializes
  `end+1` once, uses for count AND guard (bge). Rewriting `end=(mask+start)+1; for(i<end)`
  MATCHED the subf/bge/count shape (7→5 regions) BUT MWCC reassociates `+1` to `(mask+1)+start`
  AND the flags-web r4/r5 perm costs more bytes → 98.547→97.906. `end++` split → 12 regions.
  Coupled. Remaining baseline deficit = #108 flags-web r4↔r5 perm. BANKED.
- dll_0017_savegame.c saveGame_saveObjectPos 98.622: store block `((SGObjPos*)(base+0x168))[i].f`
  pushes 0x168 onto ptr (`addi r4,360; stw 0(r4)`). Respelling to `((SaveGameImage*)base)->positions[i].f`
  FOLDED 360 into store disp (`stw r5,360(r4)`, 5→2 regions) BUT MWCC hoists `slwi i*4` early →
  objectId load shifts r5→r6, register cascade → 98.622→97.611. Hoisting objectId into `v` first =
  inert (copy-prop). Coupled. BANKED.

BANKED-ON-SIGHT (no source lever, confirmed this pass):
- shader.c mapGetRomListAndOffsets 99.237: `(p1*7)*4` folds to `mulli *28` (matches target r31 dest).
  `<<2` or split-decl UNFOLDS to target's `mulli;slwi r31,r7,2` shape (instr-count matches 175) BUT
  intermediate `p1*7` lands r0-scratch vs target r7 → cascade → 98.489. Baseline `*28` scores HIGHER.
  r7-vs-r0 temp = pure allocator choice, no lever. BANKED.
- model.c ObjModel_Load 99.200 + shader.c mapLoadBlock 99.153: IDENTICAL #110 copy-prop shared-zero.
  Source `i=0; byteOff=i` → target keeps `mr byteOff,i` (copy 0), MWCC copy-props to `li byteOff,0`.
  i provably 0 so copy always folds. No per-fn copy-prop toggle. Single-instr cap. BANKED.
- textrender.c gameTextLoadForCurMap 98.772: 2-region pure scheduler code-motion — target computes
  `request = base+i*40` (mulli;add) LATE (right before its store); MWCC hoists it above preceding
  do-while. Register-neutral (205=205). Inlining the assign into the store regressed (r3/r4 perm).
  Scheduler artifact. BANKED.
- #108 whole-web reg-perm (no seed): object.c Obj_UpdateModelBlendStates 99.065 (walker r30↔r26 +
  #110 mr r31,r28 vs li), worldplanet.c worldplanet_init 98.750, dll_02B5_timer timer_update 99.103,
  dll_0158_gunpowderbarrel triggerExplosion 98.644 (def/i r26↔r29; decl-reorder inert, typed def
  regressed 98.475), dll_0014_unk RomCurve_getAdjacentWindow/func16/getRandomLinkedOfTypes,
  dll_02B3_vortex vortex_init, dll_00C6_animatedobj animatedobj_update, WaterFallSpray_update,
  dll_0000_gameui ObjGroup_AddObject 99.456 (r7↔r8, already in MEMORY).
- bias-double `@N`-vs-named sdata2 (#70 score-neutral) + FP/reg-perm: newshadows shadowCreate 98.924
  (rsqrt refinement f2/f3/f4 #82), dll_0000_gameui boxDrawFn_8012975c, dll_0040_credits Credits_frameStart,
  camera viewportEffectFn_8000e380, lightmap updateEnvironment, dll_0014_unk Objfsa_GetPatchGroupIdAtPoint.
- r0-detour (#banked): pad initControllers 98.777 (`addi r0,r3,0; mr r31,r0`), shield_update.
- pollen fn_8016A660 98.922: `if(x)goto ok;return;` — target keeps `bne ok; b epilogue` island,
  MWCC folds to single `beq`. +1 instr. Rest = @92 bias-double (score-neutral). Peephole fold, BANKED.
VERDICT: working tree unchanged (only this md appended + pre-existing sibling drpickup.c/track_dolphin.c).
all_source EXIT=0, no FAILED. drpickup.c/track_dolphin.c are sibling-owned uncommitted — untouched.

## Semantic-recovery (dedicated per-family state) — Jul05 session
WIN dll_0272_drpickup (821212d762): typed 3 raw DRPickupState-base stores in
fn_801EC1AC byte-neutral — *(s16*)(state+0x40e)->angle40E,
*(s16*)(state+0x40c)->angle40C, *(u32*)(state+0x410)->angAccum410. The two 0x430
liftZVel sites REVERTED (byte-changers): each coupled to an (int)state int-launder
read on the same statement; retyping LHS store OR the read both shift bytes.
DISQUALIFIED this session (all confirmed byte-changers or shared/narrow):
  - firecrawler: 0x308/0x261 casts are inside BaddieState shared prefix (FireCrawlerState
    only owns 0x368/0x36c). duster: 0x344/0x348/0x34c/0x323/0x2a0 = shared per-family scratch.
  - tricky(sub) 0x2b6 = u16 narrow view into f32 currentTime@0x2B4 (per-unit narrow, no field).
  - weapone6 0x828 = TrickyState pad81C region (no named field); status+0x10 is not the state base.
  - trickyfollow 0x98/0xa0 = index-scaled patch[i]/f32-triple walker (header marks raw).
  - drgenerator 0x19a hitsRemaining: `state[0x19a]` is SIGNED-char access; retyping to u8
    hitsRemaining changes the `> 0` compare + arithmetic sign (byte-changer, REVERTED).
  - dll19func0 0x20/0x8c/0x94/0x261/0x334 = BaddieState shared prefix (no dedicated struct).
Confirms the int-launder + shared-prefix + signed-char-narrow disqualifiers dominate.

## SEMANTIC-RECOVERY setup-buffer pad-split pass (2026-07-05, Opus) — 0 wins, vein confirmed mined
Swept all 89 `Obj_AllocObjectSetup`/`Obj_SetupObject` TUs plus 183 files defining a
`*Setup`/`*Placement`/`*Spawn` struct. Cross-referenced struct-with-pad-field headers against raw
`*(T*)(base + 0xNN)` casts in their consumer .c. RESULT: every file that DEFINES a partial
Setup/Placement struct has ALREADY respelled all its fixed-offset accesses through the struct — no
raw pad-offset cast survives against a mapped struct. The remaining raw casts all fall in the
briefed disqualifier classes:
- **Canonical raw setup-init writes** (`*(u8*)(setup+0x4)=2; *(u8*)(setup+0x5)=1; *(s16*)(setup+0x1a)=i`):
  tricky (dll_00C4) L412-415, tricky_flameguard L250-252/344-346/544-546, tumbleweedbush L134-136.
  tumbleweedbush is the COMMITTED reference and it KEEPS these raw — confirmed canonical (typing shifts
  codegen). Whole family disqualified.
- **Bare-int `setup`/`placement` base + single class-specific offset, NO existing struct to extend**
  (would require NEW struct + int->ptr cast that materializes a member-address temp per obj_placement.h):
  dll_0299 L66 `*(s16*)(setup+0x1e)` (only Dll299State exists, no Dll299Setup); dll_00E5_shield
  staticCamera_init L313-318 (`placement+0x1c/0x1e/0x20` rot shorts, +0x19/+0x1a u8);
  dll_00D5_kaldachom L88 `*(char*)(placement+0x28)`. New-struct creation, not a pad-split; high md5 risk.
- **GroundBaddie placement reads via `u8* setup`** (seqobj11d L337-430: 0x1c GameBit / 0x27 flag /
  0x2e flag): no GroundBaddiePlacement struct; `setup` is u8* to placementData — retyping hits the
  placementData deref-width hazard. Not a pad-split.
- **DoorLock/SeqObject/IMMultiSeq placements** (alphaanim.h) are fully named; their consumers
  (dll_0111/0112/0113/0114) use named fields only — pads genuinely unused, nothing to recover.
- **->padNN/->unkNN direct accesses**: only dll_00F1_invhit `->unkF4` (a GameObject field, not a
  setup buffer — out of scope).
SKIPPED concurrent owners (uncommitted at session start / mid-session): drpickup.c, player.c,
dll_013E_dimbossicesmash.c. NO source edits made, NO .o rebuilt, working tree clean of my changes.
VERDICT: the object-setup pad-split vein is exhausted for this scope. Legitimate 0-win pass.

## Re-check 2026-07-05 (cheap 45-min recent-commit triage)
`git log --since='45 minutes ago'` = ~24 commits, ALL carrying the Claude Opus 4.8 trailer
(this session's own struct-recovery/respell/field-naming work). ZERO fresh TEAM commits
(no match / data-split / linked-complete) landed in the window. Last real team commits
(ebfe953531 dimtricky, eede1ad83e texscroll, 14e2c60966 staticcamera, ...) are all
pre-window and already mined by prior re-checks. No fresh team unit to inspect.
VERDICT: legitimate 0-win pass. No files opened, no .o rebuilt, no commit.

## Long-tail mop-up (catch-all raw-cast scan) — Jul05 — 0 wins (all disqualifiers)
Scanned all 128 raw fixed-offset cast sites in src/main/*.c; excluded the 66 .c files
already committed this cycle (struct recovery / field naming / data-split). Un-mined tail
= 18 files. Triaged every live (non-#define, non-macro-accessor) raw cast — ALL disqualified:
  - dfshlaserbeam:171 = vtable-through-resource call (gLaserBeamEffectResource chain).
  - dim2icicle:478/500 = state/playerObj +0x35c/+0x3f4/+0x34f PAST mapped IcicleState end
    (0xad) / into shared BaddieState unnamed region (shared-prefix disqualifier).
  - dim2icicle:570/579/602 = vtable dispatch through tricky+0x68.
  - dbprotection:804 = obj+0x34 lands in ObjAnimComponent.pad34 (UNNAMED pad; named field
    is +0x35 yaw-idx). Not a named field at exact offset.
  - dll_0014_unk:1153/2224 = stateBytes/BASE unmapped blob bases inside the big multi-line
    matrix-build #define macro.
  - dll_00C4_tricky:872 / weapone6:43 / animobjd2 = TRICKY_STATE flag/reset macros (shared
    tricky-state blob, self read-write flag-clears, resistant #130 class).
  - dll_0133_sfxplayer:220-264 = data+0x1a/0x22 unmapped sound-command sequence blob.
  - dll_a6:105 = activeBank+0x18 self read-write `& ~8` on UNMAPPED ObjAnimBank blob.
  - remaining (OBJ_*/IFACE/MLDF/DVD_/_RT) = macro-abstracted accessors, already fine.
  - dfpforceaw/dfprotatep SFXPLAYER_UPDATE_EFFECT_HANDLE_POS macro = #define'd then #undef'd
    immediately, dead scaffolding (never expanded), handle/obj are raw non-struct offsets.
VERDICT: legitimate 0-win pass. No mapped-struct-base raw cast with a named field at the
exact offset+width remains in the un-mined tail. No files edited, no .o rebuilt, no commit.

## Placement/setup struct-recovery 2nd pass (Jul05, semantic-recovery)
Scanned all custom-<Family>Placement/Setup/Spawn .c files in src/main/dll for raw
casts on a base a same-file sibling types. Per-function same-var scan (scan3/scan4).
COMMITTED (2 wins, .o md5-identical / byte-neutral):
  - dll_013E_dimbossicesmash (68da73cb90): *(u8*)(params+0x3c)&2 -> ((DimbossicesmashPlacement*)params)->flags&2 (path-control flags test in _init).
  - dll_0175_dfropenode (6909912d54): 2 sites *(u8*)(objDef+0x1b) -> ((DfropenodePlacement*)objDef)->textureIndex (rope-variant array subscripts in _update+_init).
BYTE-CHANGERS (tested, reverted, md5 restored):
  - dll_0265_drcreator L191: *(s16*)(placement+0x1a) -> ->behaviorMode. Vararg
    context to fn_80137948 makes the s16 load-form load-bearing (sibling uses same
    expr in a switch, but vararg site differs). REVERTED.
  - dll_011B_landedarwing L260: *(int*)(def+0x14) -> ((LandedArwingPlacement*)def)->mapId.
    Byte-changer despite identical sibling shape at L303 (case 2/0x65 vs case 3/0x64
    colors registers differently). REVERTED.
DISQUALIFIED (no source lever):
  - siderepel/baddieinterestp staticCamera_init: raw params is a DIFFERENT alias
    (static-camera placement), not the *Placement the update-fn sibling types.
  - drgenerator arg+0x1a, dimbridgecogmai param+0x1d, pressureswitchfb params+0xc:
    offset falls in an unnamed pad (no named field to respell to).
  - dfpobjcreator data+0x1e (*s8 vs s16 unk1E) width mismatch; landedarwing def+0x1c
    (*u8 vs s16 triggerGameBit) width mismatch.
  - lightning data+0x18 -> only unk18 (generic placeholder, no recovered semantic;
    surrounded by uniform raw byte-index reads, low value / risk).
  - drearthwarrior p2+0x278: p2 is runtime STATE here (EarthWarriorState/BaddieState),
    state write not placement read; different alias than the Placement sibling.
  - objfx obj+0x1a/0x1c (ExplosionSetup): DOCUMENTED prior TEST — header note states
    0x1a (pad, f32->s16 trunc) and 0x1c (flags word) "stay raw" (byte-changers).
    Respected; not re-litigated.

## STORE-SITE struct recovery sweep (2026-07-05, Opus) — 2 wins, GameObject-tail stores
Store-focused raw-cast recovery pass. 2 byte-neutral wins committed:
- **dll_018D_mmshscales** `*(s16*)(match + 0xb4) = -1` -> `((GameObject*)match)->seqIndex = -1`
  (match is a GameObject* from *list; 0xB4 = seqIndex s16). md5 identical.
- **dll_019D_dll19d** `*(int*)(self + 0xf4) = lifetime - frames` -> `((GameObject*)self)->unkF4 = ...`
  (self used as GameObject* throughout; 0xF4 = unkF4 s32). md5 identical. The paired read at
  line 225 `lifetime = *(int*)(self + 0xf4)` is a plain field load (NOT an int-launder) so no
  coupling break; left the read raw per store-focus mandate.
DISQUALIFIED (leave raw, confirmed this sweep):
- **dll_0271_drakorhoverpad** `p + 0xd8/0xe0/0xe4` stores: p treated as GameObject*, offsets land
  on childObjs[4]/unkE0-pad/hitVolumeIndex — the file's deliberate "reuse GameObject slots as f32
  scratch via launders" idiom (surrounded by `*(f32*)&((GameObject*)p)->unkDC` etc). Canonical raw.
- **dll_00DA_pollenfragment** `*(s8*)(config + 0x19)`: config is a raw placement blob, NO mapped
  struct; reads use mixed char/s8 spellings; setup-store canonical.
- **dll_0190_ecshcup** `*(u8*)(obj + 0x37)`: 0x37 is inside ObjAnimComponent pad37[] (unnamed).
- **dll_018F_ecshshrine** `sub + 0xc/0x10/0x14`: fall inside EcshShrineState padC[] (unnamed).
- **dll_0123_fuelcell** `op + 0x43` (render-op, no mapped struct), `slot + 0x34` (index-scaled base).
- **dll_00FB_pressureswitchfb**: all stores index-scaled (`runtime + i*4`, `tmp + j*8`).
- **dll_0117_appleontree** `val + 0x24`: val = `*(int*)&obj->extra` int-launder base, mixed raw offsets.
- **dll_008D_dll8dfunc0** `base + 0xb4`: base = gDll8DEffectParamBlock (effect param block, NOT a
  GameObject); 0xb2/0xb4 paired param-block setup writes — coincidental offset collision, NOT seqIndex.
GENERALIZABLE: GameObject-tail stores at NAMED offsets (0xB4 seqIndex, 0xF4 unkF4) where the base var
is used as a GameObject* are the reliable store-site win. Most other raw stores are int-launder /
index-scaled / pad-region / non-mapped-blob = leave raw.
