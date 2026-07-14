# dll_0014_unk.c matching notes (session progress)

## State
- TU at 99.77% after goNextPoint fix (committed b4b384ddcc).
- Remaining: walkgroupFindExitPointFn_800dc398 (97.83%), RomCurve_func1C (99.86%).

## Matched this session
- RomCurve_goNextPoint: two-label goto tail (`clearAndReturn:` zero + fallthrough `returnOne:`)
  reproduces beq->+0x964 skipping the store. 100%.

## RomCurve_func1C (99.86%) — one r25/r29 web swap
- Baseline: distWrite (named decl#3) gets r25; qc4 temp (queueCount*4, idx 88) gets r29. Target reversed.
- V-K form (scratchpad/probe/probe_vk.c) fixes ALL registers:
  * `top` named int at decl#3 (top = queueCount after --, top++ after ++) absorbs the scaled web (idx 54-55)
  * found-block: `candidateDistances[candidateCount] = distance;` (indexed store) -> cdInner SR temp idx 64+ -> r29
  * links: `((RomCurveDef*)startCurve)->linkIds[directSlot]` -> cur becomes SR clone idx 59 -> r27
  * scanBase init hoisted (in-loop first stmt), distRead init fn-top (source stmt)
  * probe/distWrite/cur named cursors REMOVED
- Remaining defect: `addi r23,r1,16` (distRead init) emits BEFORE `mr r27,r30` (cur-clone
  preheader init); target has it AFTER. objdiff scores V-K 99.49 < baseline 99.86, so not committed.
- Pop rule (validated by traces): params first, then strictly descending web index.
  Named webs: decl order descending, contiguous band ~34..50. SR temps appended (54+).
  Merged webs (named absorbed by SR clone) adopt the clone's index.
- Wall: distRead-web needs idx <47 (pop r23) but its init must emit inside the preheader
  group. Preheader emission order model incomplete — next lever is tracing the emission pass.

## walkgroupFindExitPointFn_800dc398 (97.83%, 100 ndiff regions, C has +2 instrs)
- Register anchors (tailregs.py): TARGET wg1=r21 wg=r21 wgB=r22 pp=r26 p=r27 pi=r28 listWalk=r26
  slot36=r28 listIndex=r25; CURRENT wg1=r21 wg=r27* wgB=r28* pp=r26 p=r21* pi=r29* listWalk=r24*
  slot36=r29* (* = mismatch).
- Trace (segment w/ 18 fallbacks): GPR pops 474,107,103,90,88,61,57,56,55,54,42 -> r31..r21.
  F88/F90 = wg-tail/wgB-tail du-split webs (appended, "outside decl control").
- Theory: target's cursors (listWalk, slotPtr, p, pp) are SR clones from INDEXED source
  (curveList[listIndex], curve+slot*4+K, pairs[pi*2], patchBase[0][pi]) — mirrors func1C lesson.
  wg/wgB only named tail vars -> pop last -> r21/r22.
- BUT naive indexed rewrites FAIL (extra instructions; SR doesn't make the cursors):
  * full rewrite: 202 regions, +9 instrs
  * tail-only: 121 regions, +5 instrs, p lands in r4 volatile
  Suspect the `ObjfsaPatch* patchBase[1]` stack-array blocks SR, or SET_PLANE macro shapes matter.
- `arena->active[grp] = 1` with proper ObjfsaArena struct reproduces the active-flag store
  exactly (li; add; stb disp). Arena struct = {ObjfsaPatch patches[0x100]; ObjfsaWalkGroup
  walkGroups[0xB5]; u8 active[0xB8];}
- wg site-1 shape T: [add r21,r30,r0][addi r21,r21,12288] accumulate-in-dest; every C form
  tried emits via volatile intermediate or reassociates (grp*40+12288 first). Unsolved.
- pC/pB aliases in tail loop are load-bearing (removal loses 4 instructions T has).
- Probe: scratchpad/probe/wgfep.c (+build_wgfep.sh, cmp_probe.py, tailregs.py). Probe baseline
  reproduces in-tree registers (131 regions incl. reloc noise vs 100 in-tree).

## Tools built
- scratchpad/select_trace_lldb.py + run_trace.sh / run_trace_tu.sh: web idx/nadj/reg tracer
  (bootstrap breakpoint on wibo resolveImports, then raw addrs 0x508680/0x50899e/0x5089c4).
- scratchpad/probe/cmp_probe.py <symbol> [obj]: normalized diff target-vs-probe.
- scratchpad/tailregs.py [obj]: big-fn variable->register anchor extraction.

## Additional falsifications/validations (same session, later)
- Big fn under NO pragma: target keeps a dead `clrlwi r3,r6,16` before `sth ...groupId` ==> the
  original really is prop-off (`pairGid = pairId` staging survives). opt_propagation off stays.
- Self-reassign (`wg = ...; wg = wg + 0x3000;`) SPLITS the variable into two du-chain webs; the
  value-chain gets RENUMBERED (appended band, idx 88-90) regardless of decl position (fresh-name
  wgT/wgBT still landed r27/r28). Single-expression init form
  `(ObjfsaWalkGroup*)&((ObjfsaPatch*)&((ObjfsaWalkGroup*)patchBase[0])[i])[0x100]`
  keeps ONE web and moved tail wg/wgB to r22/r23 (target r21/r22) but reshuffles everything else
  (146-157 regions) - needs joint solve with first-loop webs.
- Loop-carried cursors (p, pp, pi: init outside + increment) = named-band webs (decl-indexed).
  Per-iteration-redefined vars (wg, wgB) = renumbered webs. Target has wg=r21 shared across BOTH
  sites AND the tail: unresolved which mechanism (merge? A-grant?) - next step is porting the
  select tracer to the standalone probe (wgfep.c compiles alone; trace runs in ~1 min) and
  dumping the FULL A+F stream for both loops.
- objdiff scoring: register-field mismatches score HIGHER than displaced/different instructions.
  Baseline (100 regions, all-reg-perm) = 97.83%; "better-shaped" variants scored lower.
  Verify candidate improvements against report.json before committing.

## Register-topology breakthrough (validated live, not yet landed)
A probe configuration achieved ALL EIGHT target register anchors for
walkgroupFindExitPointFn_800dc398 (wg1=r21 wg=r21 wgB=r22 p=r27 pp=r26 listWalk=r26
listIndex=r25 slotPtr=r27), reproducible in-tree. Recipe:
- Tail wg/wgB as FRESH variables (wgT/wgBT) declared at the very END of the decl list,
  initialized with a SINGLE expression (no self-reassign; self-reassign splits the web and
  the value chain renumbers into the appended band ~idx 88-90 = wrong pops).
  Single-expr form used: `(ObjfsaWalkGroup*)((u32)&((ObjfsaWalkGroup*)patchBase[0])[pp[i]] + 0x3000)`
  (association still wrong: emits mulli/addi/add vs target mulli/add/addi - 2 operand-order
  lines lost per site x3 sites).
- `p` declared early (right after slotPtr), `pp` declared between listWalk and listIndex,
  listWalk declared before listIndex.
- Site-1 wg keeps the two-statement wgB staging; wg declared late (just before wgT/wgBT).
Result in-tree: 104 ndiff regions but objdiff 97.47% < baseline 97.83% because:
(a) the curve/slot F-band shifted (an nadj=29 web now parks and steals r22; curve lands r23),
(b) the 3 single-expr init sites lose shape credit,
(c) np/back/pl/po/slot36/FPR webs still permuted.
Next session: fix (a) via decl adjustment around the idx-40 interloper (trace segment shows
F idx=40 nadj=29 -> r22), and find the association-correct single-expr form for (b) - the
target shape add-then-addi with ONE web remains unproduced by any tried expression; candidate
mechanism: biased coloring of a def1-chain into the dest web (see mp4 charDirTbl[i][2] corpus
hit - global-array base differs from register-base case).
objdiff weighting note: ~90 register-field lines are worth LESS than ~9 shape lines; always
score via report.json before judging a topology win.

## func1C landed at 99.91% (committed)
The indexed form WITHOUT a named distRead landed: end loop reads candidateDistances[sel[0]]
via the SR base web; preheader emission order now matches target exactly
([mr r27,r30][addi rX,r1,16][mr r26,rX][addi rY,r1,48]). Remaining 4 register-only lines:
the SR cd-base web (idx 48, nadj 90, created one above the named band) pops r24 while named
scanBase (idx 46-47) pops r23; target has them swapped. Constraints proven this session:
- A named web can never outrank the SR base by decl order (base = band-top + 1 always).
- Dropping scanBase (indexed or pq-direct scan) loses the persistent r24 base web entirely
  (57 regions) - the named var is load-bearing for the pointer-walk shape.
- V-K (named distRead) solves the POPS (merged base+distRead keeps named idx 46 -> r23) but
  emits the addi at source position instead of inside the preheader.
The two configs are complementary; the original produced both properties at once. Candidate
unexplored mechanism: park-round reordering (observed once in FPRs: idx48/nadj268 popped
before idx87/nadj23 - low-nadj webs sink to the last pops). If the merged distRead web can be
made to park in the sinking class, V-K completes. Next tool: extend select_trace to log the
park/simplify events (round numbers), breakpoint band 0x508~ Simplify loop.

## Simplify algorithm decoded (docs/mwcc_re/recovered/Coloring.c) - closes several questions
- Push order: repeated ASCENDING-INDEX sweeps push webs whose current degree < k (degree
  relaxes as neighbors leave); stuck -> optimistic-spill the HIGHEST-index parked web; repeat.
  Select pops LIFO => saved regs r31-descending in reverse push order. This exactly reproduces
  every observed pop sequence including the FPR "anomaly" (idx48/nadj268 = spilled late,
  pops before low-degree idx80/87 which pushed in round 1).
- Consequence for func1C's last 4 lines: in the no-distRead config, cd-base (SR temp,
  always webEnd = named-band-top + 1) and scanBase (named band top) push in the same sweep
  in index order -> base always pops one register above scanBase. PROVEN unreachable by decl
  order, dummy decls, inline-helper interference, or hoist position. The target therefore has
  the V-K structure (named distRead absorbs the base at named idx, popping r23) and the one
  remaining unknown is why the target emits distRead's addi INSIDE the preheader group
  ([mr cur-clone][addi distRead][mr outer][addi scanBase]) while every tested source position
  emits it at the source slot. Candidate: decl-initializer emission order or a coalesce-kept
  copy (see Color_Coalesce identity-sharing in recovered/Coloring.c - eligibility flags are
  set upstream during web/move building, 'the next thing to read').

## New tool: tools/mwcc_re/webmap_lldb.py (instruction->web mapper, needs field decode)
Breaks on the Apply walk (0x508804) and logs every PCode instruction's opcode + operand
descriptors (k/c/i fields at inst+0x24+n*0xc). Bootstrap-armed via wibo resolveImports (works
on macOS lldb/Rosetta, unlike the gdb scripts). Ran successfully on the walkgroup probe
(2701 instructions). REMAINING: the operand 'i' field (offset +4, 2 bytes) is NOT the web/vreg
index for all operand kinds (observed values 0-5 = likely physical/precolored); decode the
RegInfo operand layout (kind codes k0/k3 seen) to map instructions -> web indices, then
identify the F40 interloper web (nadj 29, steals r22 from curve in the 8/8-anchor config)
by finding its def/use instructions. Candidates eliminated by decl-move probes: curveList,
pC, pB, iter, checksum (target's checksum is volatile r5).

## Web NUMBERING is priority-driven, not decl-order (CodeGen_NumberWebs @0x435650)
Per recovered/CodeGenNumbering.c: webIndex = webEnd[class]++ assigned by a MAX-PRIORITY
worklist (priority = loop-weighted ref weight, desc+0x4; loop-resident pin 0x40 -> 100000).
Decl order only breaks priority ties. This reframes both residuals: web indices can be
STEERED by changing reference weights (add/remove a loop-depth-weighted use) without decl
churn. tools/mwcc_re/pri_trace_lldb.py (lldb port, bootstrap-armed, WORKS on macOS) logs
every numbering commit as "N cls= idx= pri= flags=".
Measured on the committed func1C config: the contested cd-base web (idx 48) commits with
pri=2 (the eligibility MINIMUM) while scanBase-area webs (46/47) commit at pri=68/65.
Commit order is NOT globally descending in pri (two interleaved worklists / append during
processing) - decode the worklist interleave next, then steer the base web's priority to
flip the idx-48/idx-46 order (which fixes func1C's final 4 register lines).

## Numbering caller identified: single in-order pass at 0x4c2932 (NOT the priority worklist)
Return-address logging (pri_trace_lldb.py now records ra=) shows ALL GPR web numbering
commits for func1C come from call site 0x4c2932 - the CodeGen_NumberWebs max-priority
worklist (0x4356xx) never fires for this compile. Web indices therefore follow ONE
deterministic value-graph walk. Decoding the walk order at 0x4c2932 (which value-graph
traversal, and where SR-created values slot into it) is now THE single decode that explains
- and allows steering - the cd-base(48)/scanBase(46-47) order in func1C AND the F40
interloper slot in the walkgroup function. Priorities logged are metadata, not the order key.

## 0x4c2932 attributed: CMachine.c (94 funcs, 0x4bf320-0x4c9590 per assert map)
Web numbering fires from the MACHINE EMISSION walk, i.e. webIndex = order the code
generator first touches each value while emitting PCode. Observed named-local indices
(first-declared highest) imply locals' value nodes are enumerated reverse-decl at entry
emission; SR/clone values number at their preheader/body emission positions. The exact
traversal (def-time vs first-operand-use, entry-block enumeration) is one objdump session
away: disassemble 0x4c28xx-0x4c2Axx in docs/mwcc_re/disasm style and match against the
pri_trace ra=0x4c2932 commit sequence for probe_4regions.c. That yields the steering rule
for the last 4 func1C lines and the walkgroup F40 slot.

## DECODED: lazy first-touch web numbering (CMachine emission)
Disassembly of 0x4c2920: per-operand RegInfo query (call 0x4e77e0, ret 0x4c2932) tail-chains
into the numbering commit (0x4fe550/0x4fe563) - a value is numbered the FIRST time the
machine emitter touches it as an operand. Combined with observations:
- Named locals are all touched during prologue/home enumeration (reverse declaration order,
  hence first-declared = highest idx among named) BEFORE any body code.
- Optimizer temps (SR bases/clones, split webs) number at their first emitted occurrence -
  always AFTER every named local. This is the mechanism behind "temps append above the named
  band" and is now PROVEN, not just observed.
Consequences for the residuals:
- func1C: an SR cd-base can never index below named scanBase (третья proof). Target r23-web
  must be a named distRead merged over the base. The cur-walker (pops r27, 3rd) must be a
  TEMP (idx ~59) - so target's preheader [mr r27,r30] is clone-init, and the addi r23 after
  it is ALSO preheader material => distRead's init must be hoisted-from-loop (V-J), and the
  remaining question narrows to the ADDI-vs-COPY direction between the merged distRead web
  and the cd-outer clone at preheader materialization (V-J emitted outer-primary; target is
  distRead-primary). Direction = which web the emitter materializes the value into first =
  likely first-touch order between the two webs; steer by making distRead's first emitted
  touch precede the outer clone's (e.g., position of the hoisted init among the loop's
  leading statements, or an earlier harmless read).
- walkgroup: F40's identity falls out of the same rule - it is the ~7th-from-last named
  GPR-webbed declaration; enumerate decls against the trace to name it.

## walkgroup F40 IDENTIFIED: pl (plane-staging pointer) - fix direction proven
Reverse-decl enumeration against the trace names F40 (nadj 29, steals r22 from curve) as
`pl` (with F35=wg-site1, A34/A33=wgT/wgBT - all consistent). Probe experiments:
- Direct np->planes[K] access (no staging): curve reclaims r22 ✓ but LOSES 13 address
  instructions the target has (target materializes per-block address temps).
- Block-scoped pl2/po2 via np: curve=r22 ✓, 1262/1268 instrs (6 short - some addresses fold).
- Block-scoped via OBJFSA_NEWPATCH re-deref: 1266/1268 instrs but web count shifts the
  first-touch order globally (curve back to r23).
Next: per-block comparison of the 4 SET_NEWPATCH_PLANE + 2 SET_PLANE sites against target
asm (np register per block: r28/r3/r4 sequence in target = np also re-derived per block)
to pick the exact staging form per site; then re-run the anchor set. The target's po/pl are
SHORT per-block webs (grants r24/r29/r28 shuffle), NOT one function-wide pair - the current
committed macro's shared pl/po is confirmed decomp-artifact ("false set" class).

## Per-block staging form found (probe wgfep_perblock.c)
SET_NEWPATCH_PLANE with BLOCK-SCOPED po2/pl2 initialized BEFORE the sqrtf call (target
computes the addresses pre-call; they live across it as short saved-grant webs r24/r28/r29)
gives the correct instruction count (1270, the baseline +2) and holds listIndex=r25,
listWalk=r26, p=r27, pp=r26, slotPtr=r27. Removing the shared pl/po eliminated the F40
parked web; the wg cluster then shifts one slot (wg/wg1=r22, wgB=r23, curve=r23 - each one
above target). Remaining: one web in the pop set moved into the r21-last-pop slot; identify
it via the select trace on this config and adjust (likely the same reverse-decl enumeration
- candidates: lp(F35-neighbor), fyv, sp). The macro's shared pl/po = confirmed false-set
artifact; the block-scoped form is the plausible original (macro-local temps).

## Per-block config trace: pl2/po2 webs land as grants (r21/r28 band = matches target
shuffle); new r21-blocker F39 (nadj 29) enumerates to fyv (maxY/minY staging var used
across the lp=(char*)&OBJFSA_NEWPATCH blocks, lines ~2616-2637 in-tree). Target stores
maxY/minY from volatiles (sth r4,34(r3) directly after fctiwz) => fyv+lp there are the
same shared-staging false-set artifact as pl/po; apply the same fix (block-scope or inline
the staging per site) and re-anchor. lp itself (F43, nadj 233) currently pops r22 - after
the fyv fix expect lp to need the same treatment for the wg cluster to settle on r21/r22.

## fyv eliminated as the r21-blocker
Direct (s16)fy0/fy1 stores (dropping fyv+lp staging at the four maxY/minY sites) leave the
wg cluster unchanged (wg=r22, curve=r23) and cost 4 region-lines (144 vs 140) - revert that
edit; the committed lp/fyv staging at THOSE sites is shape-correct. F39's identity remains
open - resolve via webmap operand decode (def-site correlation), not enumeration guessing.
Probe state to build from: wgfep_perblock.c (per-block po2/pl2, 140 regions, 5/8 anchors).

## webmap operand layout decoded + constraint found
PCode operand record (inst+0x24+n*0xc, 12 bytes): [0]=kind (0=reg, 3=value-ref),
[1]=class, [2:4]=le16 register/vreg, [4:8]=value-node ptr (kind 3). CONSTRAINT: the Apply
hook (0x508804) fires POST-coloring - operands are already physical regs (observed 0-5),
so instruction->WEB correlation needs a PRE-color hook instead: candidates are the
interference-graph build (InterferenceGraph.c band; disasm exists in docs/mwcc_re/disasm/)
or reading desc+0x26 (webIndex) through the kind-3 value-node ptr at Apply time (the
descriptor survives coloring). The latter is a two-line tracer edit: follow o[4:8] ->
RegInfo_Desc -> +0x26, logging web indices alongside physical regs = full web<->instruction
<->register correlation in one pass. That identifies F39 (and any future interloper)
directly from its def/use instructions.

## webmap desc-deref attempt (not yet firing)
RegInfo_Desc (0x4d0150) dispatches on value+2 via jump table 0x5b8acc; two decoded cases
lazily allocate the 0x2a-byte desc at [value+0x32] (case with cmp [ebx+0x32]) or [value+0x2a].
Tracer edit following kind-3 operand ptr -> value -> desc -> webIndex(+0x26) produced no
w-tags on the walkgroup probe: either kind-3 operands at Apply time do not carry these value
nodes, the third jump-table case applies, or the desc is unallocated by Apply. Next: at the
Apply breakpoint, inspect one kind-3 operand's value node live (x/16wx) to fix the layout,
then rerun. Tool state: scratchpad/webmap_lldb.py (repo copy needs this update once firing).

## webmap conclusion: Apply-time web correlation impossible
kind-3 operands carry IMMEDIATE/CONSTANT payloads in bytes [4:8] (observed 0xbde80000 =
-0.113f), not value-node pointers; kind-0 operands are post-color physical regs. So the
instruction->web correlator must hook PRE-color: the InterferenceGraph build pass (disasm
in docs/mwcc_re/disasm/InterferenceGraph.c.objdump.txt) where webs and their def/use lists
are constructed. That hook plus the select trace closes both residuals' register questions.

## igwalk tracer working: F39/F40-band webs are r2-sourced copies
New tool tools/mwcc_re/igwalk_lldb.py hooks the InterferenceGraph descriptor walk
(0x57b7f3, desc ptr at [esp+0xc]) and logs copy descriptors (n, flags, class, w26->w28).
On the walkgroup per-block probe: 21 class-4 records, all `w2 -> wXX` with wXX in
{40, 46, 62, 105, 126, ...} - the contested F39/F40-band webs are DEFINED BY COPIES FROM
WEB 2 (r2, the sdata2/small-data anchor). I.e. the interloper webs hold ADDRESSES OF
SDATA2 SYMBOLS (the lbl_803E05xx float constants' addresses held in GPRs across calls!) -
e.g. the hoisted &zero/&div-style anchors, NOT user variables at all. That reframes the fix:
which sdata2 constants get their addresses hoisted into saved GPRs depends on the FP-constant
reference pattern (lfs from sdata2 vs kept-in-FPR) - compare the probe's lbl_803E05F0/060C
usage against the target's f27/f30 preloads in the tail. Likely fix: load zero/div into
locals ONCE (like the committed `zero = lbl_803E05F0; div = lbl_803E060C;`) at the RIGHT
scope so no GPR anchor web is needed where the target has none.

## Phantom anchor webs decoded
The w2->wXX copies are IR-level &sdata2-constant temps that FOLD into sda21 relocs at
emission (zero instructions emitted - no r2-relative operands exist in either object) yet
still park in the interference graph and consume saved-reg pop slots. Their indices/nadj
depend on surrounding live pressure, so they settle once the user-web lifetimes match the
target. Conclusion: no separate fix needed - finish the per-site staging alignment
(SET_NEWPATCH_PLANE blocks 0-3 + 2 SET_PLANE sites, np re-deref shape per block against
target 0x8ac-0xc5c) and the phantoms will park identically. The igwalk copy-descriptor log
provides the phantom census for verifying each iteration (expect identical w-lists when
the staging is right).

## SYNTHESIS: walkgroup fix = 3 identified pieces (per-block reading of target 0x7c0-0x8c8)
Target block-0: np held SAVED (r28) across the block; po = addi r29,r28,16 BEFORE sqrtf;
pl FOLDS to 0(r28) after the call (np still live). Blocks 1-3: np re-derefed into a
VOLATILE (r3/r4) per block; po AND pl materialize as saved short webs (r29/r24 grants).
=> The COMMITTED macro (po/pl = shared named vars, OBJFSA_NEWPATCH re-deref) produces
exactly these instructions (baseline matched them); its pl block-1 du-chain parks at
nadj=29 (measured F40) instead of taking an A-grant like the target - the textbook
"one interference edge below threshold" case from the validated levers doc. Fix pieces:
1. Keep the committed macro (shared pl/po named vars) - shapes are right.
2. Tail wg/wgB: single-expression fresh wgT/wgBT declared last (fixes F88/F90 splits ->
   wg=r21/wgB=r22) - association form still to settle ((u32)-cast variant closest).
3. pl block-1 chain: +1 interference edge (validated lever forms: inlined helper return
   copy / ternary temp / shared named local) to push nadj 29->30 so it parks early and
   pops in the target slot instead of stealing r22.
Combine in the probe, verify anchors + census, port, score.

## 8/8 anchors achieved WITH committed macro shapes (probe wgfep_8anchors.c)
Recipe: committed SET_NEWPATCH_PLANE macro (shared pl/po) + decl moves (p after slotPtr,
listWalk before pp before listIndex) + fresh single-expr tail wgT/wgBT declared last
((u32)-cast form). Result: wg=r21 wg1=r21 wgB=r22 p=r27 pp=r26 listWalk=r26 listIndex=r25
slotPtr=r27 ALL CORRECT at 140 regions / 1270 instrs (baseline count). Remaining wrong:
curve=r23 (want r22, blocked by pl block-1 chain at nadj 29) and back=r28 (want r24).
The +1-edge lever (inline identity helper on pl) FIXES curve=r22 but applied to all four
macro chains it reshuffles others (157 regions, wg1=r31). Next: apply the helper to the
K=1 site only (expand that macro invocation inline or add a variant macro), re-anchor;
then back(r28->r24); then the tail-init association form; then port + score vs 97.83.

## K=1-only lever attempts (both folded)
Dead pre-assignment: DCE'd. Inline identity helper on the K=1 pl init (expanded macro):
copy folded, no new web (140 regions, anchors held, curve still r23). The mass version
(helper on all four chains) DID move curve=r22 - so the needed edge exists in that
direction, but the surviving-copy form for a SINGLE chain needs the DIMSnowHorn1_angleTo
pattern specifics (check its source in-tree: what made its return-value copy survive
inlining). Alternative: find which OTHER web interferes with the pl-chain in target but
not ours via the igwalk census diff once instruction->web logging lands pre-color.
Current best probe: wgfep_8anchors.c (8/8 anchors, committed shapes, 140 regions).

## Lever clarification: DIMSnowHorn1_angleTo is a REAL computation (not identity)
Its inlined body materializes a genuine local web (angleDelta with multiple defs/uses) -
the +1 edge came from substantive code. For the walkgroup pl chain the extra interfering
web must therefore be a real value live across the K=1 block in the ORIGINAL source that
our version lacks or scopes differently (candidates: x/z corner staging across the sqrtf,
or the pairGid/np value lifetimes). Compare the K=1 block's LIVE SET (target vs probe)
instruction-by-instruction - the register content difference at any point inside
0x9a4-0xa40 names the missing web directly. Best probe remains wgfep_8anchors.c.

## 8-anchor probe residue = single-slot rotation
Remaining saved-reg mismatches form one rotation: curve 23->22 (33x), slot 24->23 (5x),
np/back 28->24 (9x), slot36 29->28 (12x). One additional parked web in the r24-r29 band
(the pl block-1 chain parking, as in target) rotates ALL of them into place - confirmed
directionally by the mass-helper test which fixed curve. The K=1 block is otherwise
instruction- AND FPR-identical to target (verified side-by-side). Everything now reduces
to making that ONE chain park: +1 real interference edge at its live range. Folding-proof
lever forms to try next: a substantive inline helper (angleDelta-style real computation)
in the K=1 dataflow, or restructuring which corner value stays live across the K=1 sqrtf.
Volatile/f-perm shuffles downstream will settle with the rotation.

## Target-side structure pinned: pl block-1 chain PARKS there (pop consumer)
Pop-count comparison: our curve pops 9th (r23), target's 10th (r22) => target has one more
parked web in the r24 band = the pl block-1 chain (target pl=r24 via POP, ours=r22 via
grant). Levers tried that FOLD (no new web): identity inline helper at single site, dead
pre-assignment, named s16 readback staging (nx1/nz1). The mass helper (all 4 chains) moves
curve correctly but over-rotates. Remaining lever candidates for +1 edge on that chain:
(a) merge pl K1+K2 chains via source restructure that keeps bytes, (b) find the real live
value from the original (live-set delta says a GPR crosses the K=1 sqrtf in target beyond
ours - candidates: pairId/r6-band value or an np-lifetime extension), (c) decode nadj
computation (InterferenceGraph 0x57bad0 setter) and trace which edges the target-shaped
code adds. gi (u32) in the committed decls is DEAD - vestigial, remove in final cleanup.

## pl-chain index: structure-fixed, decl-immovable; SET_PLANE staging moves it at a cost
- pl decl position (early/late): NO effect on the K1 chain slot (du-split chains renumber
  independent of decl; K0 folds so even the "first" chain is a split).
- pl/po staging in SET_PLANE (all 4 wg sites): curve=r22 ACHIEVED (chain-count theory
  confirmed) but wg-block staging materializes +7 instructions (prop-off keeps named
  pointer addis; target folds them into wg-reg displacements).
- Next narrowing: try staging at exactly ONE wg site (K=3, nearest the NEWPATCH code) =
  +1 pl chain, +~2 instructions; note baseline is ALREADY +2 instructions vs target
  (the site-1 duplicate add r3,r30,r3) - the true original may trade these (the staging
  form could REPLACE the +2 with its own materializations, netting byte-equal).

## BREAKTHROUGH: K=3-only wg staging -> 117 regions (probe wgfep_117.c)
Expanding ONLY the wg K=3 SET_PLANE with pl/po staging (po = &wg->planeOffsets[3];
pl = &wg->planes[3]; before the sqrtf) gives the pl-chain census the target needs:
curve=r22, wg/wg1=r21, wgB=r22 ALL CORRECT, regions 140 -> 117 (best). Remaining:
+4 instructions total (2 baseline site-1 extras + 2 new addis from the staging - the
original may express K=3 differently to net zero), and the p/pp/listWalk/listIndex grant
cluster rotated down one slot (p=r26, pp=r25, listWalk=r25, listIndex=r24, back=r27,
slot36=r29) - retune their decl positions against the new census next.

## Register-complete config scored: 97.40 < baseline 97.83 (kept baseline in tree)
The 113-115-region configs (wg=r21 wgB=r22 curve=r22 p=r27 pp=r26 listIndex=r25 + K=3
staging) score BELOW baseline due to +4 structural instructions (objdiff weighting).
To land the win, eliminate the instruction excess: (1) the baseline site-1 +2 (duplicate
add r3,r30,r3 - the wgB/lp staging shape), (2) the K=3 staging +2 addis (target's wg-K3
block presumably folds them - VERIFY by comparing that exact block; if target K3 lacks
the addis, find the alternative +1-chain source). When instruction-neutral, the register
alignment (~60 lines) flips the score decisively past baseline. Probe: wgfep_117.c + the
decl retunes (p before slotPtr, pp/listIndex/listWalk order per anchors above).

## Target wg-K3 verified: NO staging addis (addi rX,r21,12/28 absent in first loop)
The +1 pl-chain the census needs must be a ZERO-instruction web in the target (like the
phantom sdata2 anchors). Site-1 accumulate form also still open: mp4 CharMotionCreate
proves add-then-addi with a register base comes from a DECLARED 2D array with legal inner
index (charDirTbl[i][2], inner < row size); our +0x3000 exceeds any legal row - so site-1
is NOT a 2D subscript either; both remaining shapes point to an addressing construct not
yet identified (possibly the original declared the patch/walkgroup arena with a type that
makes +0x3000 a legal member/element step, e.g. ObjfsaPatch rows of 0x100 with walkgroup
overlay via union). NEXT: probe an arena UNION type: union { ObjfsaPatch p[0x100];
struct { u8 pad[0x3000]; ObjfsaWalkGroup w[0xB5]; }; } and access w[grp] - check both the
association order AND whether its address web census adds the K1-chain slot.

## Site-1 accumulate: all source forms exhausted (union, 2D, move-chain under prop-off)
Union arena reassociates; wg=wgB move under prop-off does NOT coalesce into the accumulate
(and costs a region). Full elimination list for [add rW,r30,r0][addi rW,rW,12288]:
plain expr, char-cast chains, u32-cast, ObjfsaPatch[0x100] two-level, u8(*)[40] 2D,
union member+subscript, self-reassign (prop-off), wgB+move-chain (prop-off). The construct
producing target's accumulate remains unidentified - next candidate is decoding the CMachine
addressing emitter (0x4c2xxx band) for when it targets the dest register for subexpressions,
or accepting the +2 site-1 cost and hunting the score crossover elsewhere. Best probe state
remains wgfep_117.c + decl retunes (113 regions).

## Corpus-negative: the accumulate shape does not exist in 10,469 reference functions
`add rX,rY,r0; addi rX,rX,<const>` (any const >= 1000, and the mulli-40 variant) has ZERO
occurrences in the entire GC/2.0 refcorpus (both_off profile). The target site-1/tail wg
shape is not producible by any ordinary expression under this compiler configuration -
consistent with every source-form elimination. Remaining explanations: (a) the CMachine
addressing emitter takes a special path under conditions not present in the corpus
(decode 0x4c2xxx), (b) the original passed a different optimization configuration for this
TU than the corpus profiles (but pragma experiments bound this), or (c) the two-statement
form colors coincidentally in the target via a coalesce eligibility our build misses
(decode the upstream move-descriptor flag setting - the same open item as func1C's
materialization direction; likely ONE shared answer).

## Coalesce-eligibility decode: exact addresses mapped
Flag writers (or byte [desc+0x24], imm): full-coalesce |=6 at 0x4d036b and 0x4d0fc9
(inside marker fn ENTRY 0x4d0ea0 taking (value, srcWeb, dstWeb), sets class=4 at +0x25,
webIndex pair at +0x26/+0x28); |=2-only at 0x4d0bd3/0x4d10d6/0x4fe5ef; loop-pin |=0x40 at
0x4accd9/0x4acfa4/0x4b0a76/0x4dd8dd. CALLERS of the |=6 marker: 0x435f9e and 0x435fb8
(CodeGenNumbering band - the "upstream during web/move building"), 0x4adc30, 0x4d0355,
0x5268a6/0x52690a. Disassembling the guard conditions before the 0x435f9e/0x435fb8 calls
yields the eligibility rule - the single shared decode expected to explain BOTH residuals
(walkgroup accumulate register sharing + func1C preheader materialization direction).

## Coalesce eligibility DECODED (guard at 0x435f14-0x435fb8)
Full |=6 identity-coalesce fires ONLY when: src web numbered, eligibility bytes ok,
instr-kind in a small set, AND src web index < 10 (cmp ecx,0xa; jge skip) - i.e. only
copies involving PRECOLORED/first-ten webs (parameter/return homing, and reg-pair marking
with dst=src+1 under global 0x5e4820). GENERAL variable copies never get identity-coalesce
under this compiler. Consequence: the target's same-register accumulate at walkgroup site-1
is NOT coalesce-driven; with source forms and coalesce both eliminated, the remaining
explanations are the CMachine addressing emitter's dest-targeting path (0x4c2xxx) or a
coloring coincidence reachable by web-order steering (the func1C-style levers). The
kind-2/[ecx+6]==0x13 skip under global 0x5e4843 is a mode flag worth checking against
compiler options.

## Accumulate: proof by elimination -> CMachine dest-targeting emission
du-chain analysis: def1 (wg = &base[grp]) and def2 (wg = wg+0x3000) share no def/use =>
always separate webs => the target's single-register [add r21][addi r21,r21] cannot be two
webs (the short def1-chain can never earn a saved reg) NOR one variable-web (unconditional
redef splits) NOR coalesce (decoded: precolored-only). Therefore the target emitted BOTH
instructions for ONE IR value: the CMachine addressing emitter evaluates the (base+idx*s)
subexpression directly INTO the destination register and adds the displacement in place -
a dest-targeting path our source forms do not trigger. Decode entry: the addressing
emission in the 0x4c2xxx band (CMachine.c, 94 funcs at 0x4bf320-0x4c9590 per assert map);
find the condition separating dest-targeting from temp-materialization (likely whether the
value is single-use/addressing context). This same emitter decision plausibly controls
func1C's preheader materialization direction - one decode, both functions.

## Association analysis completed: 2D/member decompositions mathematically dead
The mp4 add-then-addi cases (charDirTbl[i][2], arr[i].member240) all have the constant
WITHIN the element (inner < row/sizeof). Our +0x3000 exceeds any 40-stride element =>
no legal 2D/member decomposition exists. The dest-targeting DOES fire for single
expressions (accumulate emitted into the dest reg) with the constant grouped first -
the association choice inside the CMachine addressing emitter is the precise decode:
what makes it emit (base+idx) before +const when the const cannot be an element member.
Note the target may simply canonicalize the same way ONLY when the addressing node comes
from a specific IR shape (e.g. pointer-arith on a typed pointer vs int) - enumerate the
IR-node kinds at the emitter dispatch (0x4c2934's 0x1e000000 kind-bits switch is nearby).

## Emitter decode reading list
Kind-classifier (0x4c2920, dispatches on RegInfo 0x1e000000 bits) callers = the CMachine
operand/addressing emission functions: 0x4c06ee, 0x4c0982, 0x4c0f4f, 0x4c0fcf, 0x4c1068,
0x4c10d1, 0x4c11d8, 0x4c122f, 0x4c1288, 0x4c12e7 (one dense band = the per-operand-kind
emitters), plus 0x4c27c0. The ADD-node addressing emitter among these carries the
association/dest-targeting condition. Disassemble the band (capstone one-shot as done for
0x4d0ea0/0x435f14), identify the (base+idx)+const vs (idx+const)+base branch, and map its
guard to an IR/type property expressible in source. Signed-int cast eliminated (same
reassociation) - the cast-kind space is fully exhausted.

## Emitter band decoded one level: depth-driven subtree order; association set by the FOLDER
0x4c0f00-region = recursive node-kind-dispatched (jump table 0x5b09f0) MAX-depth walker
(Sethi-Ullman style) - the emitter evaluates the DEEPER subtree first. Hence:
- target tree ((base + idx*40) + 12288) emits add-then-addi (deep left first) = accumulate;
- our trees are pre-folded to ((idx*40 + 12288) + base) by the constant folder, yielding
  addi-then-add. The association battle is therefore at PARSE/FOLD time, not emission.
- Also proven: the two-statement wgB form can never color both instructions into r21
  (a short chain cannot earn a saved register - validated volatile rule), so the target's
  form IS a single expression whose (int + int) addends were NOT folded.
NEXT (tiny-probe fold survey): enumerate 2-line probes of every pointer/int node
combination checking which prevents (idx*stride + const) folding - the survivor is the
original's expression form and closes walkgroup site-1/tail AND probably func1C's
materialization direction in one stroke.

## ASSOCIATION RULE CRACKED (fold survey)
`base + (idx * 40 + 0x3000)` — WITH the inner parentheses — emits the target accumulate
[mulli][add rD,idx,base][addi rD,rD,12288] (fold survey fH/fJ/fK; fK matches the exact
walkgroup site-1 shape including the u8 curve load). The flat form folds const-first; outer
parens fold back under prop-off. Applied to all three wg-address sites: they become
BYTE-IDENTICAL to target except one commutative-operand order at site-1 (add rD,idx,base
vs target add rD,base,idx - base evaluated first there; probably base-subtree depth in the
real context; minor 1-line cost).
Scores measured: baseline 97.83; accumulate-only 97.57 (removing the wgB staging shifts
the web census negatively); hybrid (accumulate + fresh-tail + decl moves, no K3) 97.81;
hybrid + K3 staging 97.61 (K3 costs more than curve gains due to an fdivs-order break in
the manual expansion - fix that expansion bug first). FINAL MILE: fix the K3 expansion
ordering, re-add it, then rebalance the decl tuning for the new census - the 8/8+curve
register file with matched accumulates nets past baseline once the K3 expansion is
byte-clean. All probes in scratchpad; forms recorded here.

## Refined K3 lever + cluster status (probe wgfep_113.c)
po-ONLY staging at wg K=3 (`po = &wg->planeOffsets[3];` + direct planes[3] stores) gives
curve=r22 at just +1 instruction (1271). With p-before-slotPtr and pp/listIndex order:
113 regions, anchors wg/wg1=r21 wgB=r22 curve=r22 p=r27 pp=r26 listIndex=r25. Remaining
cycle: listWalk(r24->r26), back(r27->r24), slot36(r29->r28), slotPtr(r26->r27; must color
AFTER listWalk so interference pushes it to r27 - single moves cascade; needs a scripted
permutation sweep over decls {slotPtr, pp, listIndex, listWalk, slot} (~15 targeted orders)
plus the site-1 commutative-operand line. Then score - expected to cross 97.83 given the
accumulate sites are byte-matched and the instruction excess is down to +3.
