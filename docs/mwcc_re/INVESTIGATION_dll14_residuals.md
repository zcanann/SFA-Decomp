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
