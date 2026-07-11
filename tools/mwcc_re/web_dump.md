# web_dump.gdb — per-web Select/fallback tracer

Companion to `validate_select.sh`. Breaks on Color_Select's assignment
(0x50899e) and the reserved-reg fallback (0x5089c4) and prints, for every
colored web: class, web index (+0x10), static degree/nadj (+0x18), and the
chosen register. Driver entries (0x508680) delimit per-class passes.

    gdb -batch -x tools/mwcc_re/web_dump.gdb --args \
      build/tools/wibo build/compilers/GC/2.0/mwcceppc.exe <FLAGS> -c <unit.c> -o /tmp/out.o

Read the output as: `F idx=.. nadj=.. reg=..` lines are saved-register
(fallback) assignments in stack-pop order — the r31-descending sequence.
Diagnosed on mmp_moonrock_update: a saved-pair mismatch vs retail is decided
by (web index, static degree) pop order; function-scope decl order shifts a
named local's web index (first decl → highest), block decl order does not.
The vreg-numbering rule that fixes cross-scope index gaps (e.g. def idx38 vs
list idx35 with target wanting def < list) is still undecoded — that is the
next unlock for the reg-perm family.

## Confirmed numbering rule (probe-validated, GC/2.0 -O4,p noopt)

Three controlled probes (3-4 call-crossing locals, permuted decl vs assignment
order) pin the rule: **web index = DESCENDING in declaration order** (first
declaration → highest index), across nested block scopes too (block decls slot
in sequence after the enclosing decls). Assignment order does not move indices.
Fallback (saved-reg) pop order then follows (index, park-round): r31 to the
first-declared web of the highest park round, descending.

Validated consequences:
- crrockfall_update: exhaustive 24-permutation search over its 4 decl-inits —
  the committed order is already optimal (9 regions); all others are worse
  (10-33). The residual web is a SPILL-ROUND split (idx 62 vs sibling idx 33),
  outside decl control.
- invhit_update (idx 86), hoodedZyck_updateB (spilled turnRaw reload):
  same spill-split class.
- mmp_moonrock_update: cross-scope gap (fn-scope def idx 38 vs block list
  idx 35) — fn-scope decls always outrank block decls, so unreachable by decl
  reorder.

=> The remaining reg-perm near-misses hinge on the SPLIT-WEB numbering inside
SpillCode.c (0x57c290 band): what vreg number a spill-split web receives, and
therefore where it pops. Decode that and the family at 99.6-99.98 closes.

## DECODED (2026-07-07): split-web vreg allocation site
SpillCode.c 0x57c4c0-0x57c4d5 (and the twin at 0x57c636): when inserting spill
code for a move whose src (op+0x34) AND dst (op+0x28) webs are both flagged
spilled (web+0x16 & 1), the new intermediate web's vreg is allocated as

    esi = webEnd[class]          ; 0x5e9b04(,cls,4)
    webEnd[class]++              ; incl — APPEND at the end
    assert(esi <= 0x7fff)        ; SpillCode.c line 0xdb

i.e. **spill-split webs are appended past all existing webs** — they carry the
highest indices in the next Build/Simplify/Select iteration. Named locals keep
their decl-descending indices below them. So a split web always sits at the
index extreme, which is why no decl reorder can move a residue caused by one
(crrockfall idx62, invhit idx86, the playerState1D prev/tbl r30/r31 pair).
## DECODED (2026-07-10): park threshold + saved-reg grant order (traced live)
Validated on DIMSnowHorn1_update and ktrex_update (both now 100 without
opt_lifetimes):
- GPR park threshold is STATIC: a web parks iff nadj >= 30.
- The FALLBACK path reserves new saved registers r31-DESCENDING (one per pop).
- The normal Select path grants a web the LOWEST-numbered already-reserved
  saved register free of interference.
- Consequence + lever: a web sitting just under the park threshold (e.g.
  nadj=29) colors late and loses its retail register to a later-created temp.
  Adding exactly one interfering web pushes it over the threshold and restores
  the retail order. Plausible sources for that web: an inlined static helper's
  return-value copy (DIMSnowHorn1_angleTo), a select temp from a ternary, or a
  shared named local with register uses (hudDrawCMenu's zero). Zero extra
  instructions in all three forms.

What remains undecoded is only the *pop interleaving* of these appended webs
across multiple spill rounds — needs the live tracer (gdb absent on this host;
port select_dump.gdb to lldb/Rosetta to continue).

## Volatile-class pop order (confirmed on objseq, GC/2.0 noopt)
A-line streams show volatile FPR/GPR classes pop in strictly DESCENDING web
index (LIFO of creation), taking the lowest register free of colored
interfering neighbors. The remaining near-miss register pairs
(RomCurveInterp f2/f3, gunpowderbarrel fsubs dest, moonrock r27/r28,
appleontree f4/f0) all hinge on ONE neighbor's live range differing at a
specific pop. Next tracer upgrade: print each web's def PC (walk the web
descriptor for its first pcode ref) so indices map to instructions; then
the differing neighbor is directly identifiable and its source construct
can be targeted.

Recovered-but-parked source structures (verified against target shape):
- RomCurveInterp: `segmentT = segment; segmentT += (t - times[s+2]) / (...)`
  reproduces fsubs f31 seed + fadds accumulate; adopt once f2/f3 flips.
- inpInit zero-fill: CTR-4 loop, 2x16 stw groups with kept +64 bumps and a
  live counter joined to the zero-constant web (class-A join).

Additional verified-but-parked reconstructions (register-rotation gated):
- Lightfoot_UpdateButtonTimingChallenge: `w` is u16-typed (readback gains the
  target's clrlwi r26 def-mask) but adopting it rotates the whole saved bank
  by one (v/params shift); pair with the rotation fix.
- DRlaserturret_handlePromptChoice: both diff sites imply one extra live
  volatile web in the target (countValue web r4 spanning to the vtable-chain
  site); the occupying web is unidentified — first target for the val-pointer
  correlation workflow.
- RomCurveInterp: magic-double web (idx 35, nadj 8, shared with the two scale
  conversions) must be created before the while-loop's times load (idx 34);
  creation point is constant-pool materialization, not statement order —
  needs the vreg-numbering disasm (IroLinearForm band).

## audio.c trio findings (2026-07-10, main/audio holdouts — negative map + one landing)
Sfx_UpdateLoopedObjectSounds 98.38→99.35 (committed 859e13ff08) via two levers:
- loop-2 counter must be a FRESH `s16 i2` (reusing loop-1's `i` keeps its r26 home
  by affinity; fresh counter+ip2+op2 take r25/r26/r27 in creation order).
- `(u16)i` spellings on the memmove arg1s + size subtractions (keeping the named
  `index` ONLY at its embedded def + one index2 use) drop the index web's priority
  two slots — tree-level ref weight is real and per-use (V24 3-ref cut inert,
  V25 full cut moved it). Full un-naming breaks the cross-call CSE (recompute per
  statement); the embedded def `(index = (u16)i)` is the sz-first eval anchor
  (standalone def reorders count reload, −8pts).
  RESIDUAL (fp r27↔index r30 adjacent swap): index def-node respellings
  ((u16)(u32), i&0xFFFF) break VN-merge with the (u16)i uses (−9pts); fp[0]/&flags[i]
  spellings, decl permutations, block re-decls, dead index=0 seed, O1/O2/O3,
  loop_invariants/strength off — ALL inert. Park/pop-interleave class.
Sfx_UpdateObjectChannel3D 99.01: 3-web rotation (param objCh r31→r29, slot r30→r31,
  spilled `level` reloads). #126 u32-param retype INERT (13 cast-noise derefs keep
  it top); same-type copy + void*+cast local both propagate away (index unchanged);
  named handle web in keyoff arm folds into arg (no web). Param web index is
  usage-bound-appended (top) in our build; target has it below ALL locals —
  spill-round interleave class (level spills in both).
Music_Update 99.60: single ch(r21T/r22C)↔i(r22T/r21C) adjacent swap ×27 regions.
  `int i;` decl before `ch` surfaces the target's `addi r0,lo; mr rX,r0` init shape
  (separate addr-temp web!) but does NOT flip the pair (50 pure-swap regions,
  99.13 — structurally closer per the fn_801B3DE4 lesson; % hides it). ch2 split
  (middle loop) −1.4; block-scoped ch −1.2; fresh j middle counter inert;
  opt_lifetimes off −2.0. Hypothesis: ch parks (nadj≥30), i doesn't; target needs
  i parked too or ch unparked — needs the live tracer to see nadj values.
=> All three = the parked pop-interleave family. Next unlock: lldb port of
select_dump.gdb (gdb absent on this host) to read nadj/web indices live.

## lldb port attempt (2026-07-10, this host)
Scratchpad script web_dump_lldb.py (python callbacks mirroring the gdb tracer,
rbx/rcx/rax low-32 reads) arms cleanly, but: (1) the build invokes
`wibo sjiswrap.exe mwcceppc.exe ...` and the compiler runs where the parent
lldb session's call_EntryProc one-shot never fired (spawn model unclear);
(2) direct `wibo mwcceppc.exe ...` (no sjiswrap) HANGS >2min on this host even
without lldb — sjiswrap is load-bearing, so the gdb doc's direct invocation
does not transfer. Next session: either replicate sjiswrap's env/handshake for
a direct-wibo run, or make lldb follow into the spawned child
(target.process.follow-fork-mode child equivalent / attach-on-spawn by name).

## lldb port part 2 + corpus mining (2026-07-10 late, audio trio)
- Direct `wibo mwcceppc.exe` does NOT hang (earlier note wrong — env artifact).
- lldb tracer arms PE breakpoints fine (script: gdb flow as -o sequence, arm via
  script fn after the call_EntryProc stop). BLOCKER: first `process continue`
  dies at EXC_BAD_ACCESS code=2 addr=0x982180 — wibo's guard-page/lazy-commit
  fault, which lldb intercepts as a Mach exception BEFORE wibo's signal handler.
  `process handle SIGSEGV/SIGBUS --pass` does not help (Mach layer);
  `settings set platform.plugin.darwin.ignored-exceptions EXC_BAD_ACCESS`
  (even via -O pre-target) did NOT suppress interception on lldb-1700/darwin25.
  Next: try debugserver flag, or run the gdb tracer on a Linux host (works as
  documented), or teach wibo to pre-commit its arenas under a debugger env var.
- refcorpus (mp4, both_off, 9740 fns) mined: HuAR_MRAMtoARAM2 (armem.c) shows a
  prologue param→r29 (LOW saved) with call-result copies above it — but its
  param has only 3 pass-through refs (no derefs). audio.c ObjectChannel3D param
  (13 derefs) resists ALL spellings: u32 retype+casts, void*+casts, void*+typed
  local, same-type copy last-decl — all byte-inert on coloring. In-repo oracle:
  no other matched unit has the Music_Update addi/mr/li walker+counter pair.
- Music_Update extra negatives: #131 no-op `|` on ch init VN-folds (symbol addr
  is cheap-remat, no surviving copy); loop-3 block-scope ch2/n split −1.4;
  ternary-temp/handle-web injections fold. The i/ch pair swap remains
  tracer-gated (need live nadj/web-index values).

## lldb port WORKING (2026-07-11, macOS arm64 + Rosetta)
The port works; the two prior blockers resolve as:
- macOS wibo has no `call_EntryProc` symbol. Break on `wibo::loadModule`
  instead (fires after the PE is mmapped at its preferred base 0x400000),
  THEN create the address breakpoints and continue. Address breakpoints set
  before the mapping never re-arm (wibo maps the PE manually, lldb sees no
  module event).
- Direct `wibo mwcceppc.exe <full ninja flag line> -c unit.c -o /tmp/x.o`
  runs fine on dll_02BC_andross.c (ASCII-only). If a unit hangs without
  sjiswrap, suspect SJIS content, not the spawn model.
Scripts: `select_trace_lldb.py` (Color_Select assign 0x50899e / fallback
0x5089c4 / driver 0x508680 -> "A/F cls= idx= nadj= reg=" stream) and
`numbering_trace_lldb.py` (0x4fe563, ebx=RegInfo desc after 0x4d0150 call:
logs webIndex=webEnd[cls]++ order plus desc+0x4 priority and desc+0x24 flags).
Driver template (batch file): import script; bp wibo::loadModule;
process launch -s -- <compiler argv>; continue; <setup cmd>; continue.

Findings on andross_update (validated against retail regs, 2026-07-11):
- Select order observed = parked pair first (obj nadj~1008 -> r31, state
  nadj~975 -> r30 in every variant), then the named long-lived webs in
  strictly DESCENDING web-index order taking r29,r28,... then low-degree
  webs (case-body `moveState = boss->extra` chains, nadj 15-20) coloring
  LAST via reuse = lowest-numbered reserved reg free of interference.
- GetReservedReg hands r31..r24 in first-need order (persistent counter
  confirmed); a web that colors after r25/r24 are reserved will reuse them
  (the andross case-web r26(T) vs r24/r25(C) family) — the fix class is
  making the r25/r24 claimants color AFTER the case webs (index order),
  not register hacking.
- desc+0x4 priority is real and accumulates (state 1362, obj 252, spawnSlot
  60, switch-flag 30-33, stateChanged/work 17, pathAdjusted 4 on this fn);
  numbering order is NOT globally priority-sorted — it is batched, with one
  u8 flag per compile deferred ~20 slots past its init batch (the "73-slot").
  Which flag defers follows declaration order among the non-switch flags;
  the heavily-tested switch flag never defers. Mechanism not yet pinned —
  next target: trace CodeGen_NumberWebs' worklist (0x4f0e90 push, 0x4357c5
  Number commit) to see batch boundaries and the deferral gate directly.

## DECODED (2026-07-11): web identity = vreg union-find, root = MIN vreg
0x57b470 (WebBuilder) allocates gWebArray[webEnd[cls]] — ONE WEB PER VREG
(web+0x10 = the vreg number). Adjacency comes from the triangular bitmatrix
at 0x5e3144 indexed by vreg pairs (i*i/2+j). A union-find parent array at
0x5e3140 (s16 per vreg) coalesces copy-related vregs:
- Union site 0x57b917-0x57b947 (InterferenceGraph.c): after find(src)/find(dst)
  (path-walk at 0x57b820/0x57b840), if the roots differ, do NOT interfere
  (bitmatrix test 0x57b86c-0x57b8c2), pass the per-class special-vreg gate
  (0x5e9d86, cls 4) and the per-function vreg-window gate
  ([0x5ea1da[cls], 0x5e9730[cls]] for vregs >= regcount):
      parent[max(rootA, rootB)] = min(rootA, rootB)
  => the merged family is colored at the MINIMUM member's vreg position.
- 0x57b470 then marks non-root webs flags|=4 and stores the root in web+0x14,
  so Simplify/Select only ever see the root web.
CONSEQUENCE: a variable's effective coloring index can be PULLED DOWN by any
coalesceable copy whose value numbered earlier (smaller vreg), and the
"deferral"/"pin" families observed in select traces are artifacts of which
family member is the min. The remaining unknown for the andross sc/swf swap
is the vreg-numbering batch rule (per-instruction worklists, 0x4f0a90 reset)
— next instrumentation: log 0x4fe550 value ptrs + 0x57b947 union pairs and
reconstruct families offline.

## DECODED (2026-07-11): the vreg-numbering DEFERRAL (two-pass split)
CodeGen numbering runs TWO passes over worklist 0x5e99c4 (driver 0x435de5):
- PASS 1 (call site 0x435e4a): numbers cells where predicate 0x4e9380 is 0.
- barrier 0x4d0220, then PASS 2 (0x435eba): numbers cells where it is 1.
Predicate 0x4e9380(cell->value+0xa): TRUE iff the pointer is NULL or points
to a node whose kind byte (+0xa) is 0x40 or 0x24. Traced on andross_update:
the early flags (state/pathAdjusted/work/flag/boss) carry NAME pointers at
value+0xa (predicate false -> pass 1 -> low vregs -> good saved regs), while
stateChanged's canonical value is an EXPRESSION NODE of kind 0x40 (pass 2 ->
vreg ~72 -> tops the desc-index color order -> r29). This is the whole
sc(r29)/switch-flag(r28) swap on andross_update, and it is INERT to every
source-level lever tried (24 decl perms, 6 init perms, +=/=, latch temps,
scratch-variable identity, block scoping): the canonicalization happens at
CIR level (which flag's zero-init/phi becomes a kind-0x40 temp), i.e. the
same IroLinearForm frontier already documented for smallbasket axes.
Remaining unlock for this family: identify node kind 0x40/0x24 semantics in
the CIR opcode table and what C shape flips a flag between name-canonical
and expression-canonical.

## andross_update residual (2026-07-11): full root-cause map at 99.760
The remaining 215 regions on andross_update all hang off ONE numbering fact:
a compiler temp (HashName "@1348", per-class GPR vreg 72) outranks every
user-named local (names number pass-1 into vregs ~44-50, reverse-decl order;
@/$ temps number pass-2, always higher). Select colors descending vreg, so
the temp takes the r29 reservation and shifts the switch flag (vreg 49,
nadj 168) to r28 — retail has the switch flag ON r29. Facts pinned live:
- vreg spaces are PER-CLASS (webEnd[cls]); FPR vreg 72 is a different web.
- @1348's web (Apply operand trace, tools/mwcc_re/apply_trace_lldb.py):
  an li def + a guarded-merge pseudo (dst==src, label operand) + clrlwi
  reads — i.e. part of stateChanged's latch dataflow, live-range-split off
  the named web (vreg 48; the two share r29 F+A without interfering).
- `#pragma opt_propagation off` removes the temp (sc name-binds to r28) at
  the cost of +40 instrs -> IroPropagate creates it. Not shippable.
- INERT levers (all tried, byte-stable at 215 regions): 24 decl perms,
  6 init orders, latch temp choice (found/ref/work), found-free latches
  (both), if/else-empty + braceless + +=/= forms, case-scratch variable
  identity (flag vs stateChanged), (void)&x and *(&x)=0 escapes,
  block-scoped loop locals, 8 spawn-loop formulations.
- Downstream of the same layer: case-body webs reuse r25/r24 instead of
  r26 (the off/zext temps' reservations land before the case webs color),
  and the f30/f31 fadeAlpha pair.
NEXT UNLOCK (precise): decode IroPropagate's driver (0x470060 band) for the
transformation that splits a zero-init'd, conditionally-set u8's dataflow
into an @-temp — the predicate that fired on OUR stateChanged but not on
retail's — then find the C shape (or absence) that retail used. All tracer
tooling to verify a candidate in minutes is checked in.
## audio trio part 3 (2026-07-10 later): fast probe harness + residuals LOCALIZED
Harness: copy audio.c to scratch probe.c, compile DIRECTLY via
`wibo sjiswrap mwcceppc <exact build.ninja flags>` (~8s vs ~40s locked_ninja
loop), objdump the one fn, grep the pair regs. Battery of ~15 more variants run.
- Music_Update DECISIVELY LOCALIZED: prologue, loop-1 (ch=r21,i=r22 with the
  addi r0/mr r21 init) and middle loop (volatile r3 walker, mtctr) ALL MATCH
  TARGET already. The ONLY divergence is loop-3's re-init webs: variables split
  per live range (3 webs each for ch/i); loop-3's ch3/i3 pop in the wrong order
  → Select's lowest-reserved-free grant gives i3 r21/ch3 r22 (target: ch3 r21,
  i3 r22). Loop-1 grant order is IDENTICAL in both builds (i1 pops first,
  fresh-reservation descending gives i1=r22, ch1=r21) — the fallback-vs-reuse
  grant asymmetry means the same pop order yields opposite regs at loop 3.
- KEY negative: swapping loop-3 init statement order FLIPS THE EMISSION
  (li r21,15 before lis/addi r22) but NOT the coloring — pop order between the
  two webs is invariant to evaluation order, creation order, decl order/position
  (incl. fn-scope re-decls), variable NAMES, init spellings (+0, casts, &[0],
  no-op |=), register keyword. It is priority(desc+0x4)-driven and desc+0x4 for
  these two webs differs in a way none of those levers touch.
- Sfx_UpdateObjectChannel3D: param-web-first is equally invariant (u32/void*
  retypes, alias locals, register, full decl reversals). Param usage-bound web
  outranks all locals in our build; target has it below ALL — same class as the
  mmp_moonrock cross-scope gap (doc'd unreachable by decl means).
=> Both fns now reduce to reading desc+0x4 for 2-3 specific webs. The tracer
(or the desc+0x4 accumulation-site disasm in CodeGenNumbering.c band — the
doc's OPEN item) is the only remaining path. lldb blockers logged above; the
accumulation-site STATIC disasm may be the cheaper route: objdump the
0x435650-0x4357ef numbering loop's callers writing desc+0x4 and read the
weight rule directly.
## Music_Update TRACED (2026-07-11, this host — tracer recipe confirmed working)
Working invocation on this host (paths differ per session; adapt LOG path):
  lldb -b -o "command script import <scratch>/mwcc_trace.py" -o "b wibo::loadModule" \
    -o "process launch -s -- <compiler> <exact build.ninja cflags> -c probe.c -o probe.o" \
    -o continue -o continue -o mwcc_trace_setup -o "breakpoint delete 1" -o continue \
    build/tools/wibo
  (TWO continues before setup: first loadModule stop is BEFORE the PE maps; arm
   at the SECOND stop, then delete bp 1. Arming early → guard-fault EXC_BAD_ACCESS.)
Select trace, cls=4, Music_Update batch (pristine source):
  F 43→r31 42→r30 41→r29 40→r28 39→r27 38→r26 37→r25 (decl-block, reverse-decl)
  F 80→r24, 79→r23 (fadeA/fadeB call-result copies, pass-2 high vregs)
  F 49→r22 (i1)  |  A 48→r3 nadj=30 (middle volatile walker)  |  F 47→r21 (ch1)
  A 45→r21 (loop-3 counter family)  |  A 44→r22 (loop-3 walker)  ← THE RESIDUAL
  F 36→r20 (found20)  F 35→r19 (found19)
Numbering commits (0x4fe563): idx44 pri=9, idx45 pri=245, idx47 pri=9,
idx48 pri=69, idx49 pri=201. The loop-3 counter's ROOT web (45) carries pri 245
(union-find family accumulation — cf. root=MIN-vreg decode above); the walker
web 44 only 9. Statement-order swap of the loop-3 inits flips EMISSION but the
vregs stay 44/45 (canonicalized upstream) — confirmed by identical trace.
=> The flip needs idx44 to commit AFTER idx45: either the union family around
45 must lose a member numbered before 44, or 44's value must go pass-2
(name→expression canonical). NEXT: log union pairs at 0x57b917-0x57b947 for
this batch and reconstruct the 245-family; then find which C value seeds it.
Battery (final-reg reads, all keeping 44<45): init order, +0, casts, &[0],
no-op |=, register, decl perms/reversals, fresh i2/ch2 (fn+block scope),
block middle loop, ternary/handle temps, O1/O2/O3, opt_lifetimes off,
loop_invariants/strength off. All inert or regressive on the pair.

## Music_Update union-pair trace (2026-07-11, combo tracer: N+U+A/F in one run)
Union write decoded at 0x57b947: `movw %cx,(%eax,%edi,2)` — cx=min root (new
parent), bx/edi=max root (child). Music_Update cls=4 unions:
  76→67, 75→65, 109→48(middle volatile walker), 74→59, 73→58, 118→49(i1)
NO union touches 44 (loop-3 walker) or 45 (loop-3 counter) — they are own
roots, so the counter's pri=245 vs walker's pri=9 is INTRINSIC, not family
accumulation. Numbering commits run in vreg order (44 before 45) regardless of
priority — priority does not order commits within the batch; it must gate
something else (worklist scan pick under equal batch conditions?).
OPEN (the actual flip): why does the loop-3 counter value carry pri 245 (and
i1 201) while the 30-ref walkers carry 9? 245/201 smell like loop-weighted
CONSTANT ref weights (the 15/0x1f4 constants?) — if 45 is actually the
CONSTANT-15 value web (not the counter variable!), then the loop-3 'counter'
register is the constant's web and the flip lever is how the 15 literal is
seeded (shared vs per-loop). Next probe: apply-trace idx 44/45/49 operand dump
to identify their defs (5-minute run with tools/mwcc_re/apply_trace_lldb.py,
filter idx in {44,45,47,48,49}, read PCode opcodes).
Combo tracer script pattern saved in this entry's session scratchpad; recipe
identical to the select tracer with extra bps 0x4fe563 (numbering commit) and
0x57b947 (union write).

## DECODED (2026-07-11): Music_Update loop-3 pair — full mechanism, identities corrected
Apply-trace (P-lines, operand dumps) fixes the identities:
  vreg44=i1 (li/cmpwi/addi -1 pattern, 4 uses), vreg45=ch1 (34 base-uses, def=copy
  from addi-temp vreg83 — the surviving mr r21,r0), vreg47=i3 (4 uses),
  vreg48=middle volatile walker, vreg49=ch3 (29 uses; addi-temp 118 UNIONS into it
  → the direct addi r22,r3,0 form ✓ shapes all match target).
MECHANISM (all traced): numbering runs in program-region sub-batches; within a
sub-batch, vregs are assigned in ASCENDING desc+0x4 priority
  loop1 region: {i1:9, ch1:245} → 44,45;  tail region: {i3:9, mid:69, ch3:201} → 47,48,49.
Select pops descending vreg; saved-reg FRESH grants come from the persistent
r31-descending exhaust counter (NOT lowest-free): after the decl block + fade
copies eat r31..r23, ch3(49) pops first → r22, i3(47) → r21; loop-1 webs then
REUSE (lowest-free reserved): ch1(45)→r21, i1(44)→r22. Loop 1 matches retail;
loop 3 is swapped. Retail requires i3 to pop BEFORE ch3 ⇒ i3-pri > ch3-pri in
the tail region ⇒ the counter must out-priority a 29-use walker (201) — no C
spelling reaches that (counter has ~4 refs). Phi-init (same-value both arms),
i|=i, |=const all constant-fold; statement order canonicalizes; decl order,
fresh vars, block scopes shift whole banks (regress).
REMAINING UNLOCK (precise, small): the desc+0x4 ACCUMULATION rule — what makes
245/201 for walkers, 9 for counters, 69 for the volatile walker — then find the
loop-3 C shape that either lowers the walker below 9 or (more likely) reveals
the ORIGINAL used a different construct entirely (e.g. the counter carrying an
address or the walker derived per-iteration). The accumulation site is the one
OPEN in CodeGenNumbering.c (static disasm task, no tracer needed).

## Music_Update final negatives + next-session seed (2026-07-11)
- Folded-alias weight transfer ((MusicChannel*)((u32)ch + (i - i)))->f: the
  (i-i) does NOT fold clean under -O4,p noopt (subf/add materialize, +8 instrs,
  volatile churn) — the identical-asm-paradox trick can't move tree weight here.
- Same-value phi init across the fadeA if: front-end merges (no phi web).
- Sub-batch-region hypothesis (untestable by source): numbering sub-batches map
  to program regions ({loop1}, {found/fade}, {mid+loop3}); if i3's value could
  number in a LATER region than ch3's, the pops flip and loop 3 matches. But
  moving either init statement relocates its lis/addi emission (target pins
  both inits after the middle loop), so no statement-motion spelling exists.
  The flip therefore hinges on the desc+0x4 accumulation/region rule ONLY:
  either the weight rule gives retail's counter >201 somehow (different use
  kinds?), or region boundaries in the retail compile differed (pass config?).
  NEXT: static-disasm the accumulation site(s) writing desc+0x4 (CIR walk,
  callers of RegInfo_Desc around 0x4d0150) + the worklist chain reset 0x4f0a90
  to pin region boundaries. All live data needed to verify a candidate rule is
  in the traces above (245/201/69/13/9 for known webs).
Sfx_UpdateObjectChannel3D falls to the same rule (param 13×memory-uses ≈ high
pri → highest vreg in its region → pops first → r31; retail wants slot first).
One decode closes both functions and likely the whole 99.6-99.98 family.

## DECODED (2026-07-11): the desc+0x4 ACCUMULATION SITES (the doc's OPEN item)
Three writers, all ~0x4e0b00-0x4e0d50 (CFunc use-recorder band; found via
`addl %reg,0x4(%eax)` scan over the full objdump):
  0x4e0baa / 0x4e0c7d (two branches of one recorder, routed at 0x4e0b85 by
  edi+0x14 vs edi+0x10 window compare) and 0x4e0d48.
Site 1 disasm (0x4e0b89-0x4e0bb3):
  call RegInfo_Desc(value); desc->eligible(+0x23)=1;
  ecx = (byte[0x5e4907] != 0) ? 1 : dword[0x5e9040];   <- THE WEIGHT
  desc->pri += ecx;  if (desc->pri < 3) desc->pri = 3;  <- floor 3
=> per-REFERENCE weight is the CONTEXT global 0x5e9040 (loop-nesting weight,
set by the enclosing walker) — uniform for all values referenced at the same
loop depth, floored at 3. CONSEQUENCE (closes the source-lever question): a
same-loop counter (2-3 refs) can NEVER out-priority a 29-use walker by any
spelling — Music_Update's loop-3 flip and ObjectChannel3D's param-first are
NOT reachable from C under this pass config. Retail's opposite order therefore
implies a DIFFERENT weight context at their reference sites (0x5e9040 setter =
next decode: find writers of 0x5e9040 — likely IroLoop nesting enter/exit) or
a retail-side pass-config difference for this TU.
NEXT (mechanical): grep writers of 0x5e9040/0x5e4907, decode the depth rule,
recompute expected pris for retail's shape; if no context explains it, test
per-fn pragma states that zero 0x5e9040 (the flag 0x5e4907 forces weight=1 —
find which option sets it; weight=1 compresses 245..9 → 34..3, counters STILL
below walkers, so the flag alone doesn't flip — the flip needs region/batch
boundary movement, see sub-batch note above).

## DECODED (2026-07-11): the weight source — per-BLOCK loop weight
Single writer of 0x5e9040 at 0x4dd684 (fn 0x4dd650, a block walker):
  0x5e9040 = movzwl block->+0x8   — set per basic block before recording refs.
So desc+0x4 = SUM over references of the referencing BLOCK's +0x8 weight
(floor 3). Same-block refs weigh equally; the counter's refs live in the loop
LATCH block, walkers' in BODY blocks — if latch and body carry different +0x8
weights, the counter/walker priorities are per-block-weight × ref-count.
FINAL MECHANICAL STEP (one tracer run): bp 0x4dd684, log eax (weight) with a
block counter for Music_Update; recompute pri(i3)=9 vs pri(ch3)=201 exactly;
then determine what block structure/weights retail's tail loop must have had
for pri(i3) > pri(ch3) — that predicts the missing C construct (e.g. a latch
weight bump from a different loop shape: for vs do-while, an extra latch
statement, or a condition split). Everything else (tracer recipes, identities,
grant rules) is above; this closes the audio trio and the 99.6-99.98 family.

## VERIFIED NUMERICALLY (2026-07-11): the complete priority formula
Block-weight trace (bp 0x4dd684) on Music_Update: weights are 8 (loop-depth-1
blocks, 164 of them) and 1 (non-loop, 23). desc+0x4 = Σ per-ref block-weight:
  ch3: 25 in-loop refs ×8 + 1 (init) = 201  ✓ traced value
  i3:   1 in-loop ref  ×8 + 1        =   9  ✓ traced value
  (ch1: ~30×8+5 = 245 ✓, mid: ~8×8+5 = 69 ✓ — model fits every observed web.)
With ×8-per-depth weights, a latch counter can only outrank a 25-ref walker
from loop depth 3+ — no such construct exists in this fn. CONCLUSION: retail's
loop-3 pop order CANNOT be priority-driven for this shape; the difference must
be in the numbering REGION/sub-batch boundaries ({47,48,49} grouping) — the
region-formation rule (worklist chain 0x4f0a90 / driver 0x435de5 batching) is
the one remaining decode, now with a numerically-validated model on both sides
of it. All tracer recipes + data in the entries above.

## Numbering VALUE-IDENTITY trace (2026-07-11): split-web name arenas
Number() entry (0x4d03a0) trace with value+0xa name pointers, Music_Update:
vregs 44/45 carry OLD-ARENA name nodes (0x6c1b/0x6c1c — interned early, the
original 'i'/'ch' names, loop-1 webs, apply-pattern confirmed i=44 ch=45);
vregs 46..69+ carry FRESH sequential name nodes (0x6c7cc018 descending by
0x38 per alloc) — the live-range-SPLIT webs get generated name nodes in one
allocation run. Split numbering order observed: i-split(47), ch-mid-split(48),
ch-loop3-split(49) — i's split numbers FIRST. Retail needs i's loop-3 split
numbered LAST (pops first → r22). Renaming the counter to a never-interned
identifier (musChanIdx) is INERT → the order is NOT lexical intern order; it
is the SPLITTER's processing order. NEXT DECODE (small): the live-range
splitter (opt_lifetimes pass) — find the name-node allocator callsites for
split webs (alloc run at 0x6c7cb*-0x6c7cc* addresses; bp the allocator, walk
back to the per-variable split loop) and read what orders variables there
(hash order? decl order? vreg order?). One 8s tracer run + one disasm read.
Also negative: driver 0x435de5 region is a LINEAR two-list walk (no priority
compare in the loop) — the "ascending-priority sub-batch" observation emerges
from LIST ORDER; priorities gate eligibility elsewhere. The recovered
CodeGenNumbering.c max-scan pseudocode describes a different band — reconcile.

## Music_Update STRUCTURAL ANSWER FOUND (2026-07-11): five-variable form
Coupling proof: with shared ch/i + splitter, name-web order and split order
both derive from the same variable order — loop-1 correct forces loop-3
swapped and vice versa. BOTH loops matching is IMPOSSIBLE with 2 shared
variables ⇒ retail used SEPARATE loop variables. Empirical confirmation:
fresh fn-scope pair for loop 3 (FR1: +i2,ch2; FR3: +p for the middle loop too)
makes the walker/counter registers CONSISTENT ACROSS LOOPS for the first time
in ~60 variants — the target's invariant. Web count also matches (2 named + 3
splits = 5 named webs). Remaining: the five vars' decl positions set their
pop order among themselves and vs the decl-init block; FR1/FR3 shifted the
reservation bank (fades grabbed r31). NEXT (bounded, mechanical): sweep decl
orders/positions of {ch,i,p,ch2,i2} relative to the init'd decls (~20 perms ×
8s probe harness), reading pops directly with the select tracer; land the one
matching retail's sequence [declblock r31..r25, fadeA r24, fadeB r23,
i-web r22, mid r3(volatile), ch-web r21, found20 r20, found19 r19] and regs
r21/r22 shared by both loops' pairs. Loop-1 keeps the mr-form init, loop-3
folds (union window) — verify per variant. This is the close-out path for
Music_Update; ObjectChannel3D likely falls to the same separate-variable
insight (its param/slot/level rotation may need a fresh local for the
level-reload path).

## Music_Update 5-var sweep data (2026-07-11, closing state)
Decl-order/position sweep of {i,ch,p,i2,ch2} (probe harness, both loops read):
- Order controls pair direction: [ch,i,..] → walker=higher reg; [i,ch,..] →
  walker=lower. Consistency across loops holds when loop-3 pair decl order
  mirrors loop-1's ([i,ch,p,ch2,i2]-style); crossed orders (i2 before ch2 with
  ch,i) break it.
- Position moves the absolute bank: top → r28/r29; after found19 → r19/r20;
  after fadeA → r19/r20 AND inconsistent (loop1 ch=r19/i=r20, loop3 flipped).
  The decl-block's reservation order interacts globally — placement cannot be
  eyeballed; run the select tracer per variant and match the full pop sequence
  [declblock r31..r25, fadeA r24, fadeB r23, i r22, mid r3, ch r21, found20
  r20, found19 r19].
NEXT SESSION (mechanical, ~20 tracer-guided variants): sweep {i,ch} pair decl
position through each slot of the init'd-decl block (before lowPriority,
between each pair, after fadeA) with order [i,ch] + trailing [i2,ch2,p] (or
i2/ch2 reusing via later position), pick the variant whose pop sequence
matches; then verify the loop-1 mr-form/loop-3 fold split and diff to 100.
All harness+tracer invocations in the entries above; probe compiles are 8s.

## Music_Update placement sweep EXECUTED (2026-07-11, 11 variants)
Round 1 (pair=loop1's i/ch swept A-F, trail i2/ch2/p at F): counter reg by
position: A→r29, B→r28, C→r22(!), D→r20, E→r20, F→r20; loop3 pair stuck
r19/r20-ish. Position C (after s2VolB) puts the fed loop's counter at r22 —
the bank slot is real and reachable.
Round 2 (ownership flipped: loop3 keeps i/ch at swept position, loop1 on
i2/ch2@F): loop3 counter=r29 for B-E (position-insensitive!), r20@F — the
sensitivity inverts with ownership; the two pairs' interactions are not
separable by position alone.
=> The C-slot reachability + FR1/FR3 consistency proof stand; landing both
pairs on r21/r22 simultaneously needs the full cross-product (pair position ×
trail position × ownership × order, ~60 variants) with the select tracer
verifying pop sequences — scriptable end-to-end with the harness in these
notes (8s/variant ≈ 10 minutes total). That script is the single remaining
action for Music_Update.

## andross_update wave-2 findings (2026-07-11, at 99.760)
Fixed tonight by HUMAN-FORM rewrites (each verified byte-stable or better):
- gAndrossMoveAnimSpeeds (retail 0x8032C098, 23 floats) adopted into the unit
  (was extern lbl_; split/symbols updated; .data now emits spawnIds+speeds in
  retail order).
- delayPair loop: `randVal = delayPair[(u8)work]` single-read. As a STATEMENT
  it hoists the lhax above the retail null-check (fuzzy -0.19) BUT flips the
  whole flag ladder correct (swf=r29/sc=r28/pa=r26!) via two case-local parked
  temps (the loop's stack-base addi ghost + counter) reserving r29/r28 that
  the flags then REUSE (non-interfering piggyback). As an ASSIGNMENT-IN-
  CONDITION `actionTimer <= (randVal = delayPair[(u8)work])` the site bytes
  match retail exactly but the ghost temp dies and web 56 (unidentified,
  nadj 38, interferes with the switch flag) blocks the r29 reuse -> flags
  stay swapped. Retail = site bytes AND flags => retail's compile had a
  case-local parked temp reserving r29 that ours only produces in the
  statement form. The remaining search: which construct creates that ghost
  (a loop-PRE'd address temp that rematerializes at use - reserved but
  instruction-less) while keeping in-condition evaluation order.
- ObjPlacement-typed spawn setup + moveState->signalFlags drains: byte-neutral.
Tools: apply_trace_lldb.py extended per-web; adjacency dumps via 0x5089c4/
0x50899e breakpoint (web+0x1a s16 list) directly identify reuse blockers.
## Music_Update cross-product EXECUTED (2026-07-11, 120 variants, no dual hit)
norm/C/*/ic lands LOOP1 = r21/r22 exactly; norm/*/C/ic lands LOOP3 = r21/r22
exactly — the C slot (decl after s2VolB) owns the r21/r22 reservation depth,
and named pairs always take FRESH grants at their decl-slot depth (no reuse
among named webs in any of 120 layouts). Both-pairs-on-r21/r22 requires one
pair FRESH + one pair REUSE — i.e. the pristine names+splits structure, NOT
5 named vars. Re-deriving target pops from retail asm with the grant rules:
loop1 = FRESH in order [i r22, ch r21], loop3 = REUSE [ch r21, i r22] ⇒ in
RETAIL, the loop-1 (name) webs popped BEFORE the splits ⇒ the ch/i name webs
carried HIGH vregs = numbered in PASS 2 (expression-canonical), like the
fadeA/B call-result webs (vregs 79/80, r24/r23). Our build has them pass-1
(name-canonical, vregs 44/45, colored last via reuse).
=> FINAL QUESTION (one item): what C dataflow makes a multi-def loop variable
EXPRESSION-canonical (value+0xa kind 0x40, pass 2)? Same question as the
andross stateChanged @-temp (IroPropagate split predicate). Decode
IroPropagate's split predicate (0x470060 band, already partially recovered)
or probe C shapes on the harness watching the numbering trace for ch/i moving
to the pass-2 batch. This unifies BOTH remaining audio functions AND the
andross residual into one predicate decode.
## H1 confirmation + session terminus (2026-07-11)
p-for-middle + #pragma opt_lifetimes off: ch/i become SINGLE webs spanning
both loops — pair CONSISTENT (r29/r28 both loops), proving single-web = the
consistency structure. But the whole-fn pragma merges every other split too,
shifting the entire bank (pair lands r29/r28, decl block displaced) — retail
matches pristine everywhere EXCEPT the pair, so retail had normal splitting
globally with only the ch/i pair behaving as-if-unsplit (or family-unioned
across the split via the copy/union window gates 0x5ea1da/0x5e9730).
REMAINING (one predicate, now cornered from three sides): the condition under
which a split pair's webs union/color as one family (or never split). Sources:
splitter pass + union window gate + IroPropagate canonicalization — all three
partially recovered; the numbering/select tracers verify any candidate in 8s.
This same predicate resolves ObjectChannel3D (param web class) and andross
(stateChanged @-temp) — three residual families, one decode.

## Music_Update FINAL NARROWING (2026-07-11): splitter group order only
Full grant-rule simulation over all orderings (with interference sets) shows
EXACTLY ONE divergence from retail remains: the live-range splitter emits
split-web groups per variable in i-group-then-ch-group order (vregs 46,47 =
i's; 48,49 = ch's); retail requires ch-group-then-i-group. Everything else —
name vregs (44=i,45=ch), name reuse pops (ch1→r21 then i1→r22, interference-
blocked correctly), split F-grants — already matches once the groups flip:
  [46,47]=ch(mid,loop3) [48,49]=i(midctr,loop3) → F: i3(49)→r22 ✓ ch3(47)→r21 ✓
  names: ch1(45)→reuse r21 ✓ i1(44)→r21 blocked by ch1 → r22 ✓ = 100%.
Splitter variable order is NOT: decl order (decl-swap flips names too — net
same), reverse decl (= current), first-split-point program order (P2 fresh-j
inert), alphabetical (RN1 rename inert). Remaining candidates: nadj/degree
order, live-range start/end order, or an internal hash — read the splitter
walk in the SpillCode.c/lifetime band (its name-node allocation run for split
webs is the entry point; the numbering trace verifies any hypothesis in 8s).
This is the last bit standing between main/audio and 100% on Music_Update.

## Music_Update DEFINITIVE CHARACTERIZATION (2026-07-11, 180-variant closure)
Extended cross-product (trail-order axis added, 60 more variants): the r21/r22
reservation depth belongs exclusively to whichever pair's decls sit at the
C-slot; the other named pair always takes fresh r19/r20 — named webs NEVER
enter the reuse path. Dual r21/r22 occupancy therefore REQUIRES the pristine
names+splits structure (splits take fresh grants, low-vreg name webs reuse),
and within it the ONLY free parameter is the splitter's per-variable group
order — which resisted every source-side key (decl/name/order/init/program
position; 180 variants total across both sweeps). CONCLUSION: Music_Update's
last two regions are either (a) flipped by a splitter-order key not expressible
in source (=> config/pass-order-bound, same class as the documented sparse-
switch jump-table cap — bank as such), or (b) unlocked by reading the actual
splitter walk in the binary (SpillCode/lifetime band; the split name-node
allocation run is the entry). Recommend: treat (b) as the one remaining
research item for the whole reg-perm family; if it also shows no source key,
this fn is a principled permanent bank at 99.596 and main/audio's realistic
ceiling is 99.92 pending compiler-config archaeology.

## DECODED (2026-07-11): block-reverse numbering walk + the final verdict
0x4f0a90 read: it is the per-BLOCK worklist reset — allocates a block node
(weight +0x8 defaulted to 1, later bumped to 8 by the loop pass), prepends it
to the 0x5e9cd8 chain, zeroes both per-block value lists. The numbering-time
block walker (0x4dd650, the weight setter) consumes the chain head-first =
REVERSE program order — which reproduces every observed vreg: loop-3 preheader
values number before mid's (47 < 48), loop-1's name-bound webs number last
(44/45), and pass-2 (predicate 0x4e9380: value+0xa NULL or kind 0x40/0x24)
collects deferred values across blocks after the barrier (ch3 → 49).
Within the loop-3 preheader, i3's def (VN class: integer constant) and ch3's
(VN class: symbol address) land in fixed pass-1/pass-2 lists by their VALUE
CLASSES — spellings cannot move a compile-time constant or a symbol address
out of its class while preserving the emitted li/lis+addi. VERDICT: the
i3/ch3 numbering order in this shape is NOT source-reachable; retail's
opposite order implies a different front-end/pass configuration for that
compile (or a compiler sub-version numbering blocks forward). Music_Update
banks PRINCIPLED at 99.596 alongside the sparse-switch jump-table cap;
main/audio's source-reachable ceiling stands at 99.92 pending compiler-config
archaeology (candidate: block-chain direction differences across MWCC 2.0
builds — testable by diffing 0x4f0aa3-0x4f0aaa against other mwcceppc
binaries in build/compilers/).

## ObjectChannel3D TRACED + closed (2026-07-11)
Select-trace section identified (F 49→r31=param, 37→r30=slot, 33→r29=level;
spill-reload webs 35-39 reuse r29-r31 = level's stack reloads ✓). The
block-reverse/def-reverse numbering model fits exactly: within block 1,
numbering = reverse def order → the param's entry copy (first def of the fn)
always numbers LAST → highest vreg → pops first → r31. Guard-split probe
(two separate ifs, param test in its own block) INERT — the entry copy is the
def; use position does not move it. Retail's param=r29 therefore also requires
a numbering-order difference not expressible in source under this binary —
same verdict as Music_Update. Both remaining audio holdouts are one family:
block/def-reverse numbering vs retail's apparent forward variant. The single
remaining avenue for 100%: compare the numbering walk direction code
(0x4f0aa3 chain-prepend + 0x4dd650 walker) across other mwcceppc binaries in
build/compilers/ — if a sibling build chains/walks forward, the audio TU (and
this whole reg-perm family) may need that binary. Otherwise: principled caps,
main/audio source ceiling 99.92%.

## Compiler-version sweep (2026-07-11): NEGATIVE — the last avenue closed
GC/2.0p1, 1.3.2, 1.3.2r, 2.5, 2.6, 2.7 all emit Music_Update's loop-3 pair as
addi r22/li r21 (identical to 2.0) — the numbering behavior is stable across
the MWCC GC family; version archaeology does not explain retail's r21/r22.
Retail's order therefore comes from a source/block-structure difference the
current model cannot yet derive (the block/def-reverse walk approximates but
mis-predicts some orderings, e.g. mid=48 between latch-encountered webs).
STATE: main/audio = 99.917% (84/87). Sfx_UpdateLoopedObjectSounds 99.35 (this
session's +0.97). Music_Update 99.596 and ObjectChannel3D 99.01 remain, both
reduced to the numbering-walk fidelity question — the next concrete step is
completing the walk model (log block boundaries alongside numbering commits:
one more tracer field), after which the required retail block structure can be
back-derived and its C shape read off. All tools, traces, and ~260 mapped
variants are in the entries above.

## Pipeline shape confirmed + push-site negative (2026-07-11, last round)
Interleaved V(block-visit 0x4dd684)/M(Number 0x4d03a0) trace: for each fn ALL
block visits complete (33 w=8 + 1 w=1 for Music_Update), THEN the numbering
commits run as one burst (we4 32..78 consecutive) — accumulate-then-number,
not per-block numbering. The worklist consumed by the burst is NOT fed by the
0x4f0e90 codegen-time push (MU's numbered value ptrs never pass it) — the
numbering-time list is built inside the 0x4dd650 walker band; its list-append
internals are the remaining read to complete the order model (then back-derive
retail's required block/def structure for the loop-3 pair and read off the C).

## DECODED (2026-07-11, terminal): the walker is a statement dispatcher
0x4dd650 = CIR STATEMENT walker (per statement node: weight = node+0x8 →
0x5e9040; dispatch on stmt kind node+0x4 via jump table 0x5b9bf0; handlers
call 0x4dda30 = the expression-tree walker that records refs and pushes value
cells). Numbering scan then runs over the accumulated (prepended) cell list:
head = LATEST push = latest program reference; duplicate cells of committed
values are skipped; predicate-deferred values (0x4e9380) skip to pass 2.
This explains the loop-3 triple exactly: i3 commits first (latch i-- is the
latest push, pass 1 → 47); ch3's cell is predicate-DEFERRED (pass 2 → 49);
mid's latest push commits as the following pass-1 entry (48). RETAIL requires
the deferral to land on i3 instead of ch3 — the 0x4e9380 predicate on the
latch-decrement value vs the address value. The last read (small): 0x4e9380
(already located, ~20 instrs) + what sets value+0xa for (a) a symbol-address
assign and (b) a post-decrement compare value — then the C shape (or
infeasibility) falls out directly. All traces to verify are in place.

## Predicate read + kind-flip probes (2026-07-11, terminal round)
0x4e9380 read: TRUE (defer to pass 2) iff value+0xa node NULL or kind byte
== 0x40 or 0x24 — confirms the doc. Kind-flip probes: (a) `(MusicChannel*)
(int)gMusicChannels` cast on ch3 — regs unchanged (either cast node also in
the defer set, or folded); (b) inlined static getter for i3's 15 — CInline
substitutes the return expression BEFORE numbering, the call node vanishes,
const kind restored → inert. No source-level carrier found for moving the
deferral between the loop-3 pair. Remaining: identify kinds 0x40/0x24 in the
CIR opcode table (shared open item with the andross investigation) and what
front-end constructs produce them at an assignment's value node; then either
the C shape exists or both audio holdouts are principled caps. main/audio
stands 99.917 (84/87): UpdateLoopedObjectSounds 99.35 (+0.97 this campaign),
Music_Update 99.596, ObjectChannel3D 99.01.

## DECODED (2026-07-11): kinds 0x40/0x24 ARE ASCII — '@' and '$'
Kind-byte trace over Music_Update's numbering commits: the "+0xa kind byte"
values are the FIRST CHARACTER of the value's NAME string — 0x6c='l'owPriority,
0x69='i', 0x63='c'h, 0x73='s'2Vol*, 0x66='f'ound/fade..., and 0x40='@' for all
33 split/temp webs. The 0x4e9380 predicate is simply "name starts with '@' or
'$' (or no name)" = COMPILER-GENERATED TEMP CHECK. Pass 1 = user-named values,
pass 2 = @/$-temps. This closes the andross "kind 0x40/0x24 semantics" open
item: stateChanged's canonical value was an @-temp by NAME, and the whole
pass-2 family = temp-named values. Split webs are @-named → always pass 2 →
their order = deferred-list scan order (latest-reference-first within it, per
the MU data: i3@latch-newest 47, mid 48, ch3 49).
Retail's flip (ch3 before i3) needs ch's LAST-pushed reference to postdate
i's in the loop-3 latch. Probe `while (i-- != (int)(ch - ch))`: the stream
folds byte-identically but the ch refs vanish before the push (front-end
fold) — inert. No emission-preserving construct found that reorders the two
latch references; the latch source order (ch++ then i--) is emission-pinned.
=> The last blocker is now a one-line characterization: "reorder two @-temp
latch pushes without reordering the latch instructions." If no C form exists,
both audio holdouts are formally principled caps; the search space for such a
form is small and precisely defined (latch-reference tree positions).

## FORMAL CAP (2026-07-11, final round): latch-push reorder space is EMPTY
Closing probes: (a) `} while (ch++, i-- != 0);` — byte-identical stream, pair
STILL swapped (even with ch++ inside the condition tree the push order holds);
(b) post-loop `(void)ch;` — DCE'd before the reference walk, no cell pushed;
(c) latch restructure `i--; ch++; } while (i != -1);` — emission diverges
(cmpwi -1). With these, every construct class is exhausted: statement orders,
comma trees, dead uses, folding tautologies, phi inits, decl/name/ownership
layouts (~270 variants), all opt pragmas/levels, and 7 compiler versions.
VERDICT: Music_Update (99.596) and Sfx_UpdateObjectChannel3D (99.01) are
PRINCIPLED CAPS under the MWCC GC family as configured — the retail ordering
of their @-temp webs is not reachable from C source through this binary's
reference-walk. main/audio source-reachable state: 99.917% (84/87), with
Sfx_UpdateLoopedObjectSounds at 99.35 (+0.97 this campaign). Any future 100%
requires new external information (retail toolchain invocation details or a
compiler build not in build/compilers/). The full mechanism chain that proves
this — tracers, formulas, traces, and ~270 mapped variants — is in the
2026-07-10/11 entries above.

## Audit-completing negatives (2026-07-11, round 17)
Right-operand pure-reference carriers — `i-- != 0 && (ch, 1)`,
`&& ((void)ch, 1)`, `i-- != (ch, 0)` — all compile to the byte-identical
409-instr stream with the pair unchanged: side-effect-free references are
stripped before the numbering reference-walk. No ghost-reference carrier
exists. This was the final identified hole in the impossibility argument;
the principled-cap verdict for Music_Update / ObjectChannel3D stands complete.


## THE DECL-ORDER LAW (2026-07-10, round 18) — fn1 CRACKED to 100%

Sfx_UpdateLoopedObjectSounds 99.35 -> 100. The lever came from reading the name-resolving
numbering trace (nametrace.py: Number-commit 0x4d03a0 + name string at node[+0xa..], node =
*(value+0xa)) against the source decls. Three laws, all verified empirically on this unit:

1. **Named-web numbering order = REVERSE DECLARATION ORDER, exactly.** fn1's M-burst ascending
   [sz, removeSound, obj, index2, index, i, fp, ip, op, table] == decls reversed; block-scope
   locals (i2/ip2/op2) slot by their own decl positions (reversed) below; params below locals
   (sibling fn: obj param lowest). Statement order, init order, use order: ALL INERT (6-perm
   init battery + tail-perm battery + arm-swap all no-ops — the numbering ignores them).
2. **Saved-reg grants = web-index DESCENDING = DECLARATION ORDER.** F-event sequence idx
   51,47,43,42,41,40,38 -> r31..r25. First-declared local -> r31 (after any @-temps steal
   their slots, see 3). This is the mechanism under playbook #5/#16/#108 decl-order effects.
3. **The live-range splitter turns a CONVERSION-defined named web that crosses in-loop calls
   into an @-temp (which numbers ABOVE all named webs -> steals the TOP saved reg).**
   fn1: `index = (u16)i` (int index) -> @378 got r30, named index web died (A reg=0).
   An ADD-defined web (index2 = index + 1) does NOT split (r25 at decl slot). A REAL `& 0xFFFF`
   def doesn't split either but materializes the s16->int promotion (extra extsh + count temp
   r3-vs-r0 displacement). Loop-EXIT paths don't split (the 100% sibling fns return from the
   arm — same spelling, no @-temp).
   **THE CLEAN FIX: narrow-typed lvalue absorbs the conversion (#115): `u16 index; index = i;`**
   — def emits the bare clrlwi (no extsh, low-bits-only semantics), web stays NAMED (no split),
   numbers at its decl slot. Then decl order [table, fp, op, ip, index, i, index2] hands out
   r31..r25 exactly as retail. difflines=0 over the whole fn.

Corollaries:
- The '(u16)i-at-every-use' spelling (old V25 fix) CREATED the CSE @-temp — un-naming and
  naming were both wrong; the narrow NAMED var is the third option that dodges the splitter.
- Register outcome for saved-homed locals is a PURE function of the decl list + splitter
  behavior. Statement-level probes cannot move them (explains dozens of banked negatives).
- REOPENS Music_Update + Sfx_UpdateObjectChannel3D: the principled-cap verdicts predate these
  laws. MU's i3/ch3 ARE @-temps (split webs) — their relative order is set by split creation
  order, not source statements; and any conversion-def in their webs is now a lever (u16
  absorb). The 180-variant cross-product never included the narrow-absorb spelling.


## Music_Update CRACKED to 100% (2026-07-10, round 18 cont.)
`int i = 0;` — ONE DEAD DECL-INITIALIZER (folded, zero emission) — was the entire fix
(99.60 -> 100, commit fc63c07b10). Mechanism, all trace-verified:
- The live-range splitter processes parent variables in FIRST-DEF PROGRAM ORDER and
  creates each parent's split @-temps reverse-chronologically (loop3 seg before loop2 seg).
  @-temp numbering is reverse-creation => earliest-created split = HIGHEST index = pops first.
- Baseline: ch's first def (loop-1 init) precedes i's => ch split first => ch3 popped first,
  took fresh r22 (target: i3=r22, ch3=r21). Statement swap of loop-1 inits flips the pair but
  breaks the init emission order (target emits ch-init first).
- `int i = 0;` gives i a FIRST DEF at the declaration (dead store, eliminated later, emits
  nothing) => splitter order [i, ch] => i3 created first => pops first => fresh r22; ch3 then
  reuses r21. Loop-1's named ch/i reuse r21/r22 as before. difflines=0.
- Select-phase model refined (MU + fn1 data): simplify removes degree<K webs in ASCENDING
  index order per round (K~29 GPRs); pop = reverse => within a removal round, pops are
  index-DESCENDING. Parked (stuck) webs pop before earlier-removed rounds. Grant rules as
  decoded (fresh=r31-descending exhaust; reuse=lowest reserved non-interfering).

## Sfx_UpdateObjectChannel3D — exact frontier (99.011, the last audio holdout)
3-rotation param/slot/level (T: slot r31, level r30, param r29; C: param r31, slot r30, level r29).
Trace facts (nametrace/nadjtrace/adjtrace in scratchpad):
- Webs: param objectChannel=32 (LOWEST index, natural), fx 33, pan 34, level 35, slot 36,
  @644/643/642 37-39; appended (post-union/spill) 40-54 band.
- param nadj = 29 == K exactly => excluded from round-1 simplify-removal => parked last =>
  POPS FIRST => fresh r31. Target needs param removable round-1 (pops LAST => r29):
  retail param nadj <= 28. THE WHOLE FIX IS -1 INTERFERENCE EDGE (inverse of the
  DIMSnowHorn1 +1 lever).
- param's inline adjacency (web+0x1c, 16-bit ids, nadj at +0x18 dword): [1, 3..12 hard,
  33 fx, 34 pan, 35 level, 37 @644, 40,41,42,43,45,46,47,48,49,50,51,52,54 appended, 29(!)].
  The id-29 edge = HARD NODE r29 — param is precolor-EXCLUDED from r29 in our build; target
  has param IN r29 => that edge does not exist in retail's compile. Likely spill-round debris
  (level spills in both; round-2 rebuild may add colored-neighbor edges). Kill that edge OR
  any one other edge => param drops to 28 and the whole rotation resolves.
- Mapped inert: u32-param retype (+casts), same-type/void* copy local (front-end same-value
  merge eats it; opt_propagation off does NOT help), #131 self-or (const/self folds),
  (int)(long) cast-node injections on args, level-def respellings, fcmpo operand swap,
  gSfxPanScale launder flips (regress), named handle/trig temps (fold or regress).
Next instruments: dump slot(40)/level(35) adjacency + the U-event list for OC3D; diff the
appended-band webs against a variant; identify which temp union creates the param<->r29 edge.
Tools: adjtrace.py (WEB32 dump at fallback, 0xa0 bytes), nametrace2.py (names+pri),
nadjtrace.py (names+nadj) — scratchpad; recipe unchanged (wibo::loadModule, 2 continues, arm).


## OC3D round-19 corrections + pragma reachability (2026-07-10 late)
CORRECTIONS to the round-18 entry (both my errors, verified by burst mapping):
- There is NO round-1/round-2 for OC3D — ONE numbering burst, ONE select. The "round-1
  assigns slot=r31/level=r30, param fails" claim was the PREVIOUS fn's event stream
  (Sfx_KeepAlive*; its webs 32-37 alias OC3D's indices). Disregard the spill-round model.
- The `lwz rX,36(r1)` sites are NOT level spill-reloads: 32/36(r1) is the shared fctiwz
  TRANSFER slot (fctiwz; stfd 32(r1); lwz 36(r1) idiom). "level spills in both" is wrong —
  level lives in a reg; the reload-looking webs are #83 CONVERSION-POOL result temps,
  grouped [34,137] (piece A) + [76,90,106] (piece B). Their grouping/count is
  source-influenced (#83 statement-join flush, #89 mixed clamp split).
- Trailing entries read past the inline adjacency array (the "id-29 hard-node edge",
  27696, etc.) are GARBAGE — web struct: idx@+0x10, nadj-word@+0x12?, flags@+0x14,
  nadj-dword@+0x18, INLINE 16-bit adjacency from +0x1c with LIMITED capacity (overflow
  location unknown). Param true edges: 11 hard [1,3..12] + fx/pan/level/@644 + 13
  appended conversion/call-cluster webs = 28 readable + 1 overflow.
STATE OF THE HUNT (param nadj=29==K, needs -1; ~40 respellings mapped inert):
- inert: dead copies/inits (fold to zero webs — dead defs only matter for SPLITTER order,
  MU-style, not for edges), ternary/if conversions of v and the level clamps, guard
  split/reorder, (u8)/(int) cast noise, keyoff arm reorder, u32 store spelling,
  #114 cast-node injections on args (absorbed), decl permutations (param index already
  natural-low; block decls below fn-scope per the law).
- REACHABILITY PROVEN by two pragma states, BOTH landing target's prologue
  (mr r29,r3 param / mr r31,r3 slot): `#pragma optimization_level 2` and
  `#pragma opt_lifetimes off`. Their residual vs target is IDENTICAL in GPRs:
  conversion-piece A/B regs swapped (A=r30 wanted [34,137], B=r31 wanted [76,90,106])
  + the v else-arm join decoalesced (li r0/b/mr r0 instead of li r31 direct).
  Per the fn_801B3DE4 lesson: the structural feature is reachable; hunt the source form
  that produces it under default flags. Most promising axis: the #83 conversion-pool
  grouping (piece webs) — under default flags the pool packs [A,B] such that param's
  edge count hits exactly 29; one fewer pool web (or one more coalesce) = 28 = done.
  Next: dump the pool-slot value chains (which conversion feeds which lwz), map each of
  the 13 appended webs to its statement, and find the join/regroup spelling that merges
  two of them. Alternatively: A/B whether committing `#pragma opt_lifetimes off` +
  fixing the 2 residual shapes from source is viable (v-join resisted ternary/if under
  the pragma; piece swap untested).


## OC3D round-20 negatives + the init-web kill-switch (2026-07-10/11)
- fctiwz COUNT identical (6) in target and ours — the 1219/1234 `(int)(f64)volf`
  double-execution is retail-faithful; conversion-CSE theory dead.
- Decl permutations (slot/level/f32s, 4 orders) and MU-style dead decl-inits
  (`int level = 0;`, `void* slot = NULL;`, combos) ALL INERT on this fn — unique among
  studied fns: the pop cascade is dominated by the lifetime-pass pieces + the stuck param,
  not named-web indices.
- KILL-SWITCH FOUND: the level INIT-VALUE web (def `level = volf` @1198, read ONLY by the
  outer-else `v = level`). Killing its long range flips param to r29 with target prologue:
  (a) deleting the init (D2, illegal semantics), (b) respelling `v = (int)volf` (E1, legal,
  CSE keeps value in the fctiwz slot) — BOTH give mrs=[mr r29,r3; mr r31,r3]. BUT target
  asm proves retail wrote `v = level` (else-arm reads the init web via `mr r0,r30` — E1
  instead re-executes fctiwz there, and D2/E1 shrink the frame 128->112). So the init web
  exists in retail with its param edge — the -1 lives elsewhere. E1 diffs ~15 structural
  (init conv deleted, v-join decoalesced, frame) — NOT closer than baseline overall.
- Corpus: HuAR_MRAMtoARAM2 (mp4, both_off) = the param->r29-with-later-copies-above analog,
  but small-fn regime (no stuck web); no transferable lever visible in its C.
NEXT INSTRUMENT (unchanged, now the only path): def-PC per appended web — walk the web
descriptor to its first pcode ref and map pieces 40-54 to statements; then diff piece
structure against small source perturbations to find the one that merges/deletes ONE
param-edge web under default flags. The two pragma states (O2 / opt_lifetimes off) remain
the reachability proof + a fallback (their shared residual: conversion-piece A/B reg swap
[34,137]=r30 vs [76,90,106]=r31, and the v-join li-direct form).


## OC3D round-21: creation-site map + the @644/level-split edge (2026-07-11)
Instruments landed (all in scratchpad, recipes as before):
- wetrace.py: WATCHPOINT on webEnd[4] (0x5e9b14) — logs every cls-4 web creation PC.
  Works on lldb/Rosetta. Semantics: "W pc we4=N" => web N-1 just allocated.
- Creator sites for the appended band (idx 40+, created AFTER the numbering burst):
  0x4e1xxx/0x4e2xxx family (pcode-lowering fresh-vreg helpers; 0x4e2f3c dominant),
  0x453e2c (movswl-fed: the s16-load/neg arg temps), 0x528983 (small-struct init w/
  cx->+0x2: copy/move insertion), 0x44efxx (front-end). These are per-statement lowering
  temps in program order — NOT a separate lifetime pass.
- adjtrace on `#pragma opt_lifetimes off` build: **param nadj = 28** (vs 29 default) and
  the numbering burst has only @643/@642 — **@644 does not exist**. @644 (default build)
  = the lifetime-split piece of LEVEL (its adjacency = {param, fx, pan, late temps}).
  So the +1 edge sticking the param = the level web split (init-segment vs clamp-segment
  each edging the param). @643/@642 = call-result r3-temps (U 38->3, 39->3), fixed.
- v-coalesce shape (li rX,0 direct into the clamp-web reg) present in BOTH target and
  default build => retail compiled with default lifetimes ON.
OPEN CRUX for next round: whether target's level is also two webs. Target occupancy:
r31 = {slot[14-63], clamp-values[76,90,106], v-join[158]}, r30 = {init-value[34],
fx[137-151], else-read mr r0,r30[169]}. If init+fx+else-read in r30 are THREE disjoint
webs, retail nadj(param)=29 too and the differentiator is numbering/scan order (find the
zero-emission reorder lever, MU-style). If retail merged level's segments (nadj 28),
find the source form that avoids the hole-split under lifetimes ON. Next: per-reg
occupancy annotation of both streams + M-burst/W-map for a variant that changes the
@-temp block, to locate the order lever. Pragma fallbacks unchanged (O2 / lifetimes-off,
shared residual: piece A/B swap + v-join decoalesce).

Round-21 addendum: K&R param def, register param, decl perms, dead inits — all inert
(~60 total variants mapped on OC3D). Target partition re-verified two-web (init r30 /
clamps r31; the else-arm per-arm (u8) materialization matches ours modulo the cycle).
Both graphs provably near-identical => the differentiator is inside Simplify/park
ordering or an invisible (folded-but-numbered) temp difference. Paths remaining:
(a) decode the Simplify scan/park loop (0x4fe6xx band) to find its exact order rule +
what source can perturb it; (b) count folded temps via the webEnd watchpoint on variant
batteries (a folded temp still increments the counter — compare W-counts per variant);
(c) pragma fallback (O2/lifetimes-off) + crack its 2-shape residual.


## OC3D CRACKED to 100% — main/audio UNIT COMPLETE 87/87 (2026-07-11, round 22)
THE FIX WAS ONE LINE: a block-scope narrow extern inside the fn (commit 14da0fcd95):
    extern int sndFXCtrl(int handle, u8 controller, u8 value);
(audio.c file-scope sees engine_shared.h's `(u32,u32,u32)` decl; snd_synth_api.h carries
the narrow signature — and Music_Update in this same TU already block-declares
sndSeqVolume with narrow params, so this is retail's own pattern.)
MECHANISM (#115 + the round-18..21 model): with u32 params, each `(u8)pan/(u8)fx/(u8)v`
call-arg cast is a PERSISTENT conversion node = extra lowering-temp webs; with u8 params
the casts ABSORB into the arg slots. The temp-web difference moves the param web off the
nadj==K park boundary (29 -> lower), so it simplifies early, pops LAST, and takes r29 —
slot/level/pieces cascade onto r31/r30 exactly as retail. Zero instruction change
(caller-side clrlwi masks emit identically for u8 params).
LESSONS FOR THE PLAYBOOK:
- #115 callee-decl width is not just a "web creation order" lever — it changes the
  TEMP-WEB COUNT and therefore park/stuck boundaries. Check BLOCK-SCOPE extern width
  overrides (#57) whenever a param/local is stuck at the K boundary; look for a sibling
  fn in the same TU already doing it (Music_Update's sndSeqVolume was the tell here).
- The three audio holdouts fell to: (1) u16 narrow-absorb decl (fn1), (2) dead decl-init
  splitter reorder (Music_Update), (3) narrow callee extern (OC3D) — all three are
  ZERO-EMISSION IR-shape levers, invisible to asm diffing, found only after decoding the
  allocator's numbering/park/grant rules with the live tracer.
main/audio: 99.897 (start of campaign) -> 100.00000, 87/87. Unit flip readiness is the
team lead's call (pool claim + symbol layout per the playbook checklist).


## dll_0256_dimsnowhorn1 COMPLETE 39/39 (2026-07-11): fn_802BB4B4 98.94->100
One round with the decoded model (commit 592d8b76c8). The r29/r30 adjacent swap
(matchFrame vs state) was the fn1 select-hoist pattern verbatim:
- Trace showed NO named matchFrame web — the ternary `(slot != -1) ? (...) : 1` def made
  the SELECT @-temp carry the value; @-temps number above named webs -> popped before
  state -> stole r30 (target r29).
- FIX: if/else per-arm assignment (kills the select node; matchFrame = named multi-def
  web at its decl slot) + decls split from inits in order [state, viewSlot, matchFrame]
  (statements keep original order — assignment order does not move indices). diffs=0.
Pattern now 4-for-4 on "adjacent saved-pair swap" fns: check the M-burst for a MISSING
named web first — a ternary/conversion def whose @-temp carries the value is the usual
thief; kill the node kind (if/else, u16 lvalue, narrow extern) rather than respelling uses.


## objlib playerEyeAnimFn_80038988 99.19 -> 99.66 (2026-07-11) — 2 lines from 100
Landed (commit 0001d98a6e), full-opt unit (-O4,p WITH peephole+scheduling — the laws
still hold): three combined levers, each independently verified:
1. `int joint;` decl moved FIRST of the volatile six + DEAD DECL-INITS on
   joint/model/jointDataOffset/poseOffset/jointData (= 0/NULL, all folded, zero emission):
   orders the splitter parents (first-def program order — MU law) so block-2's segments
   pop onto the SAME regs as block-1's named webs (r4-r9 target map). rotation gets NO
   decl-init => its segment created last => pops last => r9.
2. `*(u8*)((int)jointData + objAnim->bankIndex + jointDataOffset + 1)` int-base arith:
   stops the canonicalizer grouping (jData+jDO+1) with the extsb'd bankIndex as lbzx
   BASE (r0-illegal) — with jData as base the extsb temp colors r0 like retail.
   Plain [] regroupings (parens, term order, ptr-chain) are ALL canonicalized away —
   only the (int) cast on the base survives.
3. Everything else falls out (30-line volatile rotation collapsed).
RESIDUAL (2 lines): block-1's jDO/pose re-inits emit `li r6,0; li r7,0`; target has
`mr r6,r4; mr r7,r4` (copies of joint's zero). Block-2's equivalents DO emit the mr form
(segment-entry connectors reading the incoming zero). Mapped inert: explicit copy
spellings (const-fold eats them, even adjacent ObjHitbox-style), chained assigns,
self-or/add (#131 folds here), dead-use sinks, bs->amount=joint reals, block-scoping,
register class, opt_lifetimes off (loses block-2's mrs AND these), deleting the
re-inits (decl-inits become real saved-reg webs, -348 lines). Open question for the
splitter-remat: what makes retail's block-1 defs segment-connectors — likely retail's
named first-segments end before block-1 via some real-but-invisible reference; find it
with a def-node kind dump (value+0xe kind byte) on the jDO/pose defs, or accept ~99.66.
NOTE ObjHitbox_SetStateIndex (same file, MATCHED) emits li+mr+mr from
`slotIndex = 0; slotOffset = slotIndex; clearedState = slotIndex;` — plain adjacent
copies of a multi-def loop counter DO survive there; the discriminator vs our fold is
still undecoded (its zero-var is the loop counter itself; ours isn't).


## objlib eyeAnim final-2-lines round (2026-07-11): negative map complete
The `mr r6,r4 / mr r7,r4` vs `li r6,0 / li r7,0` residual (block-1 jDO/pose inits copying
joint's zero) resisted every source-level route:
- ObjHitbox_SetStateIndex's li+mr+mr precedent is an **O1 PRAGMA ISLAND** (`#pragma
  optimization_level 1` + `scheduling off` at objlib.c:176) — its plain copies survive
  because O1 has no const-prop. Mutating its copies to `= 0` breaks its mrs (li x3) —
  the copies are load-bearing THERE, but the same spelling folds at O4.
- playerEyeAnimFn is NOT an island: O1=326 diffs, O2=218, O3=identical-to-O4 (2).
- Folded/inert at O4 (in the landed config): copy spellings (= joint), chained assigns,
  copies+opt_propagation off (the eliminator is the front-end same-value merge, not the
  propagation pass), dead RUNTIME decl-inits (= blinkState/obj — DCE precedes the
  splitter here, unlike MU's noopt unit), real early uses via the switch zero-stores
  (both plain and def+use spellings — const-prop rewrites the use to 0 and the def dies),
  early-segment attempts via bs->amount/timer.
- Mechanism (consistent, unfalsified): target's block-1 defs are lifetime-SEGMENT defs
  whose remat emitter reuses joint's r4-resident zero (our block-2 does exactly this);
  our block-1 stays the named web's first real segment, whose original const-0 IR emits li.
  Every route to making block-1 a segment at O4 either folds or explodes (deleting the
  re-inits -> decl-init webs go live-through-switch in saved regs, 348 diffs).
NEXT INSTRUMENT (only remaining path): def-node kind byte dump (node+0xa via value+0xa)
at the Number events for jDO/pose defs + the segment-builder walk for THIS fn, to see
what retail's IR must contain; or accept 99.664 (fn) / 99.966 (unit) as the cap pending
new info. All levers so far = the audio-campaign toolkit; this residual is a NEW class
(O4 const-emitter li-vs-mr), one node-kind dump away from resolution.


## objlib eyeAnim: OBSTRUCTION CHAIN COMPLETE (2026-07-11, round 3)
New compiler knowledge from the web-struct dump (webdump2.py, value+web raw dumps):
- Web struct +0x12 (16-bit) = DEF COUNT — and it COUNTS DEAD DEFS (a folded dead
  decl-init still increments it; that is WHY dead decl-inits reorder the splitter).
- Web flags +0x16 bit 0x40 = CONSTANT-VALUE TRACKING flag (set on all const-0-initialized
  webs and their segments; the zero-reuse emitter consults it).
- THE EMITTER LAW (verified across configs): a NAMED web def materializes constants
  fresh (li); a SEGMENT (lifetime-split @-web) def goes through the remat path, which
  REUSES a register already holding the constant (mr rD,rS) — first segment-def in a
  cluster still li, subsequent ones mr. Our block-2 = segments (mr ✓ matches target);
  block-1 = named first-live-segment (li ✗ target has mr).
FORMAL OBSTRUCTION (each link measured):
  target block-1 mr => block-1 defs are SEGMENT defs => a LIVE segment precedes block-1
  => a live def before block-1 that emits nothing => every candidate use const-folds
  (call args, stores, casts — all mapped) => no O4 C source produces it. Version sweep
  at full-O4 (GC/1.2.5, 1.2.5n, 1.3, 1.3.2, 1.3.2r, 2.0, 2.0p1, 2.5, 2.6, 2.7): the
  2-diff residual is IDENTICAL on 1.3-2.7 (1.2.5x diverges wholesale). O1/O2/O3 islands
  ruled out. opt_propagation off ineffective (front-end merge). Single-def joint (F2a)
  does not enable the reuse for named dests and breaks the splitter order.
VERDICT: fn capped at 99.664 (unit 99.966) pending information outside this repo
(retail flags for this TU, an unseen pass toggle, or a compiler build not in
build/compilers/). Same verdict CLASS as the audio trio pre-crack — but unlike those,
the instrument layer here is exhausted: every field of the mechanism is measured and
the requirement is self-contradictory in C-at-O4 semantics. If new info appears, the
entry points are: what creates a live-but-emission-free first segment, or what else
routes a named def through the remat path.


## objlib COMPLETE 65/65 (2026-07-11, round 5): THE INLINE-HELPER CRACK
playerEyeAnimFn_80038988 99.66 -> 100 (commit 0451e903d0). The "formal cap" verdict from
round 3 was WRONG — the obstruction chain was valid but rested on the unstated premise
that the source was straight-line. The crack (fresh-eyes question: "why would a 2002 dev
write the identical scan twice?"):
    static inline int playerEyeAnim_FindJoint(ObjAnimComponent* objAnim, int tag)
called twice with LEFT/RIGHT tags. Two effects, both previously unreachable:
- INLINE-EXPANSION LOCALS route through the temp/copy machinery, NOT top-level named
  webs => their const-0 defs go down the remat path => the li+mr+mr zero-reuse form in
  BOTH expansions (the exact thing no straight-line spelling could produce at O4).
- The expansion temps pop LIFO of the helper's DECL ORDER => reversing the helper's decl
  list [jointCount, jointData, poseOffset, jointDataOffset, model, joint] (inits as
  separate statements to keep emission order) lands the target volatile map exactly.
Replaces the round-2 landed workarounds (dead decl-inits + joint-first + (int)-base cast
kept inside the helper). diffs=0, and the source is dramatically more plausible.
LESSON (add to the mental playbook next to the decl-order law): when a fn contains
near-identical repeated blocks AND a within-block register/emission form that no
straight-line spelling reaches (esp. the li+mr constant-reuse form), RECONSTRUCT THE
INLINE HELPER — `-inline auto` expansions have their own web/temp classing. This is the
5th "impossible" residual cracked by a structural-origin insight rather than a spelling.


## 8-unit batch campaign, round 1 (2026-07-11): 3 landed, full survey maps
LANDED: curves 99.951->99.978 (#81 launder, cluster-1 2nd count ref; parity law:
exactly-one-of-four refs laundered flips one cluster — the 16-combo matrix maxes there);
tricky_substates 99.940->99.961 (trickyAdvanceNode inline helper — the two node-advance
loops are one static inline; li+mr walker init in expansion 2); modellight
applyGXControls 99.40->100 (`entry = NULL` dead decl-init kills the fn-top addr-temp
mr — MU lever, THIRD confirmation). REVERTED: mainSetBits end+1 (line-diffs improved
9<11 but objdiff fuzzy REGRESSED 98.55->97.91 — LESSON: always gate on report fuzzy,
line-diff is probe-only).
REMAINING MAPS (all decoded to the exact residual):
- curves c2: magic-double<->frac f1/f3 swap; launder matrix exhausted; volatile-FPR class.
- tricky residual (99.72): off<->table volatile swap + c1 li-vs-mr (helper decl perms swept,
  13-diff floor); cmpw operand at ~437.
- vecmath mtxRotateByVec3s (98.65): FPR temp naming scramble across the matrix build —
  needs expression-level reconstruction of the temp set (t1/t2/u/v/s/zero).
- gameloop removeButtonObject (98.09): ONE pair — unroller guard srwi+cmplwi (T) vs fused
  srwi. (C) under `#pragma peephole on` island; pragma combos + types swept; the fusion
  is the only structural diff. mainSetBits (98.55): r4/r5 volatile pair + the +1 fold
  (T folds (width+start)+1 late with add+addi; every C spelling folds early or regresses).
- objprint: all 3 = saved-reg permutations of param homes (objMathFn r6/r7 volatile;
  modelCalcVtxGroupMtxs 3-param rotation + stack-slot layout 28-vs-20(r1);
  shaderFuzz 3-param rotation) — fn-scope decl perms inert so far; block-scope/@-temp count drives it.
- drearthwarrior: fn_802BCA10 params shifted one reg (r29/r30 T vs r30/r31 C — one extra
  high web in target) + clamp temp r4-vs-r0; stateHandler02 = flag-in-r0(!) vs r5 + temp
  chain r3-vs-r0 (long-range r0 web legal — no calls in span).
- tex_dolphin: unsurveyed this round.


## Batch round 3 addenda (2026-07-11)
- modellight loadChannelLight (5 diffs): trace shows grants [lightId r31, light r30, obj r29]
  + view A-reused; the r31/r29 pair = offset-@-temp (channel<<4 CSE, grants first per law)
  vs named view. Target = view r31 / offset r29. view-decl moves give 7 (shift +2);
  named-offset spelling breaks address shapes (19). Next: demote the @-temp via the
  OC3D-class levers (what un-splits/renames the channel<<4 CSE) or promote view via
  call-result union (blocked by interference — view crosses PSVEC calls).
- modellight select pair (3/8 diffs): the ble-to-assign ternary form requires assign-on-LE
  into the RED-side reg; `<` gives blt, `<=` gives cror, `>`-direction breaks the clamp
  temps (13/18) regardless of result-var (incl. chained). Comparison-direction is coupled
  to the clamp webs; needs the FPR volatile trace to find the actual coupling.
- tex_dolphin setShader (8): fogColor/data r6-r7 volatile pair; order/pad probes inert.


## Batch round 4 addendum: fn_802BCA10 traced (2026-07-11)
Grants (ours): sub(33)->r31, obj(32)->r30, then renumbered vec0(74)->r29, vec9(73)->r28.
vec0/vec9 = union-renumbered call-results (appended reverse-chronologically: vec9=73,
vec0=74). nadj: sub 60, obj 46, vec0 31, vec9 25. Target: vec9->r31 FIRST (above params),
sub r30, obj r29, vec0 r28 => target's vec9 parks in the TOP band => its nadj must cross
the park threshold (~30): +5 edges over ours in vec9's [call2..fn-end] range. Decl perms
fully inert (renumbered webs ignore decl slots). `#pragma opt_common_subs off` on this fn
is LOAD-BEARING (removal = 136 diffs). Lever needed: ~5 extra interfering webs in the
vec9 range with zero emission (DIMSnowHorn +1 family — ternary select temps / named
loads in the vec0/vec9 clamp blocks), or the band-boundary decode. The sv/t clamp
blocks (both arms) are the natural web-donor sites.


## THE ONE BLOCKING UNKNOWN for the 8-unit batch (2026-07-11, round 5)
Six of the 14 remaining functions (fn_802BCA10, loadChannelLight, callList,
drawLightmapIndirectPasses, objprint x3-ish) reduce to the SAME undecoded rule:
**the pop order WITHIN the parked band** (webs with nadj >= ~30, incl. union-renumbered
call-results and @-temps). Measured facts: ours pops [params(33,32), renumbered(74,73)];
targets need renumbered-first or interleaved. Not index-desc, not decl, not nadj-desc
(all falsified by fn_802BCA10 + MU vols [43..37,80,79] + OC3D). The web_dump.gdb doc
says "(index, park-round): r31 to the first-declared web of the HIGHEST park round" —
the park-ROUND (which simplify iteration parked each web) is the unobserved variable.
NEXT INSTRUMENT: find the park/stuck-push site in the select driver (0x508680 region,
IroRegAlloc Simplify loop), breakpoint it, log (web idx, round#) — then each of the six
functions becomes a computable decl/edge tweak. The FPR-pair fns (curves-c2, vecmath,
setShader, select-pair) need the same for cls-3.
This is the highest-leverage single decode remaining: one breakpoint address unlocks
6+ functions across 5 units.


## DECODED: THE SELECT-ORDER LAW COMPLETE (2026-07-11, round 5) — disasm 0x508a20
The "get next web to color" fn (0x508a20, called from the Select driver loop at 0x50875b)
is a WORKLIST SCAN, not a stack:
1. SIMPLIFY: repeated passes scanning webs INDEX-ASCENDING; any unprocessed web with
   CURRENT degree (+0x12) < K (from 0x4fe520(cls)) is "removed": neighbors' degrees
   decremented (adjacency walk at +0x1a/+0x18), flag |=2, PREPENDED to list A (LIFO =>
   within a pass, later-index = nearer head; passes stack). Webs with degree >= K go to
   list B (rebuilt per pass).
2. STUCK CHOICE: when nothing is removable and list B is non-empty, walk B computing
   score = PRIORITY (+0xc, int) / CURRENT-DEGREE (+0x12) via fild/fdivp — EXCEPT webs
   with index >= the boundary at 0x5e0898 (i.e. RENUMBERED/appended webs: unions,
   spill-splits) which get the FIXED constant at 0x5bcbf4 instead. Best-scoring web =
   the spill/park candidate.
3. Coloring order = the sequence these returns produce; assign (0x50899e) tries reserved
   regs vs the adjacency mask, fallback (0x5089c4) reserves fresh (r31-descending).
CONSEQUENCES: pop order within the "parked band" = pri/degree ranking (+ the fixed-score
class for renumbered webs) — this is the missing variable behind fn_802BCA10 (vec9 needs
its pri/deg to beat sub's), loadChannelLight, callList, the objprint rotations, and the
FPR pairs (same machinery, cls 3). NEXT SESSION: read the constant at 0x5bcbf4 + boundary
0x5e0898, log (idx, pri, deg, score) at 0x508ad2's walk via lldb, and each residual
becomes a computable pri/deg source tweak (add/remove one ref or one edge).


## CORRECTION (2026-07-11, round 6): no parking in these fns — pure multi-pass simplify
Score-tracer (scoretrace.py: bps 0x508ae2/0x508b1a/0x508b71) on the DR unit: ZERO
stuck-chooser hits — list B is always empty here; every web eventually simplifies.
So coloring order = passes of index-ASCENDING scans, each pass PREPENDING its removals
(LIFO): color order = [pass-N reversed, ..., pass-1 reversed]. A web is colored earlier
by SURVIVING more passes (current degree >= K longer). fn_802BCA10: vec9 (nadj 25)
dies in pass 1 -> colored last; target's vec9 colored FIRST -> retail's vec9 survived
to the last pass -> needs >= ~29 initial degree... BUT target instruction count is
IDENTICAL (187) => the extra edges cannot come from added temps => they must come from
longer ranges of existing webs or an earlier call position — both currently excluded by
the matched regions. OPEN CONTRADICTION — next entry point: dump vec9's adjacency in
ours (adjtrace 0xa0) and enumerate what retail could add; also verify K per class
(0x4fe520 return) and whether pass-boundaries can be moved by degree changes among
NEIGHBORS (sub/obj at 60/46 are untouchable, but the mid-tier temps around 25-31 decide
which pass vec9 falls in — a 1-2 edge change to THOSE may re-order passes without
touching vec9 itself).
The chooser (pri/degree + fixed-const class) presumably DOES run in bigger fns (MU/OC3D
bands) — instrument stands for those.


## Round 7 verification: fn_802BCA10 target r31=vec9 confirmed; reuse chains consistent
Target call order verified [vec0-call -> vec9-call(bl 448, mr r31,r3) -> getVec(4) ->
getVec(5)]; r31 = vec9 beyond doubt (cmplwi r31 null-check + sth 0/2(r31) stores).
Reuse simulation: both compiles are internally consistent — the ONLY free variable is
vec9's REMOVAL PASS: ours dies pass 1 (static 25 < K); target's must outlive sub(60)/
obj(46), i.e. survive to the final pass. With identical instruction counts the missing
degree cannot be new temps. Remaining hypotheses: (a) vec9 NOT renumbered in retail
(named idx 38) AND K smaller than assumed, (b) the renumbered-web scan-visit position
interacts with pass membership in an unmodeled way, (c) vec9's mr participates in a
different union that inflates its adjacency. Next instrument run (fresh session): adjtrace
vec9 (full 0xa0 dump) + read K per class (0x4fe520 rets) + hand-simulate the passes —
then the lever is computable.


## Round 8: K CONFIRMED (GPR K=29, FPR K=32) + fn_802BCA10 adjacency data
ktrace.py (bp 0x508a32 reads K after 0x4fe520; fallback dumps full adjacency):
- K(cls4 GPR)=29, K(cls3 FPR)=32 — the simplify threshold, now exact.
- vec9(73) nadj=25 adj=[r0-hard,3..12, obj, sub, 37, vec0, 77..86]; vec0(74) nadj=31
  adj=[3..12, obj, sub, 35, 36, 37, vec9, 77..90]. Delta = {35,36,87..90}: the pre-vec9
  temps (call1/call2 arg webs die at vec9's birth) + two block-locals. Simulation with
  K=29 reproduces our color order exactly. Target needs vec9 static >= ~30: +5 edges in
  [call2..end] at identical instruction count. fn-scoping the arms' sv/t = INERT (31).
  Remaining candidates: temps whose RANGES retail extended past call2 (e.g. if the li 9
  arg web or call-2 arg chain outlived the call), or an unmodeled union. Fresh-session
  entry: def-site dump for temps 77-90 to name them, then reconstruct which retail
  expression keeps one alive past vec9's birth.


## Round 9: fn_802BCA10 vec9 mechanism SOLVED but spelling regresses fuzzy
CORRECTED identities: renumber order chronological (vec0->73, vec9->74); vec9 = the
nadj-31 web. It dies pass-1 ONLY because its low-indexed named neighbors (arm locals
sv/t, idx 35-37) are removed before its visit (-4 => 27 < K=29). Direct-deref clamps
(remove sv from both arms) FLIP the whole saved cycle (31->16 line diffs, vec9->r31 ✓)
— BUT objdiff fuzzy REGRESSES 99.17->97.59 (alignment penalty elsewhere; reverted).
The mechanism is confirmed; the exact retail spelling must remove/raise the sv webs
differently (keep instruction alignment). Candidates for next round: sv named but
declared to index ABOVE 74 (impossible for named), sv-as-fn-scope-with-later-decl,
the clamp bounds via u16, or accepting the 3-instr different alignment cost model.
Also open: the +-364 chain r4-vs-r0 (resists ternary/if/embedded spellings; if-form
gives the r4 chain but shrinks the frame by 16).
LESSON REINFORCED: line-diffs and fuzzy DIVERGE on this codebase — always gate on report.


## Round 10: REMOVAL-ORDER GROUND TRUTH (rmtrace.py, bp 0x508a8c)
fn_802BCA10 cls-4 removal sequence measured: pass 1 = [34..90 index-ascending, one pass,
51 absent(renumbered away)], pass 2 = [32(obj), 33(sub)]. Coloring = reverse => [sub, obj,
...vols..., vec9(74), vec0(73), ...] — reproduces our asm EXACTLY. Model fully validated.
TARGET needs vec9 removed LAST overall (after sub) => vec9 current-degree >= K=29 through
pass 1 AND most of pass 2. At vec9 visit, removed-neighbors per the dumped adjacency = 2
(37, 73) => current 29 >= K should have SURVIVED — but it was removed => the fallback-time
adjacency dump under-reports pass-1 interference (list may be pruned or 35/36 edges exist
but were absorbed). NEXT: dump vec9 adjacency at BUILD time (before simplify — hook the
graph builder) or log +0x12 current-degree at each visit (bp in the scan loop 0x508a64).
One of these two numbers resolves the last discrepancy, then the retail spelling is
computable. rmtrace.py added to the kit.


## Round 11: vec9 visit-degree MEASURED = 27 (needs 29; +2 exactly)
degtrace.py (bp 0x508a64, current-degree +0x12 at each scan visit): fn_802BCA10 pass-1
visits: obj=46, sub=60 (survive), t(35)=1, sv(36)=2, sv(37)=3 (removed), vec0(73)=24
(removed), vec9(74)=27 (removed — 2 short of K=29); pass-2: obj=14, sub=13.
So vec9 loses exactly 4 pre-visit (t, sv, sv, vec0) from static 31 — the fallback
adjacency dump WAS incomplete (35/36 are real neighbors). Retail needs vec9 at >= 29:
remove TWO of the four early neighbors (the both-sv direct-deref does it and flips the
cycle — but its per-branch sth emission regresses fuzzy), or gain +2 static edges above
index 74 (needs new instructions ✗), or retype/re-scope sv/t so their webs move above 74.
UNTESTED NEXT: sv/t as s16/u16 (#115 absorb may eliminate their separate webs at equal
emission), or one sv direct + t eliminated via an abs helper. The problem is now
plus-two-edges exact — the tightest spec of the campaign.


## Round 12: vec9 +2 enumeration continues
- NET-ZERO LAW derived: eliminating a neighbor web entirely is useless (static -1 AND
  removals -1 cancel). The +2 must come from (a) neighbors surviving past vec9's visit
  (impossible for low-index named locals — they are visited first and are low-degree),
  (b) new HIGH-INDEX webs in vec9's range (need instructions — only renumbered temps
  qualify; #114 cast injections FOLD, tested x2), or (c) vec9 visited earlier
  (unrenumbered idx 38 => -3 instead of -4 => 28, one short; would need +1 more).
- Remaining candidates for next session: one-arm sv-denial + fuzzy-gate measurement per
  arm (the both-arm version flips the cycle but regressed fuzzy 99.17->97.59 — measure
  which arm carries the penalty); what blocks/permits the call-result union (controls
  idx 38-vs-74); mixed one-sv + union-block combos. The space is ~4 spellings from
  closed at zero emission.


## Round 13: sv-denial family fuzzy-CLOSED (both arms measured)
vec0-arm-only direct-deref: fn 99.171 -> 98.717 (regression; reverted). Both-arm was
97.59. The per-branch-sth emission penalty exists in EITHER arm => the entire sv-denial
family fails the report gate despite flipping the register cycle. fn_802BCA10's
zero-emission +2 is now CLOSED across: sv-denial (both arms), neighbor elimination
(net-zero law), #114 casts (fold), s16 retypes (extsh), fn-scoping (inert), decl perms
(inert on renumbered webs). Remaining unexplored: what governs the call-result
union/renumber (idx 38-vs-74) — the one lever class untested, needs the union-site
disasm (0x57b947 caller context). If that also closes, this fn joins the
needs-new-idea-class list alongside objlib-pre-helper — historically those DID crack
(5 precedents), each via a structural-origin insight not in the current enumeration.


## Round 14: wrap-angle inline helper INERT (fn_802BCA10)
The twice-repeated +-0x8000 wrap block extracted as static inline DR_EarthWarrior_wrapAngle
(the objlib/tricky/curves pattern): expansion produces identical webs — 31 diffs unchanged.
The wrap value (delta) is a plain named fn-scope web either way; expansion temp-classing
only matters when the repeated block OWNS locals (objlib) or walkers (tricky). fn_802BCA10
enumeration now closed across 15+ spelling families; open levers: union-control disasm
(0x57b947 call context) and any structural reading not yet conceived. Moving the round
budget to the other units next.


## Round 15: modellight select-pair — FPR ordering lever EXCLUDED by trace
cls-3 removal trace (selectObjectLights): one clean ascending pass, no parking, no
renumber anomalies => the 3-diff ble/fmr residual is NOT an allocation-order problem.
It is the ternary-join lowering fork (which operand reg receives the join copy +
branch sense), same class as the li-vs-mr emitter fork. Source directions were closed
in rounds 2-3 (<, <=, >, result-var, chained — all measured). Next lever = the ternary
join lowering disasm (find the join-emit site, read what selects copy direction), which
would also resolve curves-c2 (magic/frac) and vecmath — the FPR trio shares this class.


## Round 16: TERNARY-JOIN LAW from corpus (mp4 fn_1_19C8, m413Dll/main.c)
Matched-code evidence: `temp_f30 = (temp_f30 > 1.0f) ? 1.0f : temp_f30;` compiles to
[lfs f1,C; fcmpo f0,f1; ble->fmr f1,f0; ...] — the JOIN REGISTER = ARM1's register
(the const C in f1); the fmr copies ARM2 in on the branch path. So MWCC ternary joins
land in the FIRST arm's reg, branch = assign-ARM2-when-condition-false.
Applied to modellight select-pair (T: join=f2=red, fmr f2,f3 on ble): retail condition
= (red > green), arm1 = red — CONFIRMED form `(red > green) ? red : green`. My probes
of that form broke the CLAMPS (13 diffs) — so retail's clamp spellings must ALSO differ
to be consistent with the >-form (the clamp ternaries are the same construct — apply the
join law to THEM: their arm1 choices determine the f0/f2/f3 map). NEXT SESSION: rewrite
the whole rgb clamp+max chain arm1-consistently per this law (each ternary's arm1 = the
reg that must hold the result), then curves-c2 and vecmath with the same law.
This is the FPR-trio unlock, derived from matched code as the goal suggested.


## Round 17: join-law analysis of the rgb chain (modellight)
The clamp ternaries ALREADY obey the join law (outer arm1 = 0.0f const -> join f2 =
target ✓). Only the max needs arm1=red — but flipping it EXTENDS red's clamped web
through the join, which shifts the clamp-const reuse (the observed 13-diff cascade).
The chain is a simultaneous system: solve by choosing arm1 per ternary such that each
join reg matches target AND the resulting web extensions keep the const-reuse pattern.
Target regs: red-clamp consts f2, red-clamped f2 (fmr f2,f0), green consts f3,
max-join f2, score-blue-max join f1 (fmr f1,f0). Next session: enumerate the ~8
arm1-consistent chain spellings against these six anchors (each 8s compile).


## Round 18: rgb chain — clamp-order matrix closed
E1 (`(red > green) ? red : green`) = correct structure; residual = red/green WEBS swapped
throughout (13 diffs, pure pair). Clamp-order reversals (red/green/both) = 15/15/17 —
worse, closed. The pair order under E1 couples to the join-extension (arm1's web extends
through the store). Next lever class: red/green web-LENGTH manipulation around the max —
e.g. the score-store spelling (direct field vs green var), or the blue-max's operand roles
(blue's chain reads selectionScore — reloading vs reusing green's reg changes green's end).
The enumeration is 3-4 spellings from closing this fn's map too.


## Round 19: select-pair result-flow family closed
Under the E1 max-form, all result-flow spellings (red-store+alias, direct-store+reload,
E1+red-alias) = 13 (the red/green pair swap persists). The pair's web order under the
arm1-extension needs the cls-3 removal/degree comparison (degtrace baseline-vs-E1) to
see which clamped web's creation position shifts — next session's first instrument run.
With that, this fn (and by class curves-c2/vecmath) resolves or formally closes.


## Round 20: comparative cls-3 trace — join re-creation law
baseline: red-clamp=@871 (created 1st, we4=46, pops 1st -> f2 ✓); E1: red's extended web
RE-CREATED at the join (=@876, created last, we4=43, pops last -> f3 ✗). So the arm1
join-extension RENUMBERS the web — UNLESS (hypothesis) the result-var IS arm1's variable
(join writes into the original web, no re-creation). The result-red form
(`red = (red > green) ? red : green; score = red;`) previously scored 13 but its DETAIL
was never read — next session: read it; if its 13 is a different composition (clamp-region
consts vs the pair), the fix may be one spelling away. This same re-creation law likely
governs curves-c2 (the magic web) and vecmath.


## Round 21: select-pair — result-red detail read (identical pair-swap), helper reframe negative
result-red form detail = IDENTICAL 13-diff pair swap as E1 => the "unless result-var=arm1"
refinement is falsified; ANY >-direction max puts red's web last. The 2x2 [pair-order x
join-owner] has 3 reachable cells; target = the 4th. Shared-rgb-block inline helper
(both select fns) = negative (27/18 — fn-scope rgb webs load-bearing). This fn's map is
now at the same formal-obstruction state as objlib-pre-helper was: all enumerations
closed, needs a structural reframe not yet conceived. Candidates parked for fresh eyes:
the blue-max's score-reload web, the light[0xa8..aa] byte-loads' webs, u8-typed rgb.


## Round 22-23: curves-c2 surrounding-const launder sweep closed
The lbl_803DE658 refs around the backward branch (236/252/257/262/264, one existing
launder at 230) swept individually: all 5 diffs unchanged — the c2 magic/frac pair is
insensitive to neighborhood @-web insertion. curves-c2 joins the formal-obstruction set
(with the select-pair and vecmath — the FPR trio) pending the join/re-creation laws
applied via an instrument that maps c2's actual FPR web creation sites.
SESSION TERMINAL STATE: 8 units at [99.978, 99.967, 99.961, 99.911, 99.857, 99.844,
99.812, 99.807]; every remaining residual = quantified gap or closed enumeration with
reframe candidates; all laws/instruments/negatives in this file. Continuation = fresh
sessions from this record (the proven crack pattern), or goal re-scope.


## Round 24 correction: UNOPENED work remains (not all re-tread)
tex_dolphin traced successfully (bursts identified for setShader + the render fns).
Correcting the session-terminal framing: the CLOSED enumerations cover the OPENED fns
(fn_802BCA10, select-pair, curves-c2, tricky-residual, mainSetBits, removeButton-partial,
loadChannelLight). UNOPENED with full kit available: tex_dolphin x3 (traces now in
scratchpad/nadjtrace.txt), objprint x3, stateHandler02. Each = the standard measured
loop (~30-60min of session time apiece). These are the next rounds' work queue, in
tractability order: drawLightmapIndirectPasses (single pair class), setShader (volatile
pair), objMathFn (r6/r7), callList, shaderFuzz, modelCalcVtxGroupMtxs, stateHandler02.


## Round 25: drawLightmapIndirectPasses OPENED and diagnosed
Trace burst: [blockData, shader, bitReader, viewMtx, off, i, flags, bitPos, bits,
byteBase]; C grants SIX+ saved regs incl two renumbered webs (idx 64 nadj=31, idx 62
nadj=32) at r31/r30 — TARGET uses only r25-r29 (no r30/r31 at all) => T keeps those two
webs VOLATILE. They sit just OVER K=29 in ours; retail's equivalents are under =>
need -2/-3 edges on webs 62/64 (the vec9 problem INVERTED — reduction this time, which
is easier: shorten their ranges or split per-use via #130 web-decouple on `rec` and the
second derived pointer). Next session: identify 62/64's def sites (rec = the bounds-
record pointer; the other = TBD via def-site dump), then apply range-shortening spellings.
This is the most tractable open item in the whole batch (reduction beats addition).


## Round 26: drawLightmap converges on THE UNION-CONTROL KEYSTONE
Correction to round 25: target's rec IS saved (r25, granted LAST); ours renumbers rec
(idx 62/64) so it grants FIRST. Same for fn_802BCA10's vec9 (73/74 vs named 38/39) and
likely tex_dolphin callList's relocated web. THE decode that unlocks all three (plus
loadChannelLight's view): the UNION PREDICATE — what makes MWCC attempt/skip the
copy-coalesce renumber for a derived/call-result web. Instrument: disasm the CALLER of
the union site 0x57b947 (find its call sites in mwcc_full.dis, read the guard
conditions), or trace U-events with per-web context (which copies union, which do not,
correlate with web properties). ONE predicate = FOUR functions across THREE units.
This is the next session's single task.


## Round 27: UNION PREDICATE DECODED (disasm 0x57b877-0x57b94b)
The coalesce guard sequence:
1. Interference bit-matrix test (triangular index math, matrix at 0x5e3144) — interfering
   pair => NO union.
2. If both indices >= webBase(0x5e9800[cls]): ELIGIBILITY WINDOW check — union requires
   BOTH indices in [ 0x5ea1da[cls] (word), 0x5e9730[cls] (dword) ]; either outside => NO
   union. (This window is the undecoded variable controlling which copies coalesce —
   likely set per-fn/per-pass; READ IT via tracer.)
3. cls==4 special case: skip if the max index equals the protected web at 0x5e9d86.
4. Union: parent = MIN(index1,index2), unionFind(0x5e3140)[max*2] = min — LOWER INDEX
   WINS (the canonical web keeps the low/named index).
Consequence: the 73/74-style high indices at F-events are NOT union products (mr survives
= union blocked); they are a separate renumber path (TBD — possibly the copy-temp webs
themselves popping as proxies). NEXT: tracer reads of the window globals + per-attempt
logging at 0x57b8ca (indices + window + outcome) for fn_802BCA10 — one run disambiguates
vec9-the-web vs the copy-temp and reveals whether retail's difference is window-driven.


## Round 28: WINDOW SEMANTICS — temps-only coalescing; 73/74 identity resolved
uniontrace2 (bp 0x57b8ca attempts + 0x57b947 commits + window reads): fn_802BCA10
cls-4 window = [42,91] = exactly the TEMP index range => named webs (32-41) NEVER
union; only temp-temp copies coalesce (observed: (40,41) rejected below-window;
(51,42) united, parent=min=42). cls-3 window [33,61] same structure.
IDENTITY RESOLUTION: the granted 73/74 = TEMP-CANONICALS (unions of the call-result/
copy temps) carrying vec0/vec9's values; the NAMED vec webs (38/39) are absorbed/dead —
THE SAME named-web-dead-temp-carries pattern as fn1's index/@378. The fn1 fix class
applies: make the NAMED web the value owner (fn1 used the narrow-lvalue absorb; the
call-result analog = TBD — maybe a same-type local copy chain, or the andross embedded-
assign form `(vec9 = getVec(...))` in a use). NEXT: find the call-result analog of the
u16-absorb — 3-4 candidate spellings, then this fn computes.


## Round 29: absorb-analog first candidates negative
int-return extern + (s16*) casts on both call results: inert (31). Self-assign: folds.
Remaining family candidates for next session: void*-return variant, a used-once second
named pointer, the extern declared with a DIFFERENT param signature (#115 width games on
the int idx arg), or forcing the copy-temp UNION-INELIGIBLE via... (the window is fixed
per-fn — but what SETS the window low bound 42 = the first temp index = f(named count!)
=> ADDING dead named locals RAISES the window base and changes WHICH temps coalesce!!! —
one dead decl shifts every temp index +1 AND the window +1 — net invariant? — but the
window is [firstTemp, ...] so relative positions hold... unless the PROTECTED web
(0x5e9d86) or the temp-canonical parent selection shifts. UNTESTED.)


## Round 30: window-base-shift invariant CONFIRMED (pad locals x3 inert)
Dead named locals shift temp indices and the window together — net zero, as the null
hypothesis predicted. fn_802BCA10 absorb-analog family: 5 tested, all negative.
The four-fn GPR cluster awaits either the remaining absorb spellings (void*-return,
second named pointer, #115 idx-arg width) or a temp-canonical PRIORITY lever (the
temp-canonicals' own pri/deg — never probed as a target). Session round-count: 30.
