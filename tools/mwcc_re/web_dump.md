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
