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
