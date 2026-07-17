# Residuals needing owner-lane action (fleet findings, 2026-07-14/15)

Verified diagnoses from the matching fleets; each blocked on authority outside a source-edit lane
(splits/symbols surgery, shared-API changes, or accepted-ceiling calls).

## Symbol/data-lane (splits.txt / symbols.txt)
- synth_voice u64 timestamp reads emit `synthRealTimeHi+0x4` relocs where retail names `synthRealTimeLo`
  (score-neutral in fuzzy but shows in ndiff; a symbol-level fix if ever desired).
- allocLotsOfTextures (newshadows 95.27): target relocs are unit-local sdata2 pool objects
  (Uachuff_803DEE00+0x14, Vdchuff_803DEDC0+0x8, Udchuff_803DEDA0+0x1c). Extern-const conversion kills
  SDA21 addressing (32-byte objects exceed the threshold). Needs the data-pool claim treatment.
- Conversion-pool `@N` vs named doubles blocks (partial list): modelAnimUpdateChannels @539/lbl_803DE820,
  updateEnvironment @176/gLightmapU32ToDoubleBias, fn_8011EF50 @314/gGameUiU32ToDoubleBias,
  camslide_update @249/lbl_803E1698, dbstealerworm A08 @268/lbl_803E62E0, trickyMove @221/gTrickyS32ToDoubleBias.

## Shared-API changes (cross-unit risk, one owner call each)
- drlasercannon_aimAtTarget (97.66): target emits double-extsh after getAngle calls => retail's prototype
  returned s16 (MP4 corpus corroborates the idiom). getAngle is globally int; retyping is a shared-header
  decision affecting all callers.
- videoInit (pi_dolphin, 99.27 ceiling): retail inlined PPCMfmsr/PPCMtmsr/PPCMfhid0/PPCMthid0 (SDK asm
  intrinsics). Clean-C ceiling reached; matching further requires the SDK-inline treatment in src/dolphin/.

## Accepted-ceiling candidates (clean C provably cannot reach)
- gameTextInitFn_8001c794 (93.86): target keeps a write-only loop counter with NO zero-trip guard —
  unreachable under every pragma set/O-level/array form tested (7-stack matrix). Compiler pass-order quirk.
- fn_80007F78 (render 94.81): one-register pressure delta (target spills a u64 hi word to 40(r1));
  the whole 77-region rotation cascades from it; no clean-C forced-spill form found.
- renderSceneGeometry (lightmap 97.59): the required `opt_propagation off` (for the row chain) forces a
  2-instr loop guard the target lacks; propagation-on matches the unroll but opens a worse web rotation.
  Current form is the local optimum; both configs verified.

## Added 2026-07-15 (wall-audit round)
- fn_801FD6B4 (main.c, 99.36): target has a redundant `frsp f0,f1` on the mathSinf result + bare stfs —
  strong evidence the original TU declared `double mathSinf(double)` (the CLAUDE.md f32-vs-double note in
  reverse). Not expressible under the shared `float mathSinf(float)` header without a tree-wide proto
  decision. Seven source forms reproduce the frsp but never target's fresh-dest late placement.
- Coupled-constraint wall class (dll_8D_func03, ObjSeq_onMapSetup scratch-coalesce, gameTextGet,
  mapSetup, viewportEffectFn_8000e380): register coloring is fixable by decl order OR init-emission order
  but the two constraints oppose each other vs target — suggests slightly different source-level constructs
  in the original TUs rather than allocator noise.

## Reverse-creation temp-numbering signature - CRACKED for the FPR/@temp class (2026-07-16, invocation-level probe)
The suggested owner experiment ran to ground on the newclouds `__fabs` block (minimal standalone repro reproduces the exact f1/f2/f0-fresh vs f2/f1/f0-in-place flip under the unit cflags). Results:
- **Version matrix (all 20 in-repo GC compilers x unit cflags `-O4,p -inline auto -opt nopeephole,noschedule`)**: 1.0/1.1/1.2.5/1.2.5n byte-identical family; 1.1p1 minor variant; 1.3/1.3.2/1.3.2r/2.0/2.0p1/2.5/2.6/2.7 byte-identical family (our shape); ONLY 3.0a3/3.0a3.x/3.0a5.x flip to in-place fabs+thresh-f0, but with foreign integer codegen (slwi/subf for *3 vs retail mulli) - retail is NOT a different point release. Flag matrix (O0-O4, ,p/,s, -inline off/all/deferred, nocse, nopropagation, nolifetimes, noschedule-only, nopeephole-only, -sym, -lang c, -char, -rostr, -g): all inert or foreign (O1 kills CSE, O2 leaks frsp).
- **The mechanism is NOT an invocation difference - it is web-identity/banding, and it IS source-reachable.** Discriminating probes (volatile-thresh, compare-operand-swap) pin GC/2.0's pop order: '@'-temps pop LAST-CREATED-FIRST (band 4, before everything named); named locals pop FIRST-DECLARED-FIRST (band 2, after all temps). Retail's assignment needs the thresh/z/y/x loads popped as reverse-creation @temps AND the two abs results popped last as band-2 named webs. That exact object structure is reachable: DE-NAME the element loads (`v[0] = constellation[...]` direct, no scalar x/y locals - their values become the reverse-creation CSE @temps: thresh->f0, z->f0, y->f1, x->f2) and NAME the abs results as f64 locals (`f64 ax; ... ax = __fabs(v[0]); if (ax > thresh)` and in the else a block-scope `f64 ay = __fabs(v[1]);` with a nested if replacing the else-if). The named abs web absorbs the fabs dest (V-K absorption -> in-place `fabs f2,f2`/`fabs f1,f1`), and f64 (NOT f32 - f32 emits a real frsp) matches __fabs's type so no conversion appears. KEY TRAP that hid this for weeks: a FN-SCOPE-DECLARED single-use `ax` alongside NAMED x,y scalars canonicalizes back to the identical IR (byte-identical .o - the "source-inert" observation was real but only for that neighborhood); the de-name+name moves must be done TOGETHER.
- Applied to titleScreenDrawFn_80093db4: fn 99.82 -> 100, newclouds unit 99.988 -> 100.0 (fuzzy), full ninja EXIT=0, main.dol byte-identical (origin clean-room). The lever generalizes as: when retail rotates >=2 coexisting FPR temps vs ours, redistribute the contested values across the temp-band/named-band boundary (de-name loads, name results) until the pop order matches - decl order stays inert, band membership is the control.
- **Class boundary**: this cracks the VOLATILE-FPR @temp rotation class. The saved-GPR rotation caps (andross_update r24/r25 vs retail r26/r26 animState+counter, walker-init cascades) are the park/fallback grant-order mechanism, NOT this band mechanism - the lever does not transfer there (andross re-verified: residual is exactly the banked 3-cycle, plus @NNN conversion-pool relocs).

## titleScreenDrawFn_80093db4 tail (newclouds) - CRACKED via cast-deref FIFO store
The batched right-to-left conversion shape (v[2],v[1],v[0] -> r4,r3,r0, no extsh, then the three sth) is produced by spelling the FIFO stores as a cast-DEREF of the pinned global's address - `(*(PPCWGPipe2*)&GXWGFifo).s16 = x;` - with s16 operands (inline-helper params or explicit locals; both equivalent). The deref-of-&global is alias-opaque to IroPropagate, so the arg-conversion temps stay un-folded and get computed reverse-consumer-order ahead of the stores; the plain `GXWGFifo.s16 = expr` member-store form propagates/interleaves. Works under default propagation (no `#pragma opt_propagation off` needed), which also restores the strength-reduced display-list walker IVs from plain `arr[k]` indexing (the two addi-r0;mr init detours the prop-off workaround caused are gone). Volatile on the cast REGRESSES: volatile s16/u16 member stores of a variable emit extsh/clrlwi normalization (peephole-off keeps them). Fn 99.25 -> 99.82; the remaining __fabs x/y/threshold FPR region fell to the temp-band/named-band redistribution lever (see the reverse-creation entry above) - fn now 100, unit 100.0 fuzzy. The unit's MatchingFor flip is still BLOCKED on the data lane: newclouds.c owns no .sdata2 range in splits.txt while our TU emits a local .sdata2 pool (@90/@92/@103/@501/@502/@570/@571 + sqrtf__inline localstatics) whose retail home is the shared 0x803DF2xx carve (gNewCloud* + lbl_803DF2xx region) - flipping without the sdata2 pool-claim treatment links a shifted DOL (verified: unit 100.0 but main.dol differs). Needs the standard pool-claim surgery (splits/symbols ownership + retail emission order) before the complete_units flip.

## camshipbattle5c fn_8010AC48 (99.066) - true source form found, blocked by one FP home flip
Our pass1 is written z-first (`sqrtf(nz*nz+nx*nx)`, `-(nz*z+nx*x)`); the retail form for BOTH passes is x-first like our pass2. Applying `sqrtf(nx*nx+nz*nz)` + `-(nx*pts[1]->x+nz*pts[1]->z)` (src/main/dll/camshipbattle5c.c ~lines 314/320) yields perfect 1:1 instruction alignment, zero insert/delete - the SOLE residual is nx/nz homed f25/f26 vs target f26/f25 in pass1. Fuzzy currently scores the wrong-home z-first version higher (98.816 with the correct form) because the broken alignment gets textual reg-token credit. If anyone cracks the FP pair-home flip, those two x-first edits are the required companion.

## Frame-slack lever scope refinement
Trailing `u32 unused[K]` pads are DEAD-STRIPPED when the frame size already matches - the lever only applies when target `stwu r1,-N` differs from ours (as in the audio wins). Intra-frame temp-slot freshness (objanim AdvanceCurrentMove fresh fctiwz slots 8-48 vs our LIFO reuse; ObjSeq_update mirror-order slot assignment) is allocator-internal - decl reorders byte-inert, statement fusion byte-inert.

## symbols.txt over-carve: lbl_803DE9F4 (objprint shaderFuzzFn_8003cc1c residual)
Same targimpl/next-symbol-distance class you've been fixing: retail obj relocs reference `lbl_803DE9F4+0x4`, proving 0x803DE9F4 is ONE size:0x8 object, but symbols.txt (lines ~15953-15954) carves it as two 4-byte labels lbl_803DE9F4/lbl_803DE9F8. DOL bytes at 803DE9F4 = 00ff00ff00ff00ff (u16 0x00ff mask pairs - paired-single/psq_l mask shape, not floats despite data:float-adjacent neighbors). Merging to one 0x8 object should clear the SPLIT-SYMBOL region in shaderFuzzFn_8003cc1c (99.899); left to you to avoid concurrent dtk re-splits.

## Interface-global typing (unification scout, 2026-07-16)
Mechanical unification of divergent local extern types landed (11 units, md5-identical). Design-grade residue for an owner pass:
- gBaddieControlInterface is declared int* (header+definition) but EVERY consumer treats it as pointer-to-pointer-to-fn-table ((void**)*g indexed at slots 4..22); dll_0001_camcontrol.h already has a partial CamcontrolBaddieControlInterface struct proving the shape. A shared typed BaddieControlInterface** would let ~10 units drop their cast-noise. Same for gPlayerShadowInterface (int* but used as *(fn**)(*g + 0x8/0xc)).
- SHthorntailEventInterface/SHthorntailPathControlInterface (SH/SHthorntail_internal.h) and NwMammothPathControlInterface mirror the canonical MapEventInterface/PathControlInterface vtables at identical offsets with different field names (SH setAnimEvent@0x50 == canonical setObjGroupStatus@0x50) - likely misread duplicates; renaming to consume the canonical headers needs body edits. NW field names already match canonical exactly (easiest convert).
- gameloop.c defines gCarryableInterface/gPathControlInterface/gPlayerShadowInterface as void* (lines ~88-103) diverging from canonical headers, plus late block-scope-style extern redecls (~715-725).
- voxmaps.h declares gMapBlockOriginWorldX/Z as int while shader.c/track_dolphin.c use f32 - one side is wrong; f32 usage pattern suggests the header.
- dll_0035_saveselectscreen treats gMapEventInterface as single-indirection TitleMenuControl* with raw vtable[8]/[30]/[36] (gotoSavegame/setCharacter/getCurCharPos) - candidate for canonical-type consumption.

## zlbDecompress is ProDG (GCC 2.95.2), not MWCC - owner action: toolchain split
Hard evidence from the deep dive: `mcrxr cr0; addme.` decrement idiom (0/38736 hits in the whole GC/2.0 refcorpus; ProDG cc1 reproduces immediately), ~17x `andi.` where MWCC emits clrlwi (GCC andsi3), 7x countdown `mtctr/bdnz` clear loops, LR saved in a leaf, locals homed in volatile r3-r12 alongside stmw r14, dead `cmpwi r7,6` GCC artifact, per-use lis/addi named relocs for same-TU const tables. Compilers already in build/compilers/ProDG/ (3.5/3.9.3; driver wants a non-empty sn.ini, cc1.exe runs directly under wibo). If zlbDecompress is split into its own unit with ProDG support in configure.py, near-100 looks reachable - the current C is semantically exact and now scores 76.26 under MWCC with the remaining ~94 divergent instrs ALL being MWCC-vs-GCC codegen classes (mask form, loop form, prologue stmw r22/frame 64, rodata per-use relocs vs pooled base, 2x SDA21-vs-lis/addi for the in-TU sbss pair). Worth checking whether OTHER middleware-ish fns share the mcrxr signature (grep target asm corpus-wide).

## ProDG island in render.o - gap claim + fn_80007F78 wall re-diagnosis
Retail-obj mcrxr sweep (GCC-only signature) hits exactly two objects: pi_dolphin.o (zlbDecompress, proven ProDG) and render.o - where the signature sits in the UNCLAIMED gap gap_03_80006C6C_text (0x58c-0x1898, ~4.8KB of undecompiled code) between fn_80006B1C and fn_80007F78. Given the neighborhood (render_copyPackedU64Tail/Head, 64-bit bitstream math), this looks like a ProDG-compiled middleware island (video/bitstream codec family). Strong implication: fn_80007F78's 17-saved-reg storm - which resisted every MWCC source lever across multiple deep dives - may simply be ProDG-compiled too (mcrxr is sufficient but not necessary for GCC). Suggested owner sequence: (1) disassemble the gap and check fn_80007F78's prologue/mask/loop idioms against the GCC-signature list from the zlbDecompress handoff; (2) if confirmed, split the ProDG island (gap + zlb + neighbors) into ProDG-toolchain units; both long-standing walls fall together.

## zlbDecompress ProDG follow-up: compile experiment results (PARTIAL - family confirmed, build older)
Proof-of-compile ran all five in-repo ProDG cc1s (2.95.2 V1.37/v1.40/v1.46/v1.54, 2.95.3 v1.76 - all IDENTICAL output on this TU) directly under wibo (no sn.ini needed; the ngccc driver is a dead end). Pipeline that works: host `cc -E -P` preprocess, then `wibo build/compilers/ProDG/3.5/cc1.exe zlb.i -quiet -O1 -o out.s`, then `powerpc-eabi-as -mgekko`. AVOID `-O1 -fstrength-reduce` (ICE flow.c:988). Best = plain -O1: 65.3% mnemonic-LCS vs retail (MWCC hand-tuned = 90.6% on same metric), with block-for-block matches on the recurring bit-advance run (srawi/add/andi./subfic + rlwnm - GCC combines the C rotate idiom `((v<<s)|(v>>(32-s))) & (0xFFFFFFFFu>>mb)` to rlwnm directly), the 16-bit peek 10-insn run, the --rep inner loop, and retail's un-CSEd per-use lis/addi HIGH relocs.
Flag-unreachable divergences pinning an OLDER GCC build: (1) `mcrxr cr0; addme.` decrement loops (ours: addic./bdnz - no flag flips it); (2) leaf-fn LR save; (3) 84-byte frame `stmw r14,12(r1)` = 4-byte stack alignment (ours always 8-byte EABI, -mno-eabi inert); (4) andi.-preferring andsi3 (~10 sites). Candidates: pre-V1.37 SN "GameCube BUILD" ProDG 1.x/2.x or Nintendo/Cygnus GNUPro 2.9x whose rs6000.md still had the mcrxr;addme. doloop pattern. If such a compiler is sourced, near-byte match looks reachable; the render.o gap island would use the same toolchain.

## URGENT: player.c reorder 036fbf81a2 regressed 5 fns (measured on fresh build)
The "reorder functions to retail .text order (per-fn bytes identical, fuzzy-neutral)" claim does not hold on the current tree: playerUpdate 100 -> 51.56, playerRender 100 -> 73.00 (your fresh 5bb225c6b4 match), objLoadPlayerFromSave 100 -> 73.66, playerDoEyeAnims 100 -> 93.39, player_SeqFn 99.04 -> 91.48 (fresh rm+ninja of player.o, isofuzzy per-fn). Mechanism is almost certainly the effect-family inline-coupling trap documented earlier today: -inline auto only inlines callees defined ABOVE the caller, so moving small fns below their big callers (playerUpdate/playerRender) changes the callers' bodies even though the MOVED fns' own bytes stay identical - "per-fn bytes identical" verification on the movers misses the callers. Retail .text order for player likely comes from the DLL linker (same conclusion as effect1); recommend reverting the reorder or pairing it with dont_inline pragmas verified per-CALLER.
