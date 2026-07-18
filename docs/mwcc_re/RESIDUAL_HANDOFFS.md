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

## Band-model refinements from the redistribution sweep (9 parked FP walls probed)
- NEW MECHANISM (worldmap win): block-scoped SINGLE-DEF FPR webs jump the named-band pop order; promoting them to fn scope restores decl-order-with-disjoint-sharing assignment. Inverse of the per-case-split lever - scope level is a band-priority axis.
- Saved-FPR pop order pinned (dfropenode, 6-observation model logged in lane transcript): [invariant-hoisted-load temps, call-result webs, named webs forward-decl]. Call-result promotion (phase->f31) not suppressible from clean C.
- De-name mechanic REQUIRES CSE-able occurrences: under opt_propagation-off units each re-occurrence recomputes into volatile f0 (walkgroup proof) - the newclouds trick is structurally unavailable there.
- camshipbattle5c fn_8010AC48: block-scope nx/nz split + x-first = PERFECT 1:1 alignment, pure reg-subs (retail is likely block-scoped source); blocker = {nx,px,pz} 3-cycle grant order (param copies vs block-named priority). Fuzzy punishes the honest form (~30-instr rotation); the aligned source shape is documented in the lane transcript for when grant-order cracks.
- DIMwooddoor clamp: complementary failure pinned - ternary keeps target's ble+b trampoline but coalesces the phi into the constant's f3; empty-then if/else keeps distSq in-place f31 (entire downstream chain matches) but the front-end collapses the empty arm to bgt. Missing piece: any source form producing an UNCOLLAPSED empty-then (or a ternary phi joining the named web).

## DR_EarthWarrior_init 100 -> 98.806 after 6367e3f168 (rodata ownership restore)
Flagging in case the .text cost was unintended: the EWColorTbl f32->u32 retype + EWPathRange pad + extern->in-TU moves in dll_0257_drearthwarrior.c dropped DR_EarthWarrior_init from 100 to 98.806 (fresh rm+ninja, isofuzzy). If the data ownership is worth the fn cost (mmpmoonrock precedent), ignore; if not, the init codegen regression is isolated to that commit's drearthwarrior hunk.

## CORRECTION: fn_80007F78 is MWCC, NOT ProDG (2026-07-17)
Direct signature check: fn_80007F78 has 0 mcrxr, 0 addme, 0 andi., 0 clrlwi, 0 stmw, and a standard MWCC prologue (stwu r1,-160(r1); mflr r0; stw r0,164(r1)). It is NOT ProDG - my earlier "probable ProDG too" note on it was wrong. ONLY the unclaimed gap_03_80006C6C_text region in render.o carries the mcrxr signature. fn_80007F78's residual (17-saved-reg permutation storm on 64-bit bitstream math) is a genuine MWCC allocator coloring wall, not a compiler mismatch. The ProDG-island handoff still stands for the gap region and zlbDecompress; just not for fn_80007F78.

## trig.c / k_tan.c fastCastS16ToFloat-family stack offset - MECHANISM IDENTIFIED, source-unreachable (2026-07-17)
The `sth r0,10(r1)` / `addi r3,r1,10` vs our `12` divergence in 8 fns (trig: fsin16, fcos16Approx,
fsin16Precise, fcos16Precise, fn_80293AC4, fn_80293D0C; k_tan: fsin16Approx, fcos16) is NOT a local-block
ordering question. **The -O0 stack-layout law (measured, and confirmed 3x against retail):**
- The incoming parameter home area starts at offset 8 and packs each DECLARED param at its natural
  size/alignment, **whether or not the param is ever homed** (a param promoted straight to r31 with
  `mr r31,r3` still reserves its slot). Address-taken locals begin at `8 + paramAreaSize`; within the
  block they are filled from the block TOP downward in declaration order (last-declared sits at the base).
- Measured base per signature (GC/1.2.5n, `-O0 -opt functions -inline auto -schedule off`):
  `()`->8, `(char)`->10, `(s16)`->10, `(int)`/`(float)`/`(ptr)`->12, `(int,s16)`->14, `(s16,int)`->16,
  `(s16,s16)`->12, `(float,float*,float*)`->20.
- Retail oracles that CONFIRM the law: trig.o `fn_80293C64(float,float*,float*)` n@20; trig.o
  `fn_80293DA4(float x)` n@12; trig_float_helpers.o `angleToVec2(int,float*,float*)` angle@20 (matched unit).
- Version discriminator: 1.0/1.1/1.2.5/1.2.5n reserve the param area; **1.1p1 and 1.3/1.3.2/1.3.2r/2.0/
  2.0p1/2.5/2.6/2.7/3.0a3/3.0a5 do not (base 8)**. Only the 1.2.x family reproduces trig's frame
  (40 bytes, `_savefpr_30`, r31@20), so the version is right.

=> retail's base of 10 means **paramAreaSize == 2, i.e. the declared param is 2 bytes wide**. But retail's
body reads `r31` RAW with zero extension (`mr r31,r3; rlwinm r0,r31,2,14,29` and `rlwinm r0,r31,0,16,18`),
which is int-param codegen; our `int angle` source is instruction-for-instruction identical to retail
(T=91 = C=91, sole diff = the two offsets). **The two facts are mutually exclusive under every reachable
config:** a 2-byte param costs an `extsh`/`clrlwi` per read in all of 1.0/1.1/1.1p1/1.2.5/1.2.5n/1.3/
1.3.2/1.3.2r/2.0/2.0p1/2.5/2.6/2.7/3.0a3/3.0a5. Measured on the real unit: `int angle` = 99.973 (base
wrong), `s16 angle` = 97.162 (base RIGHT, +2 extsh), `s16 angle` + `#pragma peephole on` = 99.122 (base
right, extensions gone, but the param copy becomes `addi r31,r3,0` and r3 is copy-propagated into the
rlwinm). Baseline (`int angle`) is the local optimum; do not "fix" the offset without also killing the
extension.

**Corroboration from a second, structurally unrelated function in the same unit:** retail `fn_80293C64`
has `addi r30,r3,0` / `addi r31,r4,0` (a **peephole-ONLY** trait - no-peephole emits `mr r30,r3`) AND
`fmr f1,f28` before the `trigReduceQuadrant` call (a **no-peephole-ONLY** trait - peephole always elides
it as a redundant copy). Verified across 1.0/1.1/1.1p1/1.2.5/1.2.5n x {`functions`, `functions,peephole`}
and across `noprop/nocse/nolifetimes/nodead/nodeadstore/space/speed/level=0/nofunctions` peephole
sub-combinations: **no configuration produces both**. Same shape of contradiction as fsin16.

=> **Conclusion: retail trig.c/k_tan.c were built by a 1.2.5-family peephole variant that (a) eliminates
redundant sign/zero extensions and (b) does NOT do the `mr`->`addi` copy rewrite / copy-propagation /
copy-elision our peephole does.** This is a compiler-build question, not a source-spelling one - two
independent functions in the same TU each need one peephole trait and one non-peephole trait
simultaneously. Ruled out exhaustively: all 16 in-repo GC compilers (+ 1.2.5n `mwcceppc_old.exe`), ~30
`-opt`/driver flag combinations, ~19 pragmas (incl. `optimize_for_size`, `global_optimizer off`,
`no_register_coloring`, `opt_*`), 436 param-type x reduce-spelling x switch-spelling source variants
(ANSI s16/u16/short/ushort, K&R short/ushort, K&R + prototype, `register`, `const`, `volatile`, 2-byte
`enum` under `#pragma enumsalwaysint off`, 2-byte struct/union by value - MWCC passes those by pointer),
and the ghost-group route (an inlined `static` helper's locals AND its by-value `s16` param both land at
`8 + paramAreaSize`, i.e. 12, not 10 - inlining does not create a slot below the param area).
**Payoff if a matching compiler build is ever sourced: k_tan -> 100 (flip) and 6 of trig's 10 sub-100 fns
-> 100.** trig's remaining gap is then fn_80293C64 (98.75), mathSinf/fn_80293DA4/fn_80293F7C (~99.7, a
shared `lhz r4,12(r1)`/`lwz r3,8(r1)` vs `lhz r3`/`lwz r0` two-register rotation).

## sky.c: fn_80089A60 improve 34edc7ed7c regressed sibling skyFn_8008a04c (net -0.12 unit)
The `int c2 -> u8 blendAlpha` param retype (+ skyEntry u8*->SkyLightSlotView*) in fn_80089A60 improved that fn 99.56->99.84 (+0.28) but reordered sky.c's shared .sdata2 anonymous pool, regressing sibling skyFn_8008a04c 99.801->99.402 (-0.40) - net -0.12 for the unit. Caught by churn-mine (same-key gate). The u8 blendAlpha param changes the fn's constant-pool footprint, shifting skyFn_8008a04c's @N pool references in a scoring way (not pure score-neutral rename). If the naming/quality gain is worth it, keep; if the sibling matters more, the param could stay `int` with the rename only (test whether `int blendAlpha` keeps the +0.28 without the pool shift).

## RECURRING PATTERN: per-fn improves regress unit-siblings via shared-pool reorder (2nd instance)
085eb7acbd "Improve objseq.ObjSeq_update 99.68->99.75" (+0.07) regressed sibling ObjSeq_ExecuteActionCommand 99.334->99.125 (-0.21) - net -0.14 for the unit. Same mechanism as the sky fn_80089A60 case (34edc7ed7c): a matching edit changes one fn's .sdata2/literal-pool footprint, reordering the TU-shared anonymous pool and shifting sibling fns' @N references in a SCORING way. This is now 2 confirmed instances. SUGGESTION for the owner's workflow: after an "Improve <fn>" edit, run the WHOLE-UNIT per-fn report (not just the target fn) before committing - the isofuzzy/objdiff per-unit proto shows all siblings. A +0.07 target gain isn't worth a -0.21 sibling loss. The churn-mine (rename-safe same-key gate) is catching these post-hoc but pre-commit whole-unit measurement would prevent them. Both ObjSeq_update and ExecuteActionCommand were previously matched via structural levers (indexed store / (int)-cast add-grouping); the pool coupling between them is tight.

## Pragma-strip campaign (556a5ac0db + lanes A/B/C 156a962ec1/c94fb78dbf/41be92f09c) regressed 9 fns
The tree-wide "strip non-original pragma spam" removed pragmas that were LOAD-BEARING for matching on these 9 fns (churn-mine same-key gate, measured post-strip):
- track_dolphin hitDetectFn_800658a4 98.31 -> 93.85 (-4.46, LARGE - likely an over-strip, not intended spam)
- track_dolphin fn_80060C14 98.66 -> 97.76 (-0.90)
- objprint_dolphin modelRenderFn_setVtxDescr 98.94 -> 98.04 (-0.90)
- expgfx expgfx_updateActivePools 99.67 -> 98.96 (-0.71)
- lightmap sceneDraw 99.73 -> 99.12 (-0.61)
- track_dolphin renderGlows 98.50 -> 98.01 (-0.49)
- track_dolphin intersectModLineBuild 99.54 -> 99.07 (-0.47)
- shader mapLoadUnloadObjects 97.30 -> 96.92 (-0.38)
- andross andross_update 99.85 -> 99.78 (-0.06)
If some of these pragmas were genuine quality-hacks, the drops are intended (authenticity > match%). But hitDetectFn -4.46 and the ~0.9 drops on modelRenderFn_setVtxDescr/fn_80060C14 suggest real matching pragmas mis-classified as spam - worth restoring those specific ones (check whether the stripped pragma was opt_propagation/scheduling/peephole off, which are the load-bearing match class, vs a truly redundant reset-only pragma). The batch also had 5 UPs (zlbDecompress +1.0, loadCharacter +0.32, dbstealerworm/animobjd2/setLanguageFn) so net effect is mixed.

### RESOLVED 2026-07-17 (commits 875136dd06 / 66d114cda6 / 3e278ced01 / 90ddc99a73 / 6c0bece1b0, all DOL byte-identical `main.dol: OK`, +~10.6pp across 5 units)
Root causes were MIXED, not all pragmas. Byte-match is truth ⇒ a retail-matching form (real pragma, volatile pun, manual unroll, goto) IS the plausible original; the strip campaign over-cleaned some of them.
- track_dolphin: GENUINE pragma strips restored → hitDetectFn_800658a4 93.85→98.31 (`dont_inline on`), fn_80060C14 +0.90 (`opt_propagation off`), renderGlows +0.49 (`opt_dead_assignments off`), intersectModLineBuild +0.47 (`opt_loop_invariants off`). +6.32pp.
- objprint_dolphin: target modelRenderFn_setVtxDescr's -0.90 is a `goto useZero`→`use=0` CONTROL-FLOW strip (declined — defensible clean-C tradeoff, LEFT at 98.04). But restoring load-bearing pragmas recovered TWO OTHER regressed siblings: renderOpMatrix 98.74→100.0 (`optimization_level 2`), shaderSetGxFlags 98.63→100.0 (`opt_common_subs off`+`scheduling off`). +2.63pp.
- expgfx expgfx_updateActivePools 98.96→99.67: NOT a pragma — a manual 8×10 switch-scan CONTROL-FLOW form + `ppc_unroll_*` pragmas that only match TOGETHER (pragmas-on-plain-loop regressed further to 97.85). The committer's "-0.35pp sanctioned" bound was WRONG (real cost -0.71). Restored the switch-scan. +0.71pp.
- lightmap sceneDraw 99.12→99.73: NOT a pragma — a `volatile s32*` CSE-defeat pun that forces a fresh reload before increment (retail `lwz;addi` vs cached `addi`), cascading regalloc across 13 regions. +0.61pp.
- shader mapLoadUnloadObjects 96.92→97.29: NOT a pragma — a `volatile s16*` load pun at the `*w == *idPtr` compare. +0.37pp.
- andross andross_update (-0.06): negligible, not pursued.
LESSON for future strip waves: `volatile` puns and manual-unroll/goto control-flow forms that byte-match retail are LOAD-BEARING RECOVERED SOURCE, not "spam" — do not strip them by pattern; gate every strip on a whole-unit per-fn re-measure + `ninja ok`.

## Pragma-strip UPDATE: track/expgfx/lightmap/shader RESTORED (thanks), gameui cluster still stripped
Good: the 7 flagged track_dolphin/expgfx/lightmap/shader regressions are all restored to their pre-strip values (hitDetectFn_800658a4 back to 98.31 etc). Remaining from the SAME campaign (lane C 41be92f09c, gameui was in the 91-file set), not yet restored:
- gameui cMenuSetItems 98.222 -> 96.374 (-1.85, LARGE)
- gameui boxDrawFn_8012975c 99.494 -> 99.051 (-0.44)
- gameui pauseMenuFn_80129ee0 99.957 -> 99.567 (-0.39)
- gameui mapScreenDrawHud 99.583 -> 99.334 (-0.25)
- gameui drawFn_80125424 98.562 -> 98.344 (-0.22)
- gameui hudDrawButtons 98.467 -> 98.347 (-0.12)
Same triage: restore the opt_propagation/scheduling/peephole-off pragmas that were load-bearing; cMenuSetItems -1.85 is the priority. (Note: the "Match pauseMenuTextDrawFn" edit in the same batch may compound the pool reorder, but the magnitudes match the pragma-strip class.)

## "Hack purge wave 1" (f2e601f48c) scope: 105 fns regressed (16 catastrophic) - pre-purge values preserved
The deliberate pragma/goto/declspec/match-volatile purge (56 files) regressed 105 fns by the churn-mine same-key gate: 16 CATASTROPHIC (<50%: gxTextureFn_80052efc 99.79->0.0, zlbDecompress 77->2, ObjModel_BlendVertexStream 99->18, gameTextBoxFn 99->21, fn_80062808 98.9->27, etc.), 69 moderate (-5 to -50), 20 minor. Assuming this is a purge-then-rematch-authentically campaign, no action needed - but IF any catastrophic drop was unintended over-reach, the EXACT pre-purge per-fn match values are preserved at $SP/prepurge_values.txt (and the full proto snapshot at $SP/prepurge_snapshot.proto) for diff/recovery. The 16 catastrophic ones were carrying #114 volatile-reread or opt-pragma-off matches that the purge removed wholesale; re-matching them authentically (without the hack) is the presumable wave-2+ work. Flagging scope only; deferring to the campaign's intent.

## Hack-purge EXPANDED tree-wide (5cf0885a6a re-purge after rebase): now 166 fns below pre-purge
The purge campaign went tree-wide (362-file batch). Cumulative 166 fns below their pre-purge match values (was 105); newest catastrophic: mtxRotateByVec3s 99.5->43.3, mmAllocFromRegion 98.6->45.5, ObjAnim_SampleRootCurvePhase 99.1->46.1, screenRectFn 99.2->47.1, boneParticleEffect_update 99.8->53.7, Minimap_update 99.1->54.2. Full pre-purge snapshot preserved at $SP/prepurge_snapshot.proto (proto) + $SP/prepurge_values.txt. This is presumed the deliberate purge-then-rematch campaign; the churn-mine is treating all purge-batch regressions as intended and only flagging NON-purge regressions going forward. If the purge scale is unintended, the snapshot is the recovery baseline.

## Hack-purge RE-MATCH results (2026-07-17): ~31 fns recovered authentically; hack-dependent set mapped
Shipped ~31 authentic re-matches of purge-demoted fns (NO hacks re-added), via two authentic levers:
1. DE-INLINE REORDER (replaces purged #pragma dont_inline): move a single-caller helper's DEFINITION below its caller + forward decl -> MWCC auto-inliner can't inline an unseen body -> caller emits `bl` like retail. Recovered: track_dolphin (15 fns incl objShadowFn_80062498 0->47, fn_800626C8 1.5->68), objprint (fn_80039B54/fn_8003A8B4 0->100, objMathFn 52->98.7), objprint_dolphin (loadMapAndParent/modelDoAltRenderInstrs 0/68->100), pi_dolphin (fn_8004B218 0->77), rcp_dolphin (gxTextureFn 0->63.6), curves (dll_15_func08 65->99.9), drearthwarrior (stateHandler02 83->99.6), skeetla (trickySelectRouteEntry 0->100), model (BlendVertex/Normal 18/20->35, InitRenderBuffers 0->95). KEY per-fn nuance: some helpers retail DOES inline (mapCheckCurBlocks, skeetla_validateRouteEntry) - keep those BEFORE the caller.
2. GENUINE GOTO RESTORATION (real error-exits/breaks/exit-diamonds, legit C89 - FLAGGED in commits for your review): track_dolphin MapBlock_loadFromFile 79->91 etc.
HACK-DEPENDENT (no authentic re-match found - left demoted; these need a decision): the WHOLE TU runs under #pragma peephole off/scheduling off for textrender, objseq, gameloop, objanim, dll_80136a40 (debug), and the model/lightmap bodies; plus match-volatile identity-cast reloads (`*(f32*)&lbl_803DECxx`) in track_dolphin hit-detect fns and lightmap sceneDraw; plus per-fn opt_* pragmas (trickyGuard opt_propagation/common_subs/lifetimes off = confirmed load-bearing; modelInitBoneMtxs opt_propagation off; etc).
>> OWNER-TOOLING QUESTION: for the whole-TU peephole/scheduling-off units (textrender/objseq/gameloop/objanim/debug), check whether RETAIL compiled that TU with `-opt nopeephole,noschedule` (many SFA DLL/noopt units are). If so, that pragma is AUTHENTIC (matches the real build flags), not a hack - the whole unit could be flipped to those cflags in configure.py and re-match without any in-source pragma. That's the clean path for the ~30 remaining hack-dependent fns clustered in these all-peephole-off TUs.

## DE-INLINE REORDER: raises per-fn fuzzy but DIVERGES from retail .text order - authenticity decision needed
Wave 1+2 recovered ~70 purge-demoted fns via de-inline reorder (move single-caller helper below its caller + forward proto -> MWCC emits `bl` like retail, replacing purged #pragma dont_inline). IMPORTANT TRADEOFF discovered: retail consistently ordered inlined helpers BEFORE their callers and used #pragma dont_inline to suppress the inline. So the reorder gets the per-fn BYTES right (both caller and helper match retail -> report.json fuzzy UP, which IS the match-score metric) but puts the helper at a different .text OFFSET than retail -> the unit cannot FLIP to Matching as-is (flip needs exact .text order).
DECISION FOR OWNER (per-unit): (a) KEEP my reorder = max per-fn fuzzy now, unit stays unflippable until reordered to retail order; OR (b) RESTORE #pragma dont_inline with natural helper-before order = same fuzzy AND flippable, IF you judge dont_inline authentic Rare source (it was a real MWCC pragma; helper-before is the natural code org, so this is arguably MORE authentic than my helper-after contortion); OR (c) leave demoted (cleanest source, no fuzzy). My commits are all labeled "de-inline reorder" for easy identification/revert. I shipped (a) because the goal is match-score and these are hack-free clean C - but (b) may be your preferred authentic+flippable path. The genuinely FORBIDDEN hacks (opt_*/peephole/scheduling-off, match-volatiles, artificial gotos) were NOT re-added anywhere; the ~40 remaining hack-dependent fns cluster in whole-TU nopeephole units (see prior handoff - cflags path).
Also FLAGGED: the goto restorations (real error-exits/breaks/loop-and-a-half, legit C89) in the commits - review if you consider any a hack. cutcam/checkpoint were owner-re-matched in parallel (my versions auto-dropped by the collision A/B).

## gxTextureFn_80052efc REGRESSED 63.6->0.0 - your ~70-unit recovery batch (02a1213c40) missed it
My de-inline reorder (d0c72ed309, gxTextureFn 0->63.6) was undone: rcp_dolphin's later commits (canonical GX API acaddd19fe / scissor e51d19b8f1 / the 02a1213c40 recovery) left the 5 single-caller helpers DEFINED BEFORE gxTextureFn again, so MWCC auto-inlines them and it explodes to 0.0. Your recovery batch covered ~70 units but not this one. FIX (your define-after-caller lever): move textureFn_800524ec (@655), textureFn_800528bc (@730), resetLotsOfRenderVars (@736), textureFn_80052bb4 (@842), gxLoadObjectLights (@880 def) to AFTER gxTextureFn (ends @996) with forward protos - all 5 are single-caller (only gxTextureFn). gxFn_80052dc0 is already after. I did NOT re-apply it myself since you have 3 active commits on rcp_dolphin and manual reorder would collide. (The other churn DOWNs this batch - arwarwing -2.7, dll_94_func03 -1.7, voxmapsFn -0.4, shaderFuzzFn -0.1 - look like your in-progress recovery partial states, not flagged.)
