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

## Reverse-creation temp-numbering signature (fleet observation, 2026-07-16)
Across independent `-opt nopeephole,noschedule` units (newclouds snowCloudUpdateFlakes, dll_000B dll_0B_func09, plus the debugPrint family), wherever >=2 compiler temps coexist in a region, RETAIL assigns their registers in reverse creation order relative to our build - a clean cyclic rotation, not noise. Decl-order and the full opt-pragma family are inert against it. Combined with the web-numbering decode (our ordinary-temp band numbers reverse-creation), this smells like a compiler-invocation-level difference (pass order / deferred inlining / a point-release numbering flip) rather than any per-function source form. Suggested owner experiment: diff temp-web numbering on one small repro fn across MWCC point releases / -inline variants.

## titleScreenDrawFn_80093db4 tail (newclouds, 98.68)
Target pre-evaluates all three GXWGFifo f32->s16 conversions right-to-left (v[2],v[1],v[0] -> r4,r3,r0, no extsh) BEFORE the three sth stores. No C89 source form found that un-fuses the convert-store pairs without introducing extsh (inline-helper, reversed int locals, comma-expr, 7-pragma sweep all fail). Possibly the same deferred-inlining/pass-order issue as above.

## camshipbattle5c fn_8010AC48 (99.066) - true source form found, blocked by one FP home flip
Our pass1 is written z-first (`sqrtf(nz*nz+nx*nx)`, `-(nz*z+nx*x)`); the retail form for BOTH passes is x-first like our pass2. Applying `sqrtf(nx*nx+nz*nz)` + `-(nx*pts[1]->x+nz*pts[1]->z)` (src/main/dll/camshipbattle5c.c ~lines 314/320) yields perfect 1:1 instruction alignment, zero insert/delete - the SOLE residual is nx/nz homed f25/f26 vs target f26/f25 in pass1. Fuzzy currently scores the wrong-home z-first version higher (98.816 with the correct form) because the broken alignment gets textual reg-token credit. If anyone cracks the FP pair-home flip, those two x-first edits are the required companion.

## Frame-slack lever scope refinement
Trailing `u32 unused[K]` pads are DEAD-STRIPPED when the frame size already matches - the lever only applies when target `stwu r1,-N` differs from ours (as in the audio wins). Intra-frame temp-slot freshness (objanim AdvanceCurrentMove fresh fctiwz slots 8-48 vs our LIFO reuse; ObjSeq_update mirror-order slot assignment) is allocator-internal - decl reorders byte-inert, statement fusion byte-inert.

## symbols.txt over-carve: lbl_803DE9F4 (objprint shaderFuzzFn_8003cc1c residual)
Same targimpl/next-symbol-distance class you've been fixing: retail obj relocs reference `lbl_803DE9F4+0x4`, proving 0x803DE9F4 is ONE size:0x8 object, but symbols.txt (lines ~15953-15954) carves it as two 4-byte labels lbl_803DE9F4/lbl_803DE9F8. DOL bytes at 803DE9F4 = 00ff00ff00ff00ff (u16 0x00ff mask pairs - paired-single/psq_l mask shape, not floats despite data:float-adjacent neighbors). Merging to one 0x8 object should clear the SPLIT-SYMBOL region in shaderFuzzFn_8003cc1c (99.899); left to you to avoid concurrent dtk re-splits.
