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
