# A103 — the wrong-computation sweep (2026-08-05, tip d5a9438860)

Mission: read every sub-100 row's divergent regions for **semantic** divergence
(memory-access-pattern deltas: extra/missing loads or stores per iteration,
stale-hoist vs per-element reload, loop bounds/direction, store-source data
flow), as a follow-up to A102's ObjSeq_start stale-hoist find. Fuzzy is a
summary; no gate can see a wrong computation — this sweep is the instrument.

## Instrument

Two passes over all sub-100 functions (population 204, scanned 204/196 after
island skip, unscanned 0):

1. per-divergent-region load/store mnemonic multiset delta (ndiff regions);
2. **whole-function** memory-op multiset keyed `(mnemonic, displacement)` with
   base register masked and frame (`r1`) / pool-literal (`0(0)`) traffic
   excluded — this pass is colour-proof and kills the region-pairing artifacts
   that dominate pass 1 (a moved load double-counts as ±1 in two regions).

Pass 1: 41 MEM rows / 57 mnemonic rows / 106 colouring-only.
Pass 2 (authoritative): **16 rows with a real whole-function difference**;
everything else (including allocLotsOfTextures, Checkpoint_buildControlPoints,
playerBuildWallTransitionProbe's fneg block, blendTextures, renderGlows'
GX-FIFO counts — 40 == 40, trackResolveSurfacePenetration,
gameTextBuildSystemFontAtlas's "missing" stw) is **alignment shuffle over equal
multisets = colouring**, verified case by case.

## Verdicts on the 16 true-difference rows

**Wrong computations found: 0.** Every difference resolves to one of five
mechanism families, all semantics-preserving:

| row | verdict |
|---|---|
| ObjSeq_onMapSetup (engine/2) | duplicated `marks[0] = 0;` in our source — an **intentional crutch** (f5c2a8f942, "+16.71 unroller shape"). Retail stores once; MWCC keeps dead pointer-deref stores, so retail's source stored once. Idempotent, NOT a wrong computation. Naive deletion costs −0.0084 whole-DOL fuzzy (99.21→67.39 on the row) via whole-function colouring reset — the two loops share pointer webs. Left in place; candidates for a do-not-fix registry entry. |
| ObjSeq_start (engine/2) | A102's known residual. Retail's ×8-unrolled body keeps ONLY the group-top `lwz 8(r4)` (stale within the group — an unroller load-CSE quirk); the remainder loop reloads per element, proving per-element source. Probed 2 fresh spellings (`p[k-j+1]` relative-index, `p[k+1]` absolute-index): SR converts both back to the walking per-element form. 5 spellings across lanes now; unreproduced. |
| doPendingMapLoads (shader) | retail re-evaluates `gShaderRomListSlotCount` for the unrolled loop's **remainder bound**; ours caches `int cn`. Direct-global-in-condition respell DOES reproduce the reload but resets whole-function colouring (98.46→94.64). Declined; the cached local is load-bearing. |
| beginLoadingMap (shader) | same reload-vs-cache family, 1 load. Declined by family. |
| sceneDraw (lightmap) | retail reloads `gLightmapDrawQueueCount` for `++` after the two queue stores; ours CSEs. 3 probes (field respell, `u32*`→`int*` store type, qi-cache removal) — MWCC store-forwards/CSEs in all; type-based aliasing did NOT flip it. Unreproduced idiom. |
| gameUiLoadResources (engine/0) | retail reloads `gGameUiCommunicatorObjects[i]` immediately after storing it; ours forwards the call-result temp for the FIRST re-read only (later re-reads match). 5 probes: cross-typed re-read, no-temp direct array (reload appears but base becomes direct-SDA instead of retail's `li r4,addr`), pointer-var + no-temp (address hoists to a saved reg — var live across the call), inline-cast postfix (SDA-folds). Characterized: retail = materialized address + no value temp, a combination MWCC turns into either forwarding or hoisting for us. Unreproduced. |
| dll_98_spawnEffect (modgfx/152) | retail `lha 534(r31)` reload of a just-stored field; ours re-extends the cached value (`extsh`). 4 spellings (s32-cast/no-cast/s16-cast/ptr-copy): MWCC always store-forwards. A102's banked remat family. |
| renderClouds (engine/9) | retail reloads `gCloudActionGlareQuadSize[0]` twice more; **our source already re-reads it** — MWCC CSEs even across volatile GXWGFifo stores. Retail's reloads = FP-pressure rematerialization. Colouring. |
| Objfsa_UpdateWalkGroupPatches (Hcurves) | loop-structure crack: retail's clear loop = ctr=8 with **32 displacement-folded `sth` (36..1524) + one `addi +1536`**; ours bumps every 8. A hand-unrolled ×32 body (`sp[0..31].groupId = 0; sp += 32;`) reproduces the fold EXACTLY (T=C=1268), but base/value webs colour r3/r0 vs retail's r4/r3 and 7 levers (decl order ×2, named-zero value var ×2, live-var zero, byteoff pun, plain/indexed) never move them; net −0.19. Declined. Mechanism banked: **displacement folding across an unrolled body comes from constant subscripts in the source body, never from SR of a variable index** (stride 48 and stride 3 both confirmed). |
| SaveGame_gplaySetObjGroupStatus (engine/23) | the inlined `saveGame_findTransientMapBit` scan folds stride-3 displacements (0,1/3,4/6,7/9,10 + one bump) in retail; ours bumps per copy. **The standalone SaveGame_findTransientMapBit compiles from the SAME inline helper and matches 100.0 with the walking shape** — retail's own standalone also walks. So the source is proven correct and the divergence is inliner-context increment-combining. Declined (any respell breaks the 100% standalone). |
| mapFillCellEntry (shader) | our two `-=` statements are in retail-reversed order (minZ then minX; retail does minX then minZ). Statement swap fixes the order but drops the row 99.32→99.28 (colouring reset). Semantics identical (independent subtractions). Declined; noted for a future colouring-capable owner. |
| voxmaps_updateActiveMap | C113's file — not touched. Read-only adjudication: same reload-vs-cache family (retail reloads 76/72/48(r31) around a store; ours caches in r5) plus one lwzx-vs-lwz idiom. No data-flow difference. |
| trackGetIntersect2 (track_dolphin, owner-hot) | retail's `stfs 0(r27)/0(r28)` are stores through **cached `&local` pointers into the same stack slots** ours addresses as `164/168(r1)` directly. Addressing idiom; consistent with its measured-inert listing. NOT missing stores. |
| worldplanet_update (466) | `lwzx` (index-web r19 kept) vs `add+lwz 0(rN)` (sum-web r21 kept) for the same `tbl->orbitObjectIds[i]` accesses. Idiom/colouring. |
| subtitleUpdateAndDraw | same lwzx-vs-computed-pointer idiom. |
| dll_0B_spawnEffect (engine/11) | same addressing idiom (lwzx + addi,16 vs add + lwz 16). |
| mapLoadUnloadObjects (shader) | retail anchors `base+0x10000` and folds `-31832` into three displacements; ours materializes the full pointer once (it is reused). Sum-web vs anchored-displacement idiom. |

MN-class rows re-checked for arithmetic divergence: fmadds/fmuls contraction
rows (ObjHits_DetectObjectPair — C113's; playerStateMoving — owner-hot) are
expression-fusion shape, value-equivalent inputs; li/mr rows are the banked
remat family; atan2f/removeButtonObject are the confirmed dot-merge cap;
loadTextureFiles' 3 extra retail `b` are block-layout (NOT the bc+8/b pair —
scan below is authoritative).

**Sweep result: population 204, scanned 204, wrong computations 0, crutch
identified 1 (ObjSeq_onMapSetup dup store, pre-existing and intentional),
fixes landed 0, declines all documented above.** A clean sweep at this tip:
after A102's ObjSeq_start fix, the sub-100 band's divergent regions contain no
detectable data-flow divergence by the memory-access-pattern instrument.

## Mission 2 — switch-lowered-break signature, tree-wide

**Resolved 2026-09-04:** `DR_LaserCan` is now 100%. The residual below belonged
to an incorrect scalar reconstruction: the N64 DLL proves a signed-angle array
and clamp loop. With those restored, expression-form absolute value reproduces
the branch pair without the extra copy. See [the evidence](DR_LaserCan_matching.md).
The historical "unreachable residual" conclusion does not hold for that source.

`tools/unfolded_branch_scan.py` (A102's instrument) over all 1005 units:
retail 1274 in-range pairs, ours 1273, **exactly one disagreeing function**:
`drlasercannon_aimAtTarget` (609_DR_LaserCan, retail 5 / ours 4). The site is
the tail `abs` (`cmpwi; blt +2; b +2; neg`). Ternary spellings
(`delta = (delta >= 0) ? delta : -delta` and 3 variants) reproduce the pair
but MWCC keeps the then-arm copy (`mr r4,r0`) that retail's coalescer elides —
the input web colours r0, not r4, under every spelling probed (7, incl.
decl-order, CSE-if/else, fresh-var, self-assign — the last two get folded
away entirely). Row score 97.660→97.638 under the best variant: **declined**.
Mission 2 yield after A102: 0 sites remaining fixable; the mechanism's
tree-wide application is COMPLETE (1 unreachable residual).

## New facts worth keeping

- **MWCC displacement folding across an unrolled body requires constant
  subscripts in the source body**; SR of `arr[i]` (any stride ≠ 1) always
  reverts to a walking pointer with a bump per copy. Retail bodies showing
  fully folded displacement runs (Hcurves 36..1524/+1536; SaveGame inlined
  0..10/+12) therefore come from constant-subscript bodies **or** from
  inliner-context increment-combining — and the SaveGame standalone-vs-inline
  pair proves the same source emits BOTH shapes.
- **MWCC store-forwarding is not defeatable organically**: same-address
  re-reads after `sth`/`stw` forward through explicit casts, pointer copies,
  differently-typed lvalues (u32* vs int*), and array-vs-struct views. Retail
  rows that reload a just-stored location (152.c, 0.c, lightmap) are a cap
  family, not a spelling difference we can reach.
- objdiff charges the missing `b` of an unfolded pair less than the inserted
  `mr` of the ternary that recreates it — recreating a branch shape at the
  cost of one copy instruction is score-negative.
- The empty-then `if/else` (`if (c) {} else S;`) is branch-threaded to a
  single folded branch by the global optimizer — it does NOT survive as
  blt/b (v_emptythen probe, DR_LaserCan).
