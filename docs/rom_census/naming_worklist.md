# Original-name adoption worklist (kiosk/retail string evidence)

Maps the census's identifier evidence (README §2/§3/§6) onto the current tree. Every item was
layout-verified against the current structs before listing — the assert quotes name+role, so a
proposal renames our retail-verified field to the evidence name; 2001-only fields with no
retail slot are listed as unplaced rather than guessed.

Evidence grades: **RETAIL-GEN** = machine-generated retail source (`Boot/*.c.new`);
**ASSERT-2001** = live assert text in the kiosk `default.dol` debug build (16 months
pre-retail — drift-checked per item); **DEMO-2002** = E3 `sys/main.dol` strings;
**RETAIL-STR** = strings byte-present in all five retail DOLs.

Risk: **SAFE** = byte-neutral source-local rename (fields/typedefs/macros/locals);
**GATED** = touches `config/GSAE01/symbols.txt` — must pass `tools/pairing_check.py`
(0 retail-only) + `unitfuzzy.py` on every unit `pairing_check.py --refs <name>` lists, per
`docs/rename_safety.md`; **BLOCKED** = mapping unproven or conflicts with current state.

## A. gametext vs the generated `.c.new` (RETAIL-GEN, strongest grade)

Verification anchor: `src/main/textrender.c:384` embeds `Boot_English_texts` content verbatim
({0x339,3,0x81,...} = TEXT_ERROR_CRITICAL/3 phrases/window 129) and `sJpDiscStatusMessageTable
.glyphs[43]` rows equal `Boot_English_characters[]` field-for-field.

1. [SAFE] `GameTextDef` (include/main/gametext_internal.h:13) -> `gametextStruct`; fields
   `.count`->`numPhrases`, `.boxId`->`window` (0x81/0x93 = generated 129/147),
   `.strings`->`phrases` typed `UTF8**`. `alignH/alignV/language/identifier` already match.
2. [SAFE] `TextGlyph` (gametext_internal.h:23) -> `characterStruct`; `.key`->`character`
   (typed `UCS4`), `.u/.v`->`xpos/ypos`, `.offsetX/advanceX/offsetY/advanceY`->
   `left/right/top/bottom`, `.page`->`texture`. `.font` already matches. Stale `TextGlyph.lang`
   comment at textrender_internal.h:87 needs updating with it.
3. [SAFE] typedefs `UTF8` (char/u8) and `UCS4` (u32) in the gametext header (no collisions).
4. [SAFE] macro ids at src/main/textrender.c:294-299 and :384-389: `TEXT_ERROR_CRITICAL 825`,
   `TEXT_ERROR_DISC_UNREADABLE 826`, `TEXT_READING_DISC 827`, `TEXT_CLOSE_DISC_COVER 828`,
   `TEXT_INSERT_GAME_DISC 829`, `TEXT_ERROR_WRONG_DISC 830` (0x339..0x33E exact).
5. [GATED] `gameTextFonts` (symbols.txt:13948) -> `GameTextFonts` — evidence is an array in
   GameTextData.h, ours is a runtime pointer; same concept, not proven same symbol.
6. [GATED] boot fallback statics: interior arrays of `sDiscStatusMessageTable` correspond to
   `English_825`..`English_830`/`English_1381`; retail merged them into a wrapper aggregate, so
   propose only interior-array names.
7. [SAFE-wide, low priority] `GameTextData.h` as the original shared header name.
8. LANGUAGE_* already adopted — no action.

## B. map-block / model / shader field chains (ASSERT-2001)

Map block (`MapBlockData`, include/main/map_block.h; asserts bounds-check every pointer inside
blockBase/blockEnd):
9.  [SAFE] `gcPolygons`(:94)->`GCpolygons`; `textures`(:96)->`GCtextures`;
    `vertices`(:97)->`vertexPositions`; `vertexColors`(:98)->`vertexColours` (British spelling
    assert-quoted); `vertexTexCoords` already matches.
10. [SAFE] `renderInstrsMain/Transp/Water`(:105-107) -> `renderStream`/
    `transparentRenderStream`/`waterRenderStream`. Of the u16 sizes only `renderStreamSize` is
    attested — mirror the pattern for the other two with a note, or keep positional.
11. [SAFE] counts: `nPolygons`->`numPolygons`, `polyGroupCount`->`numGroups`,
    `textureCount`->`numTextures`, `displayListCount`->`numDisplayLists`,
    `shaderCount`->`numShaders`, `vertexCount`->`numPositions`. `numColours` exists in 2001 but
    must live in the unnamed pad92 region — do NOT guess its slot.
12. [SAFE] `MapBlockBoundsRec.dlist/.dlistSize`(:15-16) -> `displayList`/`displayListSize`;
    same rename in `ModelDisplayListEntry` (model.h:201-202).

Model (`ModelFileHeader`/`ObjModel`, include/main/model.h):
13. [SAFE] `ModelFileHeader.refCount`(:101)->`usage` (u8, width pinned by UCHAR_MAX);
    `Texture.refCount` (texture.h:31)->`usage` (u16, USHRT_MAX).
14. [SAFE] `textureIds`(:111; now `textureEntries`)->`GCtextures`; `vertices/normals/colors/texCoords`(:114-117)->
    `vertexPositions/vertexNormals/vertexColours/vertexTexCoords`; `jointData`(:119)->`joints`;
    `instrs`(:148)->`renderStream`; `vertexAnimEntries`(:138)->`vertexAnims`;
    `renderOps`(:118)->`shaders` + `renderOpCount`(:166)->`numShaders`; counts
    `vertexCount`->`numPositions`, `normalCount`->`numNormals`, `textureCount`->`numTextures`,
    `jointCount`->`numJoints`, `animationCount`->`numAnims`, `vertexAnimCount`->
    `numVertexAnims`. Caveat: retail split display lists into primary+shadow post-2001 — the
    2001 `numDisplayLists` maps to the primary count only. Unplaced 2001 fields: `radi`, `exT`,
    `skin2Matrices`, `skinWeights`.
15. [SAFE] `hitVolumes`(:124)->`sphereHits`; `collisionTriangles`(:125)->`GCpolygons`;
    `collisionBlocks`(:126)->`polygonGroups` (record shapes verify).
16. [SAFE] `ObjModel.file`(:323)->`mod` (assert chain `modelInstance->mod->numJoints`).
    [GATED lead] `loadModelInstance` family vs 2001+DP `createModelInstance`.
17. [SAFE-wide, flag prominently] `ObjAnimComponent.modelInstance` (objanim_internal.h:463,
    typed ObjDef*) -> `objdata` — 2001's "modelInstance" is what we call ObjModel; the
    `ObjModelInstance` typedef alias must move with it.
18. [SAFE] `ObjDef.modelCount`(:301)->`noframes`; `ObjDef.attachPointCount`(:304)->
    `noplacements`; `attachPoints`(:287)->`placements` is INFERRED (count quoted, array not).
    `lockdata` unplaced.
19. [SAFE, medium-wide] `ObjAnimComponent.bankIndex`(:499)->`modelno`; `modelBanks`(:479)->
    `frames` (object.c:281 `modelBanks[bankIndex]` = `frames[modelno]`).
20. [SAFE] `GameObject.childCount` (game/objects/object.h:67)->`numChildren` + macro
    `MAX_CHILDREN 5` (pinned by `childObjs[5]`). `parentobj` mapping (pendingParentObj vs
    ownerObj) BLOCKED until the attach path is read against the 2001 asserts.
21. [SAFE, lowest priority] `romDefNo`(objanim_internal.h:454)->`romdefno` (2001+2002+DP all
    lowercase; casing-only, enormous touch surface).
22. [SAFE] Shader (model.h): `layerCount`(:51)->`numMaterialLayers` + macro
    `MAX_SHADER_MATERIAL_LAYERS 2`; `vtxAttrFlags`(:50)->`inputFormat` + bit macros
    `GC_VERTEXFORMAT_NORMAL`/`GC_VERTEXFORMAT_COLOUR`; `flags`(:49)->`attributes` +
    `GC_SHADERATTRIBUTE_WATER`. Only the WATER bit's name is attested — leave other
    SHADER_FLAG_* values alone.
23. [BLOCKED] `OBJ_STATE_ISFROZEN`/`stateFlags`: our frozen bit lives in `colorFadeFlags` with
    four fade-role siblings — 2001 layout likely differed; provenance note only.
24. [SAFE] `renderOpMatrix` local `count` (objprint_dolphin.c ~:1216) -> `numMatrices`
    (RETAIL-STR). [GATED lead] the 2001 handler-family names `renderOpTexture/
    renderOpDisplayList/renderOpShader/renderGCModel/objprintDraw...` — map via the 2001
    `ARGS: %x %x` trace order first.

## C. mm allocator (RETAIL-STR)

25. [SAFE] `mmAllocFromRegion` (src/main/mm.c:693): param `type`->`col`, `size`->`wantsize`,
    local `largest`->`largestsize` (mm.c:812 OSReport arg order proves all three). Propagate
    `type`->`col` to `mmAlloc` (mm.h:12).
26. [SAFE] literal `0x4000` @ mm.c:228 -> `MM_MAX_MEM_STORE_SIZE` (named by its own string).
27. `MmStore.ptrStore/ptrCurrent/size/handle`, MMSTORE_ARRAY, `mmUniqueIdent` already adopted.
    `mmShowInfoFBMemoryStore` names the store-dump fn when it lands (GATED then).
28. [BLOCKED-lean] `HeapItem`: `allocTick`->`History`, `allocId`->`Id`, `prev/next`->`from/to`
    are dump-order-only evidence.
29. [BLOCKED, high future value] mm colour vocabulary `CODE_COL/MODELS_COL/ANIMS_COL/
    ANIMSEQ_COL/AUDIO_COL/TRACK_COL/TRACKTEX_COL/TEX_COL/SPRITETEX_COL/EXPGFX_COL/DLL_COL/
    CAM_COL` — value↔name mapping unrecovered; our call sites pass raw hex.
30. [flag, don't rush] TU names: 2001 `__FILE__`s say `mm_dolphin.c` (ours mm.c),
    `models_dolphin.c` (ours model.c); conversely our track_dolphin.c was plain `track.c`.

## D. track internals (DEMO-2002)

31. [SAFE] `0x5dc` @ track_dolphin.c:1158,1358 (+ `0x5dc0` alloc @ :3552) -> `MAX_LINES`
    (1500); `0x6a4` @ :1177,1385 (+ `edges[0x6a4*2]` @ :1289) -> `MAX_LINEPOINTS` (1700).
32. [GATED, heavy] `trackGetHeight` (symbols.txt:1584) -> `TrackGetHeight` (capital T in 2001,
    2002 AND the DP ROM — three generations agree). Full pairing_check + unitfuzzy sweep.
33. [BLOCKED] `linefunctable` (20-entry per-line function-group table behind the FUNC OVERFLOW
    guard @ :1236/1508) and `PLlist` — current owners not pinned 1:1. 2001 `checkMap()` not
    located in our tree.
34. `insertPoint`, `intersectModLineBuild`, `trackIntersect`, `texRestructRefs` already
    adopted.

## E. gplay function family (DEMO-2002; retail code = src/dlls/engine/23/23.c; ALL GATED)

Original prefix is bare `gplay*` (gplaySaveGame/gplayNewGame already adopted). Proposed drops
of the `SaveGame_` wrapper prefix, demo-exact casing (note lowercase `point`):
`SaveGame_gplaySetObjGroupStatus`->`gplaySetObjGroupStatus`, `..GetObjGroupStatus`,
`..SetAct`, `..AddTime` (+macro `MAX_TIMESAVES`), `..ClearRestartPoint`->
`gplayClearRestartpoint`, `..GotoRestartPoint`->`gplayGotoRestartpoint`, `..RestartPoint`->
`gplayRestartpoint`, `..SavePoint`->`gplaySavepoint`, `..GotoSavegame`->`gplayGotoSavegame`.
[BLOCKED leads] `gplaySetPlayerno` (candidate `SaveGame_setCharacter`, unproven);
`gplayGetCurrentPlayerLactions/Envactions`, `gplayLoadOptions` — verify against bodies first.
[Adopt-when-lands] `WpError` struct (`romdefno`, `lastpolyworld`) + `findBounds` — no current
decompiled owner.

## F. cross-cutting

35. [SAFE] `MAX_COMM_PRESENT` = dimension of `TrickyState.commands[]`; the guard
    `state->commandCount == ARRAY_COUNT(state->commands)` @ tricky.c:6639 is the retail
    "need to increase MAX_COMM_PRESENT" site.
36. [BLOCKED] tricky walkgroup dump fields — printing fn not decompiled; four current
    walk-group fields' mapping to the four printed values unproven. `MAX_WALKGROUPS` belongs
    to Hcurves.c — adopt when the bound literal is identified.
37. [GATED leads] audio: `AudioStream_Play` vs 2001 `audioPlayStream`; `PlayingSongs[]`/
    `MAX_PLAYING_SONGS 8`; `GetFreeActiveSound`/`ActiveSounds[]` (also in the 2002 demo — low
    drift risk). Body-level verification first.
38. CORRECTION adopted into README §3: `UPLINK/DOWNLINK/LEFTLINK/RIGHTLINK overflow` strings
    are NOT map links — they live in src/dlls/engine/60/60.c and the item struct already has
    `upLink/downLink/leftLink/rightLink` (adopted). Same TU: `PICMENU: tex overflow` confirms
    engine/60 is the original **PICMENU** DLL (matches the §6d r59-r61 picmenu family) — TU
    naming lead, GATED.

## Execution order

Items 1-4 (pure SAFE, exact-generated evidence) -> 9-16, 18-20, 22 (SAFE assert-backed struct
fields) -> 24, 25-26, 31, 35 (SAFE locals/constants) -> GATED batches E and 32 as
single-owner, fully gated symbol changes.

Applied so far (Aug 2026 pass, each verified by full `ninja` EXIT=0 + retail DOL sha1 OK +
zero per-unit `fuzzy_match_percent` movement vs baseline): A items 1-4 (gametextStruct/
characterStruct + fields, UTF8/UCS4, TEXT_* ids), C items 25-26 (mm `wantsize`/`col`/
`largestsize`, MM_MAX_MEM_STORE_SIZE), D item 31 (MAX_LINES/MAX_LINEPOINTS), F item 35
(MAX_COMM_PRESENT). Same-named fields on unrelated structs (`CtrlCharEntry.key`,
`GameTextStringTable.count`, `HeadDisplayEntry.boxId`, `LinkMenuItem.boxId`...) were
deliberately left untouched. Everything else remains open; A5-A7, B, and all GATED/BLOCKED
items are the standing queue.
