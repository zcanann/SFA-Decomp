# Dinosaur Planet -> Star Fox Adventures file correspondence

```
Lane C39, derived on origin/staging @ 0eaa172f02.
Lane C40 closed three of the four open rows by body read (dll.c, objlib.c, footsteps.c, menu.c).
Lane C41 closed objtype.c (retail-string lens) and refined lighting.c.
Lane C45 closed the final open row: the dll.c bank-copy half was rewritten out of the GC
build (descriptors are statically linked export tables; acquire == the module's initialise).

HOW THIS WAS DERIVED (so the next lane can re-run / extend it)
-------------------------------------------------------------
Four independent lenses, all reproducible; scripts in /private/tmp/c39/.
  L1  FUNCTION-SYMBOL VOCABULARY.  `readelf -sW` every built SFA source .o for FUNC symbols
      (/private/tmp/c39/sfa_fns.txt), grep every DP src/*.c for definitions
      (/private/tmp/c39/dp_fns.txt), split both name sets into camelCase/underscore tokens and
      score each (SFA unit, DP file) pair by IDF-weighted token overlap, BOTH directions.
      => /private/tmp/c39/fnmap.py.  This is the lens that produced most rows below.
  L2  PREFIX HISTOGRAM.  Per file, the histogram of function-name prefixes (DP is rigorously
      prefixed: map*/block*/cam*/vox*/font*/fbfx*/route*/joy*/rcp*/obj*).  Catches whole-module
      moves that L1's IDF dilutes.
  L3  STRING-LITERAL INTERSECTION between DP src and SFA src.  Weak (SFA's decomp carries far
      fewer literals) but ZERO false positives: curves/objhits/object/objanim/model/voxmap/
      memory all self-pair, and map.c<->shader.c and intersect.c<->track_dolphin.c both fire.
  L4  BODY READ.  Used to settle every row marked [BODY] below.

*** CRITICAL CAVEAT, verified this lane ***
  L1 is NOT circular: SFA and DP share almost no function names (the raw name intersection over
  all 58 SFA units x 57 DP files is 8 symbols).  SFA's names were NOT bulk-imported from DP.
  BUT DP's own names ARE derivations - DP's source says so in its own comments
  ("// official name: setBlendMove (probably)", "// official name: trackGetIntersect2 ?").
  USE DP FOR SEMANTICS.  For NAMES, the only DP evidence that outranks our own body reading is
  DP's *printf string literals*, which are the original's words exactly as retail's are:
    "trackIntersect: FUNC OVERFLOW %d\n"   (present verbatim in BOTH DP and SFA retail)
    "trackIntersect: linefunctable overflow!!!\n"
    "trackIntersect() MAX_LINEPOINTS overflow!!!\n"
    "WARNING: trackGetLoaded bit overflow\n"
    "trackGetIntersect2: Bad ABC (not reporting any more)\n"
    "<objanim.c -- setBlendMove> WARNING tried to load anim -1 from cache modno %d\n"  (BOTH)
  Anything else in DP is a fellow decompiler's guess and must be re-earned from our body.

*** SECOND CAVEAT: SFA's src/main file NAMES are OURS, not retail's. ***
  The `.c` strings visible in the target .o files are dtk's STT_FILE symbols generated from our
  own split config, NOT retail data.  The only source file names retail itself utters are:
    objanim.c, objHitReact.c, expgfx.c, curves.c, camcontrol.c, textblock.c, laser.c,
    n_attractmode.c, DIMBoss.c, SHthorntail.c   (plus the SDK's dvdfs.c)
  Byte-verified against all five retail DOLs (US 1.0/1.1, EU 1.0/1.1, JP): the older reading
  "Hcurves.c" is a strings-tool artifact - the 'H' at US10 dol offset 0x30e6bb is the low byte
  (0x48) of the preceding pointer 0x800DD648, and curves_addCurveDef references 0x803116BC (the
  'c'), so retail utters "curves.c: MAX_ROMCURVES exceeded!!". snd3d*.c is uttered by no retail
  DOL either; it came from the repo's own musyx source tree, not retail data.
  Note objhits.o carries retail's "objHitReact.c: sphere overflow! %d" -> retail's own name for
  that TU's hit-reaction half is objHitReact.c. `objhits.c` is a DP-era original name (the DP
  ROM utters "objhits.c: keysize overflow error"), but SFA retail itself never says it.
  => Do NOT treat a src/main filename as evidence for anything.  Several are actively
  misleading; see the src/track row below.

THE TABLE
---------
Legend:  [BODY] settled by reading both bodies.  [L1] top-1 by vocabulary, large margin.
         [STR] corroborated by a shared string literal.  [?] plausible, NOT settled.

DP file                SFA unit(s)                              evidence / notes
---------------------- ---------------------------------------- --------------------------------
map.c            (193) main/shader.c  +  main/tex_dolphin.c      [L1 161 / 124, huge margin][STR]
                       +  main/lightmap.c  +  lightmap_draw.c    DP's ONE map module is split
                       +  main/lightmap_initmapblocks.c          four ways in the GC tree.
    -> shader.c            = DP's `map*` half: rom-list/layout/load/unload/warp/texture-scroll
                             (DP mapReadLayout/mapSaveObject/mapWarpPlayer/mapFree/mapIsLoaded/
                              blockTexscroll*/blockTexanim*/blockColorTable* ...)
    -> tex_dolphin.c       = DP's `block*` half: block emplace/load/render (DP blockLoad,
                             blockEmplace, blockFree; SFA MapBlock_loadFromFile/MapBlock_init/
                             mapBlockRender_*)
    -> lightmap*.c         = DP's `blockAddToRenderList` + `dl*` display-list/scene half
                             (SFA updateVisibleGeometry / renderSceneGeometry / sceneDraw)
    Named pairs worth lifting: mapWorldXZToMapID~mapCoordsToId, mapAreWorldCoordsInMap~isInBounds,
    mapWorldXZToBlockIndex~mapGetBlockIdx, mapWarpPlayer~warpToMap, mapFree~unloadMap,
    blockTexscrollSet/Get/Tick~mapTextureScrollSetStep/GetOffset/Acquire.
    C38's anchor holds: DP mapInitObjSetupList == SFA mapBuildRomListIndex, and DP
    gMapObjSetupLists is 0x41A0 exactly as SFA's per-map record table.

intersect.c       (56) main/track_dolphin.c                      [BODY, DECISIVE][L1 23][STR]
    DP intersect.c and SFA track_dolphin.c are the SAME module: both define a 21-function `track*`
    API.  DP: trackGetHeight{,Ceiling,Floor,Nearest} trackGetIntersect trackGetLineIntersect
    trackIntersect{Init,Tick,Broadphase,BuildAABB,GetBlockList,GetPLIndices,MarkBlocksDirty,
    ModLineBuild,NeedsUpdate,Initialized,LastLineTick} trackToggleHitLine.
    SFA already carries the retail-attested `trackIntersect` (it prints
    "trackIntersect: FUNC OVERFLOW %d") and `intersectModLineBuild`.
    ** Highest-value unlifted pair: DP `trackGetLineIntersect(Vec3f*,Vec3f*,f32,s32,
       TrackLineIntersectResult*,Object*,s8,s8,u8,s8)` is SFA's `objBboxFn_800640cc` -
       TEN parameters, identical types in identical order, and the SFA body does exactly what
       DP's does (sweep a circle from `from` to `to` against every group-6 object's local-space
       lines, then against the static track).  See "HANDED OVER" below.
    Other pairs: trackIntersectNeedsUpdate~trackIntersectRebuildPending,
    trackIntersectGetBlockList~trackGetBlockDescriptors,
    trackIntersectMarkBlocksDirty~trackInvalidateDynamicSlotsForObject,
    trackToggleHitLine~trackSetLinesEnabledByParam,
    trackIntersectTick~trackTickDynamicSlotCooldowns, trackIntersectBuildAABB~(SFA hitDetectFn_*).

camera.c          (90) main/camera.c                             [L1 132, dominant]
object.c          (81) main/object.c                             [L1 108][STR]
objanim.c         (15) main/objanim.c                            [L1 64][STR][retail: objanim.c]
objhits.c         (90) main/objhits.c                            [STR][retail: objHitReact.c]
    L1 cannot see this pair: 87 of DP objhits.c's 90 functions are still `func_8xxxxxxx`.
    DP objhits.c is therefore a CONSUMER of our names, not a source of them.
objmsg.c           (6) main/objhits.c  (folded in)               [BODY, EXACT 6<->6]
    DP objSendMesg / objSendMesgMany / objSendMesgManyNearby / objPeekMesg / objRecvMesg /
    objMesgQueue  ==  SFA ObjMsg_SendToObject / ObjMsg_SendToObjects /
    ObjMsg_SendToNearbyObjects / ObjMsg_Peek / ObjMsg_Pop / ObjMsg_AllocQueue.
model.c           (39) main/model.c  (+ main/modelEngine.c)      [L1 38][STR]
lighting.c        (16) main/modellight.c + dlls/engine/5          [BODY] SETTLED (C44).
    DP's lighting.c is TWO things and only one of them is modellight.c.  The light-EMITTER object
    API (DP lightClearEmitters and the per-light record) is main/modellight.c, which SFA renamed
    wholesale to `modelLightStruct_*` (create/free + ~30 projection/specular/glow accessors) -
    that is why L1 is diluted.  The AMBIENT / SKY-LIGHT half (DP lightInit, lightGetAmbient,
    lightDimAmbient, lightUpdateSkyLight, lightSetInside/lightGetInside, lightAmbientDL) has no
    counterpart in modellight.c at all; the matching vocabulary lives in the sky DLL,
    dlls/engine/5 (skySetAmbientColor / getAmbientColor / skyGetAmbientColor / skySetLightSlot /
    skySetLightDirection / skySetLightColor / skySetLightsEnabled / skyApplyLightSlot).  The
    sphere-mapping pair (lightModelSphereMapping / lightBlockSphereMapping) was rewritten for GX
    and now lives in the TEV builders (addSphereMapTexStage / addSphereMapLitStages,
    shader_dolphin.c).  Body read done (C44): DP lightUpdateSkyLight(dir, 4 intensities, rgb)
    == SFA skySetLightSlot(slot, dir, rgb, moon/ambient intensities, blendAlpha) at role level -
    both push the sky light's direction + sun colour + scaled moon/ambient colours into the
    renderer's light state each frame; SFA is the GX rewrite (per-slot SkyLight records blended
    by lightBlendFactor replace DP's inside/outside gInsideLightT lerp; GX light objects replace
    D_800B1834..43).  DP lightGetAmbient(u8*x3) == skyGetAmbientColor(slot,u8*x3); DP
    lightSetInside/lightGetInside have NO engine/5 counterpart (the inside-lighting flag did not
    survive the GX rewrite).  NOTHING TO LIFT: DP's light* names are derivations, and SFA's
    sun/moon/ambient vocabulary is already writer-derived (C43's skySetLightSlot triple proof).
texture.c         (19) main/texture.c  (+ main/tex_dolphin.c)    [L1]
rcp.c             (21) main/rcp_dolphin.c + main/intersect_screenmath.c  [L1 17 / 9]
    plus the `Rcp_*` functions that ended up in shader.c and texture.c.  DP rcpClearScreen /
    rcpDrawPauseScreenFreezeFrame / rcpInit / rcpScreenColour / rcpBorderColour.
di_rcp.c           (5) main/rcp_dolphin.c                        [?]
framebuffer_fx.c  (51) track/intersect_render.c                  [BODY]
    DP fbfxBurnPaper / fbfxSineWaves / fbfxWeirdResizeCopy / fbfxDoEffect / fbfxPlay / fbfxTick
    == SFA doHeatEffect / renderMotionBlur / doBlurFilter / doColorFilter / doDistortionFilter /
    doSpiritVisionFilter / drawSnowFlashOverlay / renderWhirlpool.  Same module, GC rewrite.
objprint.c        (14) main/objprint_dolphin.c                   [L1 21][name]
    DP objprintDrawObject / DrawModel / DrawChildModel / DrawShadowModel / BlendColor /
    MultiplierColor / MatrixOverride / LockIconCoords.
newshadows.c      (33) main/newshadows.c  (+ main/shadow_dolphin.c)  [name][L1 12 on shadow_dolphin]
    DP prefixes the whole module `shadows*`; SFA's is generically named (`get*`, `fill*`), so DP
    is a genuine NAMING lead here and it is UNWORKED.
shadowtex.c        (6) main/shadow_dolphin.c                     [?] DP shadowtexInit / exDraw /
    exSwapBuffer ~ SFA shadowInit / shadowBeginFrame / shadowVolumeBeginFrame.
voxmap.c          (42) main/voxmaps.c                            [L1][STR][name]
generic_queue.c   (10) main/voxmaps.c  (folded in)               [BODY] SFA Queue_Init/Push/Pop/
generic_stack.c   (11) main/voxmaps.c  (folded in)               Peek/IsEmpty/GetCount + Stack_*
route.c           (18) main/voxmaps.c (voxmaps_*Route*)          [BODY] DP routeFind/routeHeapInsert/
                       + main/pi_pathsearch.c                    routeUpHeap/routeDownHeap/
    routeScanNeighbors/routeIsGoal/routeNext/routeAddPoint/routeAddNeighbor/routeClear/routeCurve
    == SFA voxmaps_updateRoutePath / _processRouteQueue / _expandRouteNeighbors /
       _visitRouteNeighbor / _getRouteNode / _buildRouteWaypoints / _allocRouteWork
    and, for the second A* instance, pathSearchBegin / pathSearchStep / pathSearchExpandNode /
       pathSearchHeapSiftDown / pathSearchNodeMatchesTarget / pathSearchBuildPath.
memory.c          (24) main/mm.c                                 [L1 35][STR][name: both use `mm`]
curves.c          (19) main/curves.c  + dlls/engine/20_Hcurves   [L1 28][STR]
    retail's own string is "curves.c: MAX_ROMCURVES exceeded!!" (the 'H' formerly read here is
    a pointer-low-byte artifact, see the SECOND CAVEAT block) - so the "Hcurves" DLL-half name
    has NO retail-string backing; DP's own ROM also says curves.c.
joypad.c          (27) main/pad.c                                [L1 16]
vi.c              (20) main/pi_videoinit.c (+ pi_dolphin.c)      [L1 16]
pi.c               (7) main/pi_dolphin.c                         [L1][name: SFA kept the `pi` tag]
asset.c           (19) main/gameloop.c + main/pi_dolphin.c       [BODY] DP assetLoadAnim/LoadModel/
    LoadObject/LoadDLL/EnqueueLoad/QueueTick/RomLoad ~ SFA animationLoad / loadAsset /
    loadAssetFileById / loadTextureFile / getTabEntry / doQueuedLoads / loadDataFiles.
acache.c           (4) main/gameloop.c  (cacheAllocAndCopy)      [?]
rarezip.c          (6) main/zlb.s                                [BODY] the Rare zip/ZLB decompressor
                                                                 (SFA's is FOREIGN-COMPILER, do not touch)
print.c           (26) main/dll_80136a40.c                       [BODY] DP diPrintf/sprintf/strcpy
di_cpu.c          (17) main/dll_80136a40.c                       [L1 14]  == SFA debugPrintf /
di_comm.c          (9) main/dll_80136a40.c                       debugPrintfxy / debugPrintDraw /
di_cpu_stack.c     (1) (none - N64 debug stack walker)           debugPrintDrawGlyph / logPrintf /
debug.c            (3) main/dll_80136a40.c                       errDisplayHandler / errorThreadFunc.
fonts.c           (29) main/textrender.c + textrender_run.c      [L1 11][BODY]
                       + textrender_drawbox.c + gametext*.c      DP fontWindow{XY,Draw,UseFont,
    EnableWordwrap,DisableWordwrap} / fontRenderText / fontRenderFillRect / fontStringFormat /
    fontWordwrap / fontYSpacing / fontExtraCharSpacing / fontSquash / fontBgColour
    == SFA gameTextSetWindow / textRenderStr / gameTextMeasureString / gameTextRenderStrs / ...
    retail's own name for the DLL-side text block is textblock.c ("<textblock.c Init>").
main.c            (34) main/gameloop.c    [L1 22][BODY] DP mainLoop etc.
                       + main/modelEngine.c (the game timer)     == SFA gameLoop / gameUpdate /
    main / getGameState / setGameState / checkReset / cutsceneEnterExit / blankScreen.
dll.c             (12) main/modelEngine.c (the load/free API only) [BODY] SETTLED, and the
    copy half is CLOSED (C45): DP's `dllLoad(u16 idOrIdx, u16 exportCount)` / `dllFree(void*)`
    are SFA's `Resource_Acquire(u16 id, int)` / `Resource_Release(void*)`.  Proof is positional,
    not nominal: DP menuDoMenuSwap and SFA loadUiDll are the same function statement for
    statement, and where DP writes `dllFree(gActiveMenuDLL)` / `dllLoad(gMenuDLLIDs[i], 1)` SFA
    writes `Resource_Release(gModelEngineCurUiDllRes)` / `Resource_Acquire(id, 1)` - same slots,
    same literal 1, same surrounding statements.  The RELOCATION half (dllRelocate /
    dllLoadFromTab / dllFindExecutingDLL / dllReplaceLoadedDLLs / dllThrowFault) has NO
    counterpart in any decompiled SFA source: OSLink/OSUnlink are declared in the SDK headers
    but never defined in the DOL.  The COPY half was REWRITTEN OUT of the GC build - there is
    no bank copy and no loader.  Every descriptor slot is statically linked into the DOL:
    a gResourceDescriptors entry IS the module's own export table (ObjectDescriptor*: three
    reserved words + slotCountAndFlags, then initialise/release, then the export slots), so
    ResourceDescriptor's `acquire`/`release` at 0x10/0x14 alias slot00/slot01 - the module's
    own initialise/release (lbl_8031C020's acquire is GameUI_initialise, expgfx_funcs' is
    expgfx_initialise; both decompiled, in tree) - and `data` at 0x18 is &slot02, the export
    surface Resource_Acquire stores into gResourceLoadedHandles.  DP's dllLoad ROM-copy thus
    collapsed to "run the module's initialise on first acquire"; the "four banks" of
    src/dlls/README.md are descriptor-table SLOT RANGES (engine/modgfx/projgfx/objects), not
    memory banks.  The fossil: DLLS.bin / DLLS.tab / DLLSIMPO.bin still occupy file ids
    0x42-0x44 in sResourceFileNameTable (pi_dolphin.c) but NO call site in the tree passes any
    of them - mapLoadDataFile serves only the per-map ids >= 0x45, and every other
    fileLoad/DVDOpen path is reached with different constants.
objexpr.c         (28) dlls/engine/10_expgfx/expgfx.c            [STR: retail says "expgfx.c:"]
objlib.c          (14) main/obj_movelib.c + main/objhits.c       [BODY] SETTLED, split two ways.
    The space-transform half is obj_movelib.c; the TOUCH-CALLBACK half is objhits.c (which
    already holds DP objmsg.c), statement for statement:
      objRegisterTouchCallback     == ObjContact_AddCallback           (same NULL guards, same
                                      duplicate-pair scan, same cap of 16, ++ on both objects)
      objRemoveTouchCallbacksForObj== ObjContact_RemoveObjectCallbacks (same `!= 15 && != 0`
                                      compaction from the tail)
      objInvokeTouchCallbacks      == ObjContact_DispatchCallbacks     (same two ref counters,
                                      same both-orderings test)
      DP Object.unkD9              == SFA GameObject.contactRefCount
      DP sObjectPairCallbacks/sCallbackPairIndex == gObjContactCallbacks/gObjContactCallbackCount
    DP's two-object `objRemoveTouchCallback(obj, otherObj)` has NO counterpart in our tree - the
    other three are all that survive.
objtype.c          (8) main/objhits.c  (folded in)               [BODY, EXACT 8<->9][RETAIL STRING]
    SETTLED, and it carries the strongest evidence in this table: SFA's own `main.dol` contains
    "objAddObjectType: Reached MAXTYPES!!" and the function that OSReports it is
    `ObjGroup_AddObject`.  Retail's noun for an SFA "object group" is therefore **object type**,
    and objhits.c holds DP's whole objtype.c module (as it already holds objmsg.c and objlib.c's
    touch half).  The storage is the same three objects: DP gObjectTypeIndices[66] /
    gObjectTypeListCount / gObjectTypeList[256]  ==  SFA gObjGroupOffsets.offsets /
    gObjGroupObjectCount / gObjGroupObjects, i.e. a prefix-sum index array over one flat list.
      DP objAddObjectType   == ObjGroup_AddObject      statement for statement: same
          `type < 0 || type >= 65` guard, same MAXTYPES guard + printf, same duplicate scan over
          [idx[t], idx[t+1]), same `insert = (end==start) ? start : end-1`, same shift-up loop,
          same `for (t+1 .. 66) idx[t]++` suffix bump.
      DP objFreeObjectType  == ObjGroup_RemoveObject   same guard, same linear find, same
          shift-down compaction, same suffix decrement.  DP's rodata carries
          "objFreeObjectType: obj romdefno %d, type %d\n".
      DP objGetAllOfType    == ObjGroup_GetObjects     identical body (out-of-range -> *count=0,
          return NULL; else *count = idx[i+1]-idx[i], return &list[idx[i]]).
      DP objIsObjectType    == ObjGroup_ContainsObject identical body - DP's odd
          `ret = i < iend` / while-break shape is what our xor+shift boolean tail decompiles to.
      DP objTypeInit        == ObjGroup_ClearAll       zero the index array, zero the count.
      DP objGetNearestType(s32 type, Vec3f*, f32*) == ObjGroup_FindNearestObjectToPoint - same
          three parameters in the same order, same *distance-squared seed, same sqrtf on exit.
      SFA's ObjGroup_GetObjectGroup (find which list an object sits in) has NO DP counterpart;
          it is the exact inverse of objAddObjectType's `type` argument, so objGetObjectType.
    ** The two-way assignment IS resolved - by the CALLER SET, not by the body. **
      DP names its two (type, Object*, f32*) finders by whether they skip `object`, and both of
      ours skip it, so that discriminator does not exist here.  The caller sets settle it
      exactly, 2-for-2 and 50-for-50:
        DP objGetNearestTypeToExcludingSelf has exactly TWO caller DLLs, 499_NWice and
          688_DBstealerworm.  SFA's GameObject*-returning finder has exactly TWO caller DLLs,
          420 and 578_DBstealerwo - and SFA 420 IS DP 499_NWice (NW_ice_update is that body
          statement for statement: F32_MAX seed, copy the paired object's transl x/y/z and yaw,
          call the finder on its own type, then the alpha test and the `dist < 120.0f` test).
          => ObjGroup_FindNearestObjectForObject == objGetNearestTypeToExcludingSelf.
        DP objGetNearestTypeTo is the workhorse, 50 caller files; SFA's int-returning finder is
          the workhorse too, ~55 caller files, and the CCgasvent pair calls it on both sides
          (DP 463_CCgasvent objGetNearestTypeTo <-> SFA 389_CCgasvent).
          => ObjGroup_FindNearestObject == objGetNearestTypeTo.
      LANDED: all nine now carry the type vocabulary, two-sided (src + symbols.txt).
footsteps.c       (10) main/newshadows.c + track/intersect.c     [BODY] SETTLED for the SFX half;
    the DECAL half is GONE.  DP `footstepsGetSfxBank(bank)` returns one of gFootstepSfxBank1..5;
    SFA fuses the bank pick and the lookup and writes the SAME switch out TWICE - newshadows.c
    `audioPickSoundEffect_8006ed24` and track/intersect.c `objAudioFn_8006ef38` both select
    gSurfaceSfxTable + {0, 0x14, 0x28, 0x3c, 0x50, 0x64, 0x78, 0x8c, 0xa0} from the same u8
    `type`, with case 7 as the default in both.  gSurfaceSfxTable (0xD8 bytes) accounts exactly:
    9 banks x 10 u16 sfx ids (0x00..0xB3) + a 0x23-entry surfaceType->column map at 0xB4, which
    is what `base[idx + 0xb4]`, `idx < 0x23` reads.  player_state.h already binds
    footstepSoundId+surfaceType to that picker.  DP's footprint DECALS (TEXTABLE_18/19/1A
    Footprint1..3, the +/-3 quads, footstepsInit/Clear/TurnOn, the per-frame display lists) have
    NO counterpart anywhere in the tree: the GC port dropped them.
menu.c            (27) main/modelEngine.c (the UI-DLL switcher)  [BODY] SETTLED - and NOT
    engine/0, which is what the token lens ranks first (99.4) purely on the word "menu".
    DP's menu module is SFA's UI-DLL block, statement for statement:
      menuSet          == loadUiDll                    menuGetCurrent  == getCurUiDll
      menuGetPrevious  == getPrevUiDll                 menuGetActiveDLL== getCurUiDllInterface
      menuUpdate1      == uiDll_runFrameStartAndLoadNext
      menuUpdate2      == uiDll_runFrameEndAndLoadNext
      menuDraw         == curUiDllDraw    - DP takes FOUR pointers (gdl, mtxs, vtxs, pols) and
                                            forwards THREE to the vtable; SFA's takes four ints
                                            and forwards three.  That arity fingerprint alone
                                            settles the row.
      menuDoMenuSwap   == the swap block, hand-inlined at all three SFA sites
      gActiveMenuDLL/gCurrentMenuID/gNextMenuID/gPreviousMenuID/gMenuDLLIDs
        == gModelEngineCurUiDllRes / curUiDll / gModelEnginePendingUiDll /
           gModelEnginePrevUiDll / gModelEngineUiDllResourceIds
lfx.c / envfx.c    (3) main/skystars.c / render.c(getEnvfxAct)   [?] SFA render.c literally has
    getEnvfxAct / getEnvfxActImmediately - DP's envfx.c is 2 functions.  Weak but suggestive.
scheduler.c       (20) (none)                                    N64 OS scheduler; GC uses OS/VI.
boot.c / reset.c   (9) main/boot_logo.c / gameloop checkReset  [?]
audio.c / mp3 /   (16) main/audio*.c                             NOT a correspondence: DP is the
  segment_BED0.c                                                 N64 audio driver, SFA is MusyX.
libultra/*             src/dolphin/*                             platform SDK, unrelated bodies.
bitstream.c / linked_list.c / generic_* / assert.c / mpeg.c / developer_names.c / rsp_segment.c /
segment_11EF0.c / segment_11F70.c / segment_13D0.c               no located SFA counterpart.

SFA UNITS WITH NO DP COUNTERPART (GameCube-only work)
-----------------------------------------------------
  main/shader_dolphin.c        the GX/TEV shader-stage builder (N64 had no TEV)
  track/intersect_memcard.c    GameCube memory-card save/load (N64 used the controller pak)
  track/intersect_mtx44.c, track/intersect_screenmath.c   GX matrix/screen helpers
  main/gametext*.c (localisation), main/thp/*  (THP movie player)
  main/modelEngine.c is NOT one of these - it carries DP menu.c and DP dll.c's load/free API;
  only its model-list / ring-buffer / game-timer parts are GameCube-only.
  main/acosf.c / trig.c / sincosf.c / vecmath.c   MSL/PS math
  src/musyx/**                 MusyX

*** THE src/track/ FILENAMES ARE MISLEADING - RECORDED, NOT ACTED ON ***
  `src/track/intersect*.c` contain NO track-intersection code.  intersect_render.c is the
  framebuffer-FX + HUD-draw + TEV-stage module (DP framebuffer_fx.c), intersect_memcard.c is the
  memory card, intersect_screenmath.c/intersect_mtx44.c are GX matrix helpers, intersect.c is
  water FX + surface SFX.  DP's intersect.c is SFA's main/track_dolphin.c.  Renaming five source
  FILES is zero-score, high-churn and collides with four live lanes; handing to the tree owner.

OPEN ROWS (state, do not guess)
-------------------------------
  NONE.  Every content row in this table is settled.

  Previously open: the DLL bank copy (dll.c row) - CLOSED by C45.  The old claim that the
  gResourceDescriptors `acquire` callbacks reach code "not in any decompiled TU" was FALSE:
  each acquire pointer is the module's own decompiled initialise function (slot00 of its
  export table).  There is no copy machinery to find; see the dll.c row for the full proof.

  Previously open here: DP lighting.c's ambient/sky half vs dlls/engine/5 - CLOSED by C44's
  body read (see the lighting.c row; role-level match, nothing to lift).

  Previously open: dll.c, objlib.c's touch half, footsteps.c, menu.c (closed by C40), objtype.c
  (closed by C41) and the objtype.c two-way nearest-finder assignment (closed by C42 with a
  third lens: when the bodies are identical and the string lens is silent, compare the CALLER
  SETS - a rare API's two-DLL caller set is a fingerprint).  Method note: the IDF token lens (L1)
  put DP menu.c on engine/0 with a 2x margin and it was WRONG - the shared token was just "menu".
  L1 nominates, L4 (body read) decides; never land an L1 row without one.  The objtype.c row is
  the other direction: L1 could not see it at all (SFA renamed every symbol Group-for-Type), and
  it fell out of a `main.dol` STRING search.  Run the string lens FIRST on any row L1 misses.

HANDED OVER (analysis done here, the file belongs to another lane)
------------------------------------------------------------------
  DONE (C42): the nine `ObjGroup_*` functions in src/main/objhits.c now carry retail's "object
  type" vocabulary, two-sided (src + config/GSAE01/symbols.txt), 494 tokens over 168 files.
  ObjGroup_AddObject->objAddObjectType [SFA retail string], RemoveObject->objFreeObjectType
  [DP rodata string + exact body], ClearAll->objTypeInit, GetObjects->objGetAllOfType,
  ContainsObject->objIsObjectType, FindNearestObjectToPoint->objGetNearestType [all four: exact
  DP body], GetObjectGroup->objGetObjectType [ours, no DP counterpart],
  FindNearestObjectForObject->objGetNearestTypeToExcludingSelf and
  FindNearestObject->objGetNearestTypeTo [caller-set lens, see the objtype.c row].
  Do NOT extend the substitution to the SaveGame `ObjGroup` family
  (SaveGame_gplaySet/GetObjGroupStatus, gSaveGameMapObjGroupBits, gMapObjGroupStatuses,
  gSaveGameObjGroupCacheIdx, GAMEBIT_*_ObjGroups): that is a DIFFERENT concept - one 32-bit
  spawn-group mask per MAP id, held in the save file - and its "object group" noun is attested
  by the retail gamebit names themselves.

  `objBboxFn_800640cc` (src/main/track_dolphin.c, held by B32 body-only; called from player.c
  (A39/A40), tricky.c, 211, 423, LanternFire, WM_Galleon) is DP's `trackGetLineIntersect`:
  ten parameters, identical types in identical order, identical body role.  A two-sided rename
  is defensible on the BODY alone (it sweeps a circle of `radius` from `from` to `to`, first
  against every group-6 object in its own local space via trackSweepCircleAgainstLines, then
  against the static track) and it joins the file's existing trackIntersect /
  trackSweepCircleAgainstLines / intersectModLineBuild family.  C39 did not take it because the
  token substitution spans six DLL files owned by three live lanes.
```
