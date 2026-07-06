# Rena's SFA wiki, imported

> Reference material reverse-engineered by [Rena Kunisaki](https://github.com/RenaKunisaki) and contributors, imported from the [StarFoxAdventures wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki). These are RE notes, **not independently verified** against the retail binary here - treat as leads. Each page below is cross-referenced to the concrete structs / symbols / source files it maps to in this repo.

The GameBits table from this wiki has already been imported as code: 687 named bits in the unordered section of [`include/main/gamebits.h`](../../include/main/gamebits.h).

## Pages

| Page | Covers |
|------|--------|
| [Animation](Animation.md) | Covers Fox move IDs, the model-embedded skeleton-animation compression pipeline (MODANIM/AMAP/ANIM/PREANIM TAB-BIN chain), and vertex morph-target animation; mapped to modelLoadAni... |
| [Audio](Audio.md) | Rena wiki's Audio page (SFX.bin format, sound-effect selection pseudocode, file list) cross-referenced to src/main/audio.c's audioInit/audioLoadTriggerData (exact file paths verifi... |
| [AudioStreams](AudioStreams.md) | Documents the /streams/*.adp cutscene-dialogue directory listing and cross-references it to our fully-recovered playback path (StreamEntry in include/main/engine_shared.h, AudioStr... |
| [BaddieLootDrops](BaddieLootDrops.md) | Wiki's 6-tier/50%-chance baddie loot system maps concretely to two matched pickup DLLs (0x00FF MagicDust dust, 0x00ED collectible Apple/EnergyEgg health) plus a magicplant 'move ex... |
| [ChapBits](ChapBits.md) | CHAPBITS.bin (disc-root, 0x14000 bytes, mostly zero) is verified byte-for-byte and fully zero-mapped against this repo's own retail ISO, but is not referenced anywhere in our decom... |
| [Curves](Curves.md) | Documents the RomCurve object network (DLL 0x125 point object, DLL 0x14 navigation/interpolation) and its known Type-field values, cross-referenced against dll_0125_curve.c, dll_00... |
| [DLLs](DLLs.md) | Full 469-entry DLL ID table preserved verbatim, cross-referenced against gResourceDescriptors[]/Resource_Acquire/Release in src/main/modelEngine.c (confirms the wiki's refcount-onl... |
| [Files](Files.md) | Wiki's disc file catalogue maps almost entirely onto src/main/pi_dolphin.c's sResourceFileNameTable[90]/mapLoadDataFile dual-slot streaming system, with concrete fileIds and confir... |
| [Formats](Formats.md) | Covers the E0E0E0E0/F0F0F0F0/FACEFEED pack headers, ZLB/DIR compression tags, and TAB high-bit conventions; maps every one of them to concrete, verified code in src/main/pi_dolphin... |
| [Gametext](Gametext.md) | Gametext file format, control codes, font slots/IDs, and the Sequence Lookup Table map almost 1:1 onto src/main/gametext.c + textrender.c (TextGlyph=characterStruct, GameTextDef=ga... |
| [MapList](MapList.md) | Wiki's map-ID/directory/parent RAM tables and MAPINFO.bin T-type field are all matched byte-for-byte in src/main/pi_dolphin.c, shader.c, object.c, and objprint_dolphin.c (sMapFileN... |
| [Maps](Maps.md) | Covers map layers/grids, MAPS.bin/TRKBLK.tab/HITS.bin/globalma.bin formats, and the block-model header; cross-referenced almost offset-for-offset against MapBlockData (map_block.h ... |
| [Models](Models.md) | Model file header, Bone, HitSphere, ModelVtxGroup, DisplayListPtr, and the bit-packed render-instruction script — cross-referenced offset-for-offset against include/main/model.h Mo... |
| [ObjectFileStruct](ObjectFileStruct.md) | Documents the OBJECTS.bin per-object-type record (objdata), maps nearly every field to our ObjDef struct (include/main/objanim_internal.h) and loadObjectFile/objGetTotalDataSize/lo... |
| [Objects](Objects.md) | Wiki's ObjInstance layout, message-queue system, object-name prefixes, and object-category IDs mapped field-by-field to this repo's ObjAnimComponent (objanim_internal.h) + GameObje... |
| [Romlist](Romlist.md) | Wiki's disc romlist entry format (type/size/acts/loadFlags/bound/cullDist/position/id, act-bit tables, OBJINDEX.bin) is matched almost verbatim: ObjPlacement, SaveGameRomListPositi... |
| [Scripting](Scripting.md) | Rena's Scripting wiki page (ANIMCURV/OBJSEQ sequence VM, condition scripts, triggers) maps almost entirely onto src/main/objseq.c (DLL 0x02 ObjSeq), src/main/dll/dll_0126_trigger.c... |
| [Shop](Shop.md) | ThornTail shop item price/discount/gamebit/text table, cross-mapped to DLLs 0x284/0x285/0x286 (shopitem/spshop/spshopkeeper), the ShopItemRow struct in dll_0285_spshop.c, and ~20 a... |
| [Textures](Textures.md) | Covers TEXn.bin/tab layout, the 0x60-byte Texture header, GXTexFmt/GXTexObj, texture-ID translation (TEXTABLE/TEX0/TEX1/TEXPRE), the model Shader/ShaderLayer/ShaderFlags/AttrFlags ... |
| [Tricky](Tricky.md) | Covers Tricky's attack-timer mechanic, unused Decoy/Guard/Baddie-Alert/Kyte content, ball-play color progression, and the Mammoth Dismount/Death Crash/Weird Head Movement bugs, cro... |
| [UnusedThings](UnusedThings.md) | Cross-referenced the wiki's unused-content page against this repo; strongest confirmed matches are getLActions() in src/main/render.c (LACTIONS.bin, byte-for-byte), DLL 0x11 = src/... |
| [Warptab](Warptab.md) | Documents WARPTAB.bin's 16-byte warp-destination records; verified byte-exact against src/main/rcp_dolphin.c's warpToMap/WarpDestination (getTabEntry fileId 28 == sResourceFileName... |

## Code-incorporation roadmap

Concrete, high-confidence naming/enum/struct opportunities the agents surfaced while cross-referencing each page against our code. These are **proposals for review**, not applied changes (the GameBits import above is the one exception). Each is scoped to a specific file/struct so it can be adopted and build-verified individually.

### Animation
- ModelFileHeader.unk70 (include/main/model.h, u8[0x10] at offset 0x70) should become s16 animGroupBaseIndices[8] - confirmed by modelLoadAnimations writing s16 group-base indices there while scanning MODANIM.BIN for -1 sentinels; matches the wiki's per-model Idx0..Idx7 table exactly.
- Add a Fox move-ID constant set (FOX_MOVE_STANDING=0x0000, FOX_MOVE_RUNNING=0x0003, FOX_MOVE_FLY_ARWING=0x0263, FOX_MOVE_GET_ITEM=0x035A, etc., full list in the doc) - no existing enum/define home in the codebase for these; values consumed as raw moveId ints by Object_ObjAnimSetMove/ObjAnim_SetCurrentMove via PlayerState.moveAnimTable.
- Rename gModelTexAtlasList (src/main/model.c, local extern, no header) to something like gModelAnimCacheList - every verified call site (modelLoadAnimations, animLoadFromTable's macro sibling, loadAnimation) keys it by animId, never a texture id; the 'Tex' naming appears to be a misnomer inherited from a generic shared-cache helper pattern.
- ObjAnimState+0x2c (include/main/objanim_internal.h, currently u8 pad2c[8]) holds a real pointer field (confirmed write site in ObjModel_SampleJointTransform feeding fn_80007F78's posA read) - at least the first 4 bytes should be named/typed rather than left as padding; ObjAnimState+0x4c (inside pad4c[0x58-0x4c]) is similarly read as a u16 'next frame stride' by fn_80007F78, though its writer wasn't traced in this pass.

### Audio
- Declare gSfxTriggerExtraTable as u8[8] instead of a bare scalar extern in include/main/engine_shared.h — confirmed 8 bytes at 0x803DB248 via config/GSAE01/symbols.txt, matching the wiki's sfxTable_803db248[8]; byte contents from the wiki are unverified against the ROM and should be hex-dump-confirmed before adopting the literal values.
- Rename SfxTriggerFull.field_6 -> nearDistanceRaw and field_8 -> farDistanceRaw (or similar) in include/main/engine_shared.h now that Sfx_ReadTriggerParams/Sfx_PlayFromObjectEx confirm they feed nearDist/farDist respectively — resolves two previously-unnamed placeholder fields with high confidence.
- Investigate whether SfxTriggerFull.pitchBase/pitchRand should actually be named panBase/panRand (or similar) — the wiki's basePan/panRand with '127=center' semantics fits a pan center-point far better than a pitch value; the computed value is a dead parameter by the time it reaches Sfx_AllocObjectChannel so usage doesn't disambiguate, needs further investigation before renaming.

### AudioStreams
- Name StreamEntry.fadeBits/volBits bit layout as macros (STREAM_FADEBITS_FLAGA_SHIFT/FLAGB_SHIFT/STOPSFX_SHIFT, STREAM_VOLBITS_CHANMASK_BIT/VOLUME_MASK) in include/main/engine_shared.h next to StreamEntry, derived directly from AudioStream_Play's shift/mask expressions.
- Revisit the header comment in src/main/dll/CC/dll_0122_cctestinfot.c which guesses the map is 'Crystal Caves' - our own map-name tables (sMapFileNameCapeclaw/Ccshrine/Ccbridge, mapId 47) confirm it is Cape Claw, matching the wiki's CC directory.
- Revisit src/main/dll/dll_0195_dbshshrine.c's header comment guess ('Discovered/Bone-shop' for 'dbsh') - the literal map-table name "dbshrine" (a Krazoa spirit shrine, mapId 43) is a more direct fit for its 'dbsh' abbreviation.

### BaddieLootDrops
- COLLECTIBLE_ITEM_ENERGY_EGG (0xB) / COLLECTIBLE_ITEM_APPLE (0x3CD) constants for the obj->anim.seqId values switched on in collectible_applyPickup (dll_00ED_collectible.c) and spawned by largecrate_spawnDropContents (dll_0105_largecrate.c) -- cross-verified in two independent call sites, high confidence
- LARGECRATE_DROP_* enum for LargeCrateState.dropType's switch values (1/2/3/5/6/7/8/9) in dll_0105_largecrate.c, replacing bare case labels
- Resolve the 6-byte size mismatch between this codebase's SnowClawAnimTbl ({ s16 v[5] }, 10 bytes) and symbols.txt's recorded 0x10-byte size for gSnowClawDropObjectTable before trusting the table's element count
- If/when the generic baddie loot-drop logic is decompiled out of baddieControl.h's FUN_8010xxxx range, name it against BaddieState/GroundBaddieState (baddie_state.h) using this wiki page's tier1/3/6 + 50%-chance framing

### Curves
- ObjfsaRomCurveDef (include/main/dll/objfsa_romcurve.h) tail 's8 angle; u8 pad2D[3];' at 0x2C-0x2F should be split into 'rotZ/rotY/rotX/pad2F' (s8/s8/u8/u8) to match the sibling RomCurvePlacementDef (dll_0015_curves.h) and DrakorCurveNode (dll_0271_drakorhoverpad.c) overlays of the exact same offsets, which already use three named one-byte fields instead of one byte + padding.
- Centralize the verified RomCurve Type literals (0x03 HagabonMK2, 0x15 DIM2PathGenerator/ROMCURVE_TYPE_ACTION, 0x16, 0x17, 0x23 CurveFish, 0x24 Tricky) as named #defines next to ROMCURVE_TYPE_ACTION/ROMCURVE_TYPE_SCALE_OVERRIDE_15 in include/main/dll/dll_0015_curves.h instead of bare hex literals scattered across dll_0014_unk.c and dll_0103_curvefish.c.

### DLLs
- Add a canonical `SFA_DLL_UNUSED_IDS` list (26 IDs) marking confirmed-inert gResourceDescriptors[] slots — currently this fact exists nowhere in-tree; would prevent future contributors from hunting for source that was never written.
- Rename the ~20 still-`lbl_ADDR`-named entries in gResourceDescriptors[] (indices like 0x00-0x2, front-end range 0x32-0x44, etc.) to descriptive `g<Name>ObjDescriptor` symbols now that their owning dll_XXXX_name.c/flat file has already identified them (e.g. objseq.c for index 2, sky.c for index 5, dll_0037_optionsscreen.c for index 0x37) — the file-level identification work is done but not reflected back into modelEngine.c's array.
- include/main/dll/FRONT/dll_0032_n_rareware.h is misnamed relative to its content: the header's own declarations (n_rareware_render/frameEnd/etc.) belong to DLL 0x0033 per src/main/dll/dll_0033_nrareware.c's header comment, not 0x0032 as the filename implies — worth a rename/relabel for consistency with the dll_XXXX_name.c convention used elsewhere.

### Files
- Add `enum MldfFileId` (90 named fileId constants, fully drafted in the doc) to include/main/pi_dolphin.h and replace raw hex literals at call sites in model.c, object.c, track_dolphin.c, shader.c, rcp_dolphin.c, objHitReact.c, and pi_dolphin.c itself.
- OBJHITREACT_ENTRY_TAB_FILE_ID in include/main/objHitReact.h could be redefined as MLDF_FILEID_OBJHITS_BIN once the enum exists, documenting the disc-file link explicitly.
- WarpDestination in src/main/rcp_dolphin.c could gain a one-line comment tying its 16-byte layout to WARPTAB.bin fileId 0x1c (idx<<4 stride) for future readers.
- model.c's raw `0x2c`/`0x2d`/`0x2e`/`0x31`/`0x32`/`0x52` literals in fileLoadToBufferOffset calls are good candidates to rename via the same enum, since their formats (offset-index vs payload) are now documented.

### Formats
- Named constants for the texture TAB bank-word (bankWord in rcp_dolphin.c:2459-2460): TEX_TAB_MAP_A/B (0x80000000/0x40000000), TEX_TAB_MIP_COUNT_SHIFT/MASK (>>24 & 0x3f) - currently bare literals, high-confidence per wiki's explicit texture-TAB paragraph and matching source arithmetic.
- PackHeader (pi_dolphin.c:160) and ZlbHeader (pi_dolphin.c:146) are currently file-local to pi_dolphin.c but are reused across at least 3 call sites (loadAndDecompressDataFile, piRomLoadSection) and conceptually apply repo-wide to any FACEFEED/E0E0E0E0/ZLB/DIR blob - candidate to promote to a shared header (e.g. include/main/resource.h) with the wiki-cross-referenced field comments already drafted in this doc.
- Confirmed answer to wiki's open question 'DIR only supported for textures?' = yes, specifically TEX1.bin and TEXPRE.bin (fileId 0x20/0x4b/0x4f) per loadAndDecompressDataFile - worth a source comment update at those call sites citing the resolved uncertainty, though this task was told not to edit code/headers itself.

### Gametext
- Add a LANGUAGE_ENGLISH..LANGUAGE_SPANISH (0-5) enum fixed by sLanguageNameTable[] order in src/main/gametext.c:1284
- Add GAMETEXT_FONT_JAPANESE/ICON/FLAG/LATIN/FACE (0,2-5) enum for TextGlyph.lang / GlyphEntry font ids
- Add GAMETEXT_SLOT_DIALOGUE/CUTSCENE/ERROR/HUD (0-3) enum for gGameTextCharsets[] slot index, verified exactly against directory ids (Boot=3->slot2, Link=0x1c->slot3) in gameTextLoadDir (textrender.c:1494)
- Rename TaskTextEntry{a,b,key} (include/main/engine_shared.h:314-318) to {textSeqId, dirId, objSeqId} and gameTextGetTaskText's outA/outB params accordingly - exact-match verified against the wiki's whole Sequence Lookup Table
- Rename GameTextDef.pad0[2] (include/main/engine_shared.h:463) to identifier (u16) - it's read, not padding, per gameTextGet's linear scan; also rename f5/f6 to alignH/alignV, pad7 to language
- Add named control-code #defines for TEXT_CTRL_SEQ_ID(0xe000), TEXT_CTRL_SEQ_TIME(0xe018), TEXT_CTRL_HINT_ID(0xe020) alongside the existing TEXT_CTRL_SCALE/_LANGUAGE/_ALIGN_*/_COLOR in textrender.c
- Consider renaming TEXT_CTRL_LANGUAGE (0xf8f7) to TEXT_CTRL_FONT since it sets glyphLang/a font id, not a spoken language, per the wiki's 'Set Font' description

### MapList
- Add a shared MapId enum (0x00-0x74, named after sMapFileNameTable's existing Romlist strings) to replace ~122 mapGetDirIdx()/lockLevel()/unlockLevel()/mapUnload() call sites currently passing bare hex literals across src/main/dll/**
- Add a shared MapType enum (MAPTYPE_NORMAL/SUBMAP/UNLOAD_UNUSED/SUBMAP_UNUSED/NO_HUD = 0-4) for curMapType/getCurMapType() in shader.c, replacing magic-number comparisons in object.c:1994/2007 and lightmap.c:440
- Fold the per-file duplicated map-ID defines (DIMBOSS_MAP_DIR=0x1C, DIMBOSS_GUT_MAP_DIR=0x1B, DIMTOP_MAP_DIR=0x13 in include/main/dll/DIM/dll_01E0_dimboss.h; CRCLOUDRACE_DRAG_ROCK_MAP_ID; WORLDPLANET_MAIN_MAP_ID) into the single MapId enum once adopted
- Name the 0x20-byte MAPINFO.bin record struct (now that offset +0x1c = map type is pinned down via shader.c:502/2785) instead of raw u8*/getTabEntry byte offsets

### Maps
- Fill include/main/map_block.h's MapBlockData padding (0x34-0x58, 0x5C-0x90) with the now-confirmed fields: gcPolygons(0x4C)/polygonGroups(0x50)/textures(0x54)/vertexColors(0x5C)/vertexTexCoords(0x60)/shaders(0x64)/displayLists(0x68)/hits(0x70)/renderInstrsMain,Transp,Water(0x78/0x7C/0x80) plus their counts(0x84/0x86/0x88, 0x98)
- Rename map_block.h's `layerCount` (0xA2) to `shaderCount` (it bounds the shaders[] array, per fn_8006070C in dll_0134_texscroll2.c) to stop it colliding in name with MapShader.layerCount (0x41, the per-shader nLayers) in tex_dolphin.c
- Rename map_block.h's `edgeCount` (0xA1) to `dlistCount`/`nDlists` (it bounds the displayLists[] array per MapBlock_init's fixup loop and fn_800606FC, matching the wiki's nDlists) while keeping a note that dll_013C_xyzanimator.c's EdgeVerts view of the same array is a valid alternate interpretation
- Unify the scattered MapTriIndex/MapTriGroup (track_dolphin.c) and MapShader/MapBlockBoundsRec (tex_dolphin.c) typedefs into map_block.h so tex_dolphin.c's narrower duplicate MapBlockData declaration can be retired
- Add a SurfaceType enum (SURFACE_GENERIC/GRASS/SAND/SNOW/INSTANT_DEATH/ICE/WATER/LAVA/CONVEYOR/METAL) for the confirmed-behavior subset of PlayerState.surfaceType values used in dll/player.c's switch, replacing bare case 3/8/13/26/29 literals

### Models
- Add ModelDataFlags2 #defines (MODEL_FLAG_NO_ANIMATIONS 0x2, MODEL_FLAG_NO_DEPTH_TEST 0x400, MODEL_FLAG_ALPHA_Z_UPDATE 0x2000, MODEL_FLAG_ALT_POINTER_LAYOUT 0x8000) to include/main/model.h alongside the existing MODEL_FLAG_DYNAMIC_VERTEX_BUFFERS/MODEL_FLAG_VERTEX_ANIM_AREA
- Add MODEL_FLAGS24_VERY_BRIGHT 0x02 next to the existing MODEL_FLAGS24_NORMALS_9BYTE in model.h
- Add MODEL_SHADERFLAGS_USE_OBJ_COLOR 0x0002 for ModelFileHeader.shaderFlags bit 2, confirmed via objprint_dolphin.c:1791 gObjOverrideColor path
- Add a ModelRenderInstrOpcode enum (values 0-5) for the instrs bitstream opcodes, matching the existing prose comment in objprint_dolphin.c near line 862 almost verbatim
- Name ModelFileHeader offset 0xFA as texCount/texMtxCount (u8) — confirmed as a texture-matrix-descriptor loop bound at objprint_dolphin.c:1583 (hdr[0xfa])
- Name ModelFileHeader offset 0xF5 (currently referenced only positionally as unkF5) as displayListCount — confirmed as the primary/first-group display-list count via model.c:415 and objprint_dolphin.c:2135
- Define a ModelBone/Bone struct (s8 parent; u8 idx[3]; f32 head[3]; f32 tail[3]; total 0x1c) to replace the raw u8*+0x1c-stride walk in model.c's modelInitBoneMtxs/modelInitBoneMtxs2/modelGetBoneMtx call sites, and correct the comment that tail is unused -- it's the skinning rest-pose translation

### ObjectFileStruct
- Name ObjDef+0x50/+0x52 (currently raw pad in the struct, read ad hoc as *(s16*)(def+0x50/0x52) in loadCharacter) as s16 dllId; s16 category; - dllId is confirmed to be the id behind every src/main/dll/dll_XXXX_*.c file, category is the same id our object_class_packets.py calls class_id
- Name ObjDef+0x61 (currently pad61, an isolated 1-byte gap) as u8 hasHitbox - confirmed live via *(u8*)(def+0x61) checks in object.c:1439/1465/2539
- Add AttachPoint* attachPoints at ObjDef+0x2C and u8 attachPointCount at ObjDef+0x58 (both currently unnamed padding, never dereferenced anywhere in src/) using the wiki's 0x18-byte AttachPoint layout (pos f32x3, rot s16x3, bone s8, +4 more s8)
- Investigate/likely fix: ObjDef.helpTextIds is declared s16[8] (objanim_internal.h:256) but the wiki and our own tools/orig/object_catalog.py agree the on-disk field is only 4 u16 help-text ids at 0x7C - the extra 4 slots (0x84-0x8B) overlap what the wiki separately identifies as unknown bytes + a 'lagVar88' float; every known DLL call site only indexes 0..3
- Adopt full ObjFileStructFlags44 bit set as OBJDEF_FLAG_* defines in objanim_internal.h (only OBJDEF_FLAG_DEFERRED_RENDER 0x800 exists today; 0x1/0x10/0x20/0x40/0x400/0x8000/0x80000/0x200000/0x400000(confirmed)/0x800000(confirmed)/0x1000000 are transcribed and ready, provided as fenced C in the doc)
- Add enum ObjShadowType (NONE/BIG_BOX/MODEL_GEOMETRIC/CRASH/BLUE_GLOW_RECT) for ObjDef.shadowType, replacing the raw 0/1/2/3 comparisons already confirmed in object.c and newshadows.c
- Reconcile OBJDEF_RENDERFLAG_PROJECTED_SHADOW(0x4)/DEFERRED_RENDER(0x10) against the wiki's differing ObjFileStructFlags5F story for the same two bits before adding the remaining 5 bits (0x01/0x02/0x08/0x20/0x80)

### Objects
- Rename ObjAnimComponent.seqId (offset 0x46) to defNo - retail debug string in objlib.c literally reads "...defno=%d..." from this field, and ObjList_FindNearestObjectByDefNo(obj, defNo, ...) compares its defNo param directly against it
- Rename GameObject.paletteIndex (offset 0xE8) to hintTextIdx - object.c's own objSetHintTextIdx(int obj, u16 idx) function writes exactly this field
- Reconcile ObjAnimComponent.bankIndex (0xAD) naming: objlib.c independently calls the same offset OBJ_ACTIVE_MODEL_INDEX_OFFSET, and the wiki calls it curModel - two of three sources disagree with the header's bankIndex
- Add a category-ID enum for ObjAnimComponent.classId (0x44) - currently every comparison site uses bare hex; at least 8 values (Player=1, Tricky=2, AnimatedObj=0x10, unused-seq03=0x11, most-baddies=0x1C, enemy-mushroom=0x2A, player-weapon=0x2D, KT_Rex=0x6D) are confirmed live in this codebase
- Break out ObjAnimComponent's unnamed 13-byte pad37[0x44-0x37] gap into next(ObjInstance* @0x38)/loadDistance(f32 @0x3C)/cullDistance2(f32 @0x40) per the wiki's ObjInstance table
- Consider naming GameObject.unkF1[3] (0xF1-0xF3) as brightness/colorIdx/? per wiki, though 0xF3 conflicts with objlib.c's own OBJ_MODEL_JOINT_COUNT_OFFSET define - needs a usage check before picking

### Romlist
- Add a shared RomListEntryHeader struct (type/size/acts0/loadFlags/acts1/bound/cullDist/posX,Y,Z/id) to a new include/main/romlist.h — independently confirmed byte-for-byte by ObjPlacement, SaveGameRomListPosition, and the raw *(u8*)(obj+N) arithmetic in shader.c/object.c, but currently has no single named type anywhere.
- Add ROMLIST_LOADFLAG_* #defines (IS_LEVEL_OBJECT=0x01, IS_MANUAL_LOAD=0x02, NEAR_PLAYER_ONLY=0x04, LOAD_FOR_OTHER_MAP=0x10, IS_BLOCK_OBJECT=0x20) to replace the bare `*(u8*)(obj+4) & N` literals in shader.c's objShouldLoad, matching the OBJLOAD_FLAG_* naming convention already used nearby in object.c.
- OBJHITREGION_ROM_ENTRY_TYPE (0x130) in objlib.c could be cross-checked against other romlist entry `type` constants if/when more per-type entry structs get named, forming a small ROMLIST_ENTRY_TYPE_* enum.

### Scripting
- enum SeqActionOpcode for ObjSeq_ExecuteActionCommand's top-level action-command switch (src/main/objseq.c) - SETTIME/MOVEMODE/ANIM/OVERRIDE/.../SET_MAX_TIME, fully wiki-verified for opcode 0x02
- enum ObjSeqSubCmd0BOp for seqDoSubCmd0B's condition-script op field (packed & 0x3f) - fully case-verified against the wiki
- enum ObjSeqConditionCode for ObjSeq_EvaluateCondition's 18 condition cases (seqCounter/day-night/gObjSeqBoolFlags/gObjSeqCondFlags/seqGlobal1-3/timer) - semantics verified, note flagged off-by-one wrinkle vs wiki hex numbering around 0x0F
- enum SeqEnvfxBgOpcode for objSeqDoBgCmds0D's ENVFX background-command switch - fully case-verified including the exact screen-transition duration/fade table
- named #define/array-literal for lbl_8030EDA4 (input-override table {0x100,0x200,0x40000,0x80000,0x20000,0x10000,-1}) - exact match to wiki
- resource-file-id enum/#defines for the sResourceFileNameTable indices already confirmed here: 0xd=ANIMCURV.bin, 0xe=ANIMCURV.tab, 0xf=OBJSEQ2C.tab, 0x3b=OBJSEQ.bin, 0x3c=OBJSEQ.tab
- GAMEBIT_ENV_disableDayFX3 = 0x3AF could be added to include/main/gamebits.h's enum GameBitId (siblings 0x3AB/0x3AC already present; 0x3AF confirmed by this page's ENVFX subcommand 0x1C op 0x02 but not yet in the header)
- naming TriggerPlacement's pad3A[0x44-0x3A] gap fields (localId-adjacent size[3]/rot[2]/target) in src/main/dll/dll_0126_trigger.c using the wiki's offsets 0x3A/0x3D/0x43

### Shop
- Adopt `enum ShopItemIndex` (SHOP_ITEM_DUMBLEDANG_POD=0x00 ... SHOP_ITEM_MAP_VOLCANO_FORCE_PT=0x33, SHOP_ITEM_LAST=0x3B) into src/main/dll/SP/dll_0285_spshop.c so shop_buyItem's switch (currently raw cases 0,1,2,3,4,5,6,7,8,0x17) and the ShopItemRow accessors read by name instead of magic hex.
- Split ShopItemRow's anonymous `u8 pad1[0x4 - 0x1]` into named `discount1/discount2/discount3` (u8 each) - verified via shop_initBody's `item[5] = item[randomGetRange(0,2)+1]` discount-pick logic to be exactly the wiki's D1/D2/D3 columns.
- Once shop_buyItem's gameBitIncrement targets (0x66c, 0x86a, 0xc1, 0x13d, 0x5d6, 0x3f5) are traced to a real consumer, add them to include/main/gamebits.h as GAMEBIT_ITEM_{BombSpore,MoonSeed,GrubTubFungus,Firefly x2,FuelCell}_Count (or similar) alongside the already-present *_Got/_Bought entries - table above gives the candidate names/rows for free.

### Textures
- Promote the file-local ObjModelRenderOp (objprint_dolphin.c) / MapShader+TexLayer (tex_dolphin.c) / raw def-byte arithmetic (model.c, rcp_dolphin.c) into one canonical `Shader`/`ShaderLayer` pair in include/main/model.h, per the Ready-to-adopt draft in the doc.
- Add a `ShaderFlags` set of #defines for Shader.flags@0x3C (confirmed bits: HIDDEN=0x2, ALPHA_COMPARE=0x400, STREAMING_VIDEO=0x20000, UNLIT=0x80000, and this repo's own new evidence for 0x40000000 = "force blend") replacing bare hex literals in tex_dolphin.c/objprint_dolphin.c.
- Add SHADER_ATTR_* bit defines for the byte at Shader offset 0x40 (objprint_dolphin.c currently just comments '0x10 = additive path' inline).
- Rename Texture.tmemAddr (include/main/texture.h) to texRegion (type GXTexRegion*) — every use already passes it as GXTexObj's texRegion arg, so the wiki's name is more accurate than the current one.
- Investigate/resolve the Texture+0x50 field naming conflict: this repo's imageOffset (backed by a real GXInitTexObj pointer-arith use in rcp_dolphin.c:1503) vs. the wiki's tevVal50 guess — worth a comment reconciling or refuting one of the two.
- Add named TexScroll table-entry struct for shader.c's lbl_803DCE68 (0x3a-slot, 0x10-stride scroll-matrix table) matching the wiki's Scrolling section, replacing raw pointer arithmetic in mapTextureScrollAcquire/mapTextureScrollSetStep.

### Tricky
- enum TrickyAbilityBit {TRICKY_ABILITY_CALL=0x01, TRICKY_ABILITY_FIND_SECRET=0x02, TRICKY_ABILITY_STAY=0x08, TRICKY_ABILITY_FLAME=0x10, TRICKY_ABILITY_THROW_BALL=0x20} to replace the raw hex literals in Tricky_getAvailableCommands (dll_00C4_tricky.c)
- Name the TrickyState 0x748..0x798 queued-command array fields (targetObj/commandKind/commandType/status, stride 8, count unk798, cap 10 = MAX_COMM_PRESENT) instead of leaving pad744 opaque
- Consider fixing/annotating the 325767.0f vs 32767.0f literal in ObjSeq_func20 (src/main/maketex.c:1216) as a known retail typo rather than leaving it unexplained

### UnusedThings
- enum SaveSelectPanelId in dll_0035_saveselectscreen.c replacing the 5 SAVE_SELECT_PANEL_* #defines (CHOOSE_SLOT/OPEN_FILE/SLOT_ACTION/CONFIRM_ERASE/CHAPTER_SELECT) - single-file scope, low risk
- FuelcellSetup.offBit/onBit (dll_0123_fuelcell.c) are already named fields - no change needed, but worth noting as the concrete field pair responsible for the wiki's reported fuel-cell GameBit-collision bugs if that object is revisited
- No new enum/struct is warranted for LACTIONS/SCREENS/DLLS/VOXOBJ - Files.md's existing enum MldfFileId and DLLs.md's SFA_DLL_UNUSED_IDS already cover those id spaces

### Warptab
- Rename WarpDestination.angle0/angle1 (src/main/rcp_dolphin.c) to layer/angle - traced via loadNextMap -> SaveGameCharacterPosition.map/.angle, confirms angle0==wiki Ly, angle1==wiki Ang; pure rename, no layout change
- Add a project-wide WarpTabId enum (only for the ~20 ids this repo's code already names/switches on: 0x00,0x02,0x0F,0x12,0x1A,0x20,0x22,0x32,0x33,0x4E,0x50,0x60,0x63,0x6C,0x73,0x77,0x78,0x79,0x7C,0x7E,0x7F) to replace scattered raw hex literals and per-file #defines like LINKA_LEVCONTROL_WARP_ID_* and DUMMY39_WARP_MAP
- Fix the misleading 'two orientation s16s' doc comment above WarpDestination in rcp_dolphin.c now that angle0 is confirmed to be the map layer, not an orientation

*Total: 91 proposed incorporations across 21 pages.*
