# ObjectFileStruct (`OBJECTS.bin`)

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/ObjectFileStruct). Reverse-engineering notes; not independently verified here.

This is the structure of entries in `OBJECTS.bin`. `OBJECTS.tab` gives the offset of the
beginning of each entry. Many fields are guessed/unknown. The official name of this type
appears to be `objdata`.

Offsets are relative to the beginning of the structure and will be converted to pointers
when the object is loaded.

Offset|Type|Name|Description
------|----|----|-----------
0x00|float||copied to shadow field 0
0x04|float|scale|
0x08|u32\*|pModelList|-> list of model IDs
0x0c|pointer|textures|
0x10|pointer||indexed by model idx
0x14|pointer||
0x18|ObjSeq\*|offset_0x18|[OPTIONAL] Scripting/Triggers
0x1c|u16\*|pSeq|[OPTIONAL] -> seq IDs
0x20|pointer|pEvent|[OPTIONAL] offset into the file; changed to pointer on load
0x24|pointer|pHits|[OPTIONAL]
0x28|ObjectFileStructWeaponData\*|pWeaponDa|[OPTIONAL]
0x2c|AttachPoint\*|attachPoints|
0x30|short\*|pModLines|ignored in file (zeroed on load)
0x34|pointer|pIntersectPoints|ignored in file (zeroed on load)
0x38|pointer|nextIntersectPoint|
0x3c|pointer|nextIntersectLine|
0x40|AButtonInteraction\*|aButtonInteraction|[OPTIONAL] count in field 0x72 -> something 0x12 or 0x18 bytes per model
0x44|ObjFileStructFlags44|flags|
0x48|ObjFileStruct_ShadowType|shadowType|
0x4a|s16|shadowTexture|
0x4c|?||
0x4d|?||
0x4e|HitboxFlags60|hitbox_flags60|
0x50|s16|dll_id|if not -1, load this DLL; func 0 is a model callback
0x52|ObjCategory|category|
0x54|?||
0x55|byte|nModels|
0x56|byte|numPlayerObjs|if > 0, `objAddObjectType(obj, 8)`
0x57|u8||never read?
0x58|u8|nAttachPoints|official name: `noplacements`
0x59|byte|nTextures|count of sth 0x10 bytes
0x5a|u8|numVecs|count of sth 0x12 bytes; crashes if reduced
0x5b|?||
0x5c|byte|modLinesSize|ignored in file
0x5d|s8|modLinesIdx|
0x5e|u8|numSeqs|
0x5f|ObjFileStructFlags5F|flags_0x5f|
0x60|byte|hitbox_fieldB0|
0x61|byte|hasHitbox|or # hitboxes, but should only be 1
0x62|byte|hitboxSizeXY|
0x63|byte|hitbox_field6A|
0x64|?|hitbox_field6B|
0x65|byte|hitboxFlags_0x65|8 = has sth 0x1C8 bytes
0x66|byte||
0x67|byte|hitbox_fieldB5|
0x68|short|hitboxSizeX1|
0x6a|word|hitboxSizeY1|> 0x169 = no shadow; also hitbox related
0x6c|short|hitboxSizeZ1|or damage type?
0x6e|short|hitboxSizeZ2|
0x70|byte|hitbox_fieldB4|related to hitbox (height?)
0x71|u8|flags_0x71|related to hitbox
0x72|byte|nFocusPoints|
0x73|byte|stateVar73|1 = translucent; 3 = invincible - not flags
0x74|?||
0x75|?||
0x76|ObjectFileStructFlags76|flags76|1 = animated
0x77|byte|hitboxSizeZ|
0x78|s16|map|crashes loudly if invalid
0x7a|?||
0x7b|?||
0x7c|GameTextId[4]|helpTexts|one per model
0x84|?||
0x86|?||
0x88|float|lagVar88|causes lag at ~65536.0; GPU hang at much more; related to shadow; maybe causing excessive map loads?
0x8c|byte|nLights|
0x8d|byte|lightIdx|
0x8e|byte|colorIdx|related to textures; 1=dark, 2=default, 3+=corrupt, 77=crash, 0=normal
0x8f|?||
0x90|byte|hitbox_flagsB6|< 0xE = invincible
0x91|char[11]|name|only used for debug print
0x9c|varies|-|additional data depending on object

## ObjFileStruct_ShadowType

Val|Description
---|-----------
0x0|None
0x1|Big box
0x2|Geometric shadow, generated from the object's model
0x3|Crash (requires some extra data?)
0x4|Blue glowing rectangle

## ObjFileStructFlags44

Value|Description
-----|-----------
0x00000001|Has models
0x00000010|Different light color
0x00000020|Related to models
0x00000040|Has children
0x00000400|Enable culling
0x00000800|Use different model loading
0x00008000|Maybe "can hold player"?
0x00080000|Different culling
0x00200000|Keep hitbox when invisible
0x00400000|Has event
0x00800000|Did load models (set at runtime)
0x01000000|Related to hit detection

## ObjFileStructFlags5F

Val|Description
---|-----------
0x01|Crazy translucent effect (meant for jellyfish?)
0x02|Shadow does not use a texture
0x04|Shadow uses depth testing
0x08|Related to matrices
0x10|No shadow; force depth test if 0x01 also set
0x20|Visible
0x80|Different textures (very dark)

## Help Texts

Four text IDs, one for each of the object's models. If the ID for the current model is not
`0xFFFF`, standing next to the object will display that text on the PDA.

## ObjectFileStructWeaponData

Offset|Type|Name|Description
------|----|----|-----------
0x00|s16|id|-1 = end
0x02|s16|offset|`WEAPONDA.bin` offset
0x04|s16|size|max 0x800

## AttachPoint

Offset|Type|Name|Description
------|----|----|-----------
0x00|vec3f|pos|Position offset from bone
0x0C|vec3s|rot|Rotation offset from bone
0x12|s8|bone|Bone index, or -1
0x13|s8|?|Always equals bone index? Changing has no effect?
0x14|s8|?|Always equals bone index? Changing has no effect?
0x15|s8|?|Always 0xCD?
0x16|s8|?|Always 0xCD?
0x17|s8|?|Always 0xCD?

These define points on the object's model that can be referenced by animations. For example,
the staff is placed at point 2 when on Fox's back, and point 0 when in his hand. The position
and rotation of the point is added to those of the bone to determine the staff's position and
rotation. The bone index can be -1; in that case, the point isn't attached to a bone, and is
offset from the model's origin instead.

## In this codebase

The runtime, pointer-fixed form of this exact struct is `ObjDef` (aliased `ObjModelInstance`)
in `include/main/objanim_internal.h` — `sizeof(ObjDef) == 0x9C`, i.e. it ends with the wiki's
11-byte debug `name` field at 0x91; anything past 0x9C ("additional data depending on object")
is not modelled. `ObjAnimComponent.modelInstance` (obj+0x50)
points at a loaded instance of it, and `loadObjectFile` (`src/main/object.c`) is the loader
that performs exactly the offset-to-pointer fixups the wiki describes:

- File names are literal in `src/main/pi_dolphin.c`: `sResourceFileNameObjectsTab` = `"OBJECTS.tab"`
  (line 8012), `sResourceFileNameObjectsBin` = `"OBJECTS.bin"` (line 8013),
  `sResourceFileNameWeapondaBin` = `"WEAPONDA.bin"` (line 8003).
- `loadObjectFile` converts `buf+0x20`, `buf+0x24`, `buf+0x28`, `buf+0x18`, `buf+0x1c`, `buf+0x40`
  from file offset to pointer **only if non-zero** (matches the wiki's `[OPTIONAL]` tags on
  `pEvent`/`pHits`/`pWeaponDa`/`offset_0x18`/`pSeq`/`aButtonInteraction`), converts `buf+8`,
  `buf+0xc`, `buf+0x10`, `buf+0x2c` **unconditionally** (matches the wiki not marking `pModelList`
  /`textures`/`attachPoints` optional), and zeroes `buf+0x30`/`buf+0x34` (matches "ignored in
  file (zeroed on load)"). It also reads `n = (s8)buf[0x5d]` (`modLinesIdx`) to drive
  `loadModLines`, matching the wiki's `modLinesIdx`/`modLinesSize` fields exactly.
- Our own `tools/orig/object_catalog.py` (independently written against the retail files, not
  from this wiki) already decodes this struct at the **same offsets**: `FIELD_SPECS` lists
  `pModelList`@0x08, `field_0x18`@0x18, `pSeq`@0x1C, `pEvent`@0x20, `pHits`@0x24, `pWeaponDa`@0x28,
  `hitboxes`@0x2C (the wiki's `attachPoints`), `aButtonInteraction`@0x40; `build_records` reads
  `name` from `offset+0x91 : offset+0x9C` (11 bytes), `dll_id`/`class_id` as `>Hh` at `offset+0x50`,
  `n_models`/`n_player_objs` as `>BB` at `offset+0x55`, `n_sequences` at `offset+0x5E`, `map_id` as
  `>H` at `offset+0x78`, and exactly **4** help-text `u16`s at `offset+0x7C`.

### Definition loading and ownership (2026-10-06)

The ten relocated fields now have explicit `u32 ...Offset` / typed-pointer union
views in `ObjDef`. The offsets are relative to the start of the definition, not
`OBJECTS.bin`. `loadObjectFile` returns `ObjDef*`; the cache and its callers carry
that type. The four unconditional fixups and six optional fixups above preserve
the retail behavior, including a zero unconditional offset becoming the resource
base. Foxhollow's native loader provides useful field evidence, but its conditional
attachment-point relocation is not copied into the matching loader.

A read-only audit of EN's 1,477 definitions found every nonzero offset within its
resource or exactly at its end. Empty tables commonly use the end offset: 682
texture and joint-binding tables and 875 attachment-point tables. None of the
four unconditionally relocated fields is zero in these assets. Their zero-offset
behavior is established by the retail loader, not inferred from this sample.

`modLines` and `intersectionLines` are separately allocated runtime data. In
`intersectModLineBuild`, `intersectionPoints` and `intersectionSegmentRanges`
point inside the `intersectionLines` allocation. The last cache reference frees
`modLines`, `intersectionLines`, then the definition, without freeing those views
or any relocated resource table. The former teardown incorrectly expressed the
first allocation as `GameObject.anim.parent`; it now accesses `ObjDef.modLines`.
Dinosaur Planet's `objLoadObjdef` / `objFreeObjdef` corroborate this ownership.
The refcount remains a byte, including its retail wraparound behavior, and the
cache slot remains uncleared after final release; zero refcount forces a reload.

The destructor retains one pointer local across its object-list and definition
phases because splitting those lifetimes changes MWCC's register allocation.
Likewise the signed modline selector retains an explicit byte conversion. These
source choices preserve the complete TU, not only the recovered functions.

`python3 tools/test_object_definition_lifecycle.py` exercises the production
loader and cache-release block with native pointers above 4 GiB, all 1,024
zero/nonzero offset combinations, signed selector extremes, byte refcounts,
allocation failure, end offsets and reload after release. It checks allocation
ownership with ASan/UBSan at `-O0` and `-O2`. Its I/O spy supplies a decoded host
header; it does not claim to deserialize retail bytes on a 64-bit host. All five
configured retail builds pass `all_source` and their strict source-linked DOL
checks. Complete changed TUs match; the two pre-existing library report-accounting
exceptions remain unchanged.

### Field-by-field

Offset|Wiki name|`ObjDef` field|Evidence
------|---------|--------------|--------
0x04|scale|`rootMotionScaleBase`|`src/main/object.c:1193`: `tmpl.scale = modelDef->rootMotionScaleBase;` — even the local variable is named `scale`.
0x08|pModelList|`modelFileIds` (`s32*`)|`loadCharacter` indexes the table per model and negates each ID for `ObjModel_Load`.
0x0c|textures|`textureSlotDefs` (`ObjTextureSlotDef*`)|Offset match; on-disk compact 2-byte-per-slot def (`sizeof(ObjTextureSlotDef)==2`).
0x18|offset_0x18 (`ObjSeq*`, triggers)|`extraSetupData` (`u8*`)|Offset/optionality match, but **usage disagrees with the wiki's guess** — see below.
0x1c|pSeq|`sequenceMap` (`s16*`)|Offset match, sequence-id role matches.
0x20|pEvent|`eventMoveTable` (`s16*`)|Offset match; also the field name at the same offset (0x20) in `ObjAnimDef`.
0x24|pHits|`hitReactMoveTable`|Offset match; also `ObjAnimDef.hitReactMoveTable` at the same 0x24.
0x28|pWeaponDa|`weaponDaTable` (`s16*`)|Offset match; feeds `ObjWeaponDaTable`/`WEAPONDA.bin` loading (`objGetTotalDataSize`'s `OBJLOAD_FLAG_WEAPON_DA` path).
0x2c|attachPoints|`attachPoints` (`ObjAttachPoint*`)|**Confirmed**: `loadObjectFile` fixes `buf+0x2c` from offset to pointer unconditionally; `objRenderChild` (`objprint_dolphin.c`) and `staffUpdateSegmentTransforms` (`objhits.c`) index it with stride **0x18**, matching the wiki's `AttachPoint` record exactly (`sizeof(ObjAttachPoint)==0x18`), and `attachPointCount` @0x58 bounds the indexing.
0x40|aButtonInteraction|`hitVolumes` (`ObjDefHitVolume*`)|**Confirmed**: `hitVolumeCount` lives at 0x72 exactly where the wiki says the count for this field is, and `sizeof(ObjDefHitVolume)==0x18`, matching the wiki's "0x12 or 0x18 bytes per model" guess exactly.
0x44|flags (`ObjFileStructFlags44`)|`flags` (`u32`)|Direct match. Bit 0x800000 ("Did load models, set at runtime") is confirmed live: `((ObjModelInstance*)obj->def)->flags |= 0x800000LL;` right after model loading in `loadCharacter`. Bit 0x400000 ("Has event") gates extra alloc size in `objGetTotalDataSize`. Bit 0x800 ("Use different model loading") lines up with our own `OBJDEF_FLAG_DEFERRED_RENDER` (0x800).
0x48|shadowType|`shadowType` (`s16`)|Exact name+offset match. `== 2` (geometric shadow from model) checked in `newshadows.c:997`; `== 3` (crash/needs extra data) is literally our `OBJLOAD_FLAG_SHADOW_TYPE3` (`object.c:1135,1271`); `== 1` (big box) checked at `object.c:1586`; `!= 0` (has shadow) is `OBJLOAD_FLAG_HAS_SHADOW`.
0x4a|shadowTexture|`shadowTextureId` (`s16`)|Exact match.
0x4e|hitbox_flags60|`hitboxFlags` (`s16`)|Exact offset match, and the wiki's "60" suffix is explained below — see the `ObjHitsPriorityState` cross-reference.
0x50|dll_id|**not named** (raw `*(s16*)(def+0x50)`)|**Confirmed**: `loadCharacter`: `if ((int)*(s16*)(def + 0x50) != -1) tmpl.dll = Resource_Acquire(*(s16*)(def + 0x50) & 0xffff, 6);`. This is *the* field behind every `src/main/dll/dll_XXXX_*.c` file name in the repo (729 such files under `src/main/dll/`).
0x52|category (`ObjCategory`)|**not named** (raw `*(s16*)(def+0x52)`, local var `f44` in `loadCharacter`'s `LoadedObj`)|Read as `tmpl.f44 = *(s16*)(def + 0x52);`. This is the same id our own `tools/orig/object_catalog.py`/`object_class_packets.py` call `class_id` — a large space of romlist "type" ids (hundreds, not a small enum; see e.g. `WMOBJCREATOR_SPAWN_WM_WALLCRAWLER = 0x275` in `src/dlls/objects/505_WM_ObjCreat/WM_ObjCreat.c`, or the related code in `src/dlls/objects/529/529.c`).
0x55|nModels|`modelCount` (`s8`)|Exact offset match.
0x56|numPlayerObjs|`group8RegistrationCount` (`s8`)|**Confirmed**, and better-named than the wiki's guess: `if (...->group8RegistrationCount > 0) objFreeObjectType((u32)obj, 8);` (`object.c:1580`) is the teardown mirror of the wiki's `objAddObjectType(obj, 8)`.
0x58|nAttachPoints (`noplacements`)|`attachPointCount` (`u8`)|**Confirmed**: `staffUpdateSegmentTransforms` (`objhits.c`) gates on `>= 2` and bounds its `attachPoints` walk with `k < attachPointCount`; `playerUpdateCameraTargetLookAngles` (`player.c`) gates joint look-at on `!= 0`.
0x59|nTextures|`textureSlotCount` (`u8`)|**Confirmed**: `objGetTotalDataSize`/`loadCharacter` add `textureSlotCount * sizeof(ObjTextureRuntimeSlot)`, and `sizeof(ObjTextureRuntimeSlot)==0x10` — matches the wiki's "count of sth 0x10 bytes" exactly.
0x5a|numVecs|`jointBindingCount` (`u8`)|`objGetTotalDataSize` allocates this many `ObjJointPose` records, each 0x12 bytes; the packed binding table lives at `jointBindings` (0x10).
0x5e|numSeqs|`sequenceCount` (`u8`)|Exact match.
0x5f|flags_0x5f (`ObjFileStructFlags5F`)|`renderFlags` (`u8`)|Offset match. We already have `OBJDEF_RENDERFLAG_PROJECTED_SHADOW` (0x4) and `OBJDEF_RENDERFLAG_DEFERRED_RENDER` (0x10) named, but **our semantics for these two bits differ from the wiki's** — see "Open discrepancies" below.
0x60|hitbox_fieldB0|`hitboxStateIndex` (`u8`)|**Confirmed chain**: copied via `*(s8*)&hitState->stateIndex = ... obj->modelInstance->hitboxStateIndex;` in `ObjHits_RefreshObjectState` (`src/main/objlib.c`), and `ObjHitsPriorityState.stateIndex` is at offset **0xB0** — exactly explaining the wiki's "B0" suffix.
0x61|hasHitbox|**not named** (`pad61`, isolated 1-byte gap)|**Confirmed usage**: `if (*(u8*)(def + 0x61) != 0)` gates hit-volume state allocation in `objGetTotalDataSize`/`loadCharacter` (`object.c:1439/1465/2539`).
0x62|hitboxSizeXY|`primaryHitboxRadius` (`u8`)|Offset match; copied to `hitState->primaryRadius`.
0x63|hitbox_field6A|`lateralResponseWeight` (`u8`)|**Confirmed chain**: copied to `hitState->lateralResponseWeight`, and `ObjHitsPriorityState.lateralResponseWeight` is at offset **0x6A** — exactly explaining "6A".
0x64|hitbox_field6B|`axialResponseWeight` (`u8`)|**Confirmed chain**: same as above, `ObjHitsPriorityState.axialResponseWeight` is at offset **0x6B**.
0x65|hitboxFlags_0x65|`primaryHitboxShapeFlags` (`u8`)|Copied to `hitState->shapeFlags`; bit 3 (`0x8`) gates `ObjHitbox_AllocRotatedBounds` (extra 0x110 bytes in `objGetTotalDataSize`, vs. the wiki's guessed 0x1C8 — same bit, different size guess).
0x67|hitbox_fieldB5|`targetHitMask` (`u8`)|**Confirmed chain**: `hitState->targetMask = obj->modelInstance->targetHitMask;` (`objlib.c`), and `ObjHitsPriorityState.targetMask` is at offset **0xB5**.
0x68-0x6e|hitboxSizeX1/Y1/Z1/Z2|`primaryCapsuleOffsetA/B`, `secondaryCapsuleOffsetA/B` (`s16`)|Offset match; copied verbatim into the like-named `ObjHitsPriorityState` fields.
0x70|hitbox_fieldB4|`sourceHitMask` (`u8`)|**Confirmed chain**: `hitState->sourceMask = obj->modelInstance->sourceHitMask;` (`objlib.c`), and `ObjHitsPriorityState.sourceMask` is at offset **0xB4**.
0x71|flags_0x71|`runtimeSourceHitMask` (`u8`)|Offset match.
0x72|nFocusPoints|`hitVolumeCount` (`u8`)|**Confirmed** — see 0x40 above; also feeds a second `hitVolumeCount * 5` allocation matching `sizeof(ObjHitVolumeRuntimeBounds)==5`.
0x73|stateVar73|`fixedSortDepth` (`u8`)|**Disagrees with our own code** — see "Open discrepancies" below.
0x76|flags76 (`ObjectFileStructFlags76`)|`effectFlags` (`u8`)|Offset match; bit 1 gates a fade-in-alpha sequence in `object.c:344` (plausible but not confirmed identical to the wiki's "1=animated").
0x77|hitboxSizeZ|`secondaryHitboxRadius` (`u8`)|Offset match.
0x78|map|`mapLoadObjectId` (`s16`)|Offset match; our name suggests a different reading (object id used for map loading) than the wiki's "map id" — unverified either way here.
0x7c|helpTexts (`GameTextId[4]`)|`helpTextIds` (`s16[4]`)|**Resolved**: the array was oversized at `s16[8]` and overran the f32 at 0x88; corrected to `s16[4]` with `pad84[4]`.
0x88|lagVar88|`shadowModelScaleBase` (`f32`)|**Confirmed**: `objAllocModelState` (`shadow_dolphin.c`) copies it into `ObjModelState.shadowModelScale`, which `buildShadowVolumeBox` uses as the shadow-volume scale — matching the wiki's "related to shadow".
0x8c|nLights|**not named** (`pad8C`)|Not found.
0x8d|lightIdx|`modelLightMaskIndex` (`u8`)|Offset match; name suggests a slightly different role (mask vs. index) — unverified.
0x8e|colorIdx|**not named** (`pad8E`)|Not found; `1=dark,2=default,3+=corrupt` semantics not modelled yet. Elsewhere, `loadCharacter` separately reads a related color/light byte from `def+0x8e` into a local (`tmpl.ff2`), consistent with this offset being read as a small enumerated index.
0x8f|?|`fallbackHitSphereRadius` (`u8`)|Offset match; wiki has no info here, ours has a name but no cited use found in this pass.
0x90|hitbox_flagsB6|`secondaryHitboxShapeFlags` (`u8`)|**Confirmed chain**: `hitState->secondaryShapeFlags = obj->modelInstance->secondaryHitboxShapeFlags;` (`objlib.c`), and `ObjHitsPriorityState.secondaryShapeFlags` is at offset **0xB6** — exactly explaining "B6". The wiki's "< 0xE = invincible" note is new detail not yet in our headers.
0x91|name|`name` (`char[11]`)|**Directly confirmed**: `src/main/dll/firecrawler.c:5` says the enemies there were "identified from the retail OBJECTS.bin (object name at def+0x91)", `object.c` passes it straight to `OSReport("LOADED OBJECT %s")`, and `tools/orig/object_catalog.py` reads `offset+0x91 : offset+0x9C`. `sizeof(ObjDef)` is now 0x9C.

### The `ObjHitsPriorityState` naming chain (why the wiki's "hitbox_fieldXX" names look odd)

The wiki's odd `hitbox_fieldB0`/`field6A`/`field6B`/`fieldB4`/`fieldB5`/`flagsB6` names for
several `ObjectFileStruct` bytes are not offsets within `ObjectFileStruct` itself — they are the
offsets those bytes land at once copied into a *different*, runtime hit-detection state struct.
This repo already recovered that struct as `ObjHitsPriorityState`
(`include/main/objhits_types.h`), and `ObjHits_RefreshObjectState` (`src/main/objlib.c`) is the
copy site. The offsets line up exactly:

Runtime field (`ObjHitsPriorityState`)|Offset|Wiki name for the source `ObjectFileStruct` byte
-----------------------------------|------|-----------------------------------------------
`flags`|0x60|`hitbox_flags60` (source: `ObjDef.hitboxFlags` @0x4E)
`lateralResponseWeight`|0x6A|`hitbox_field6A` (source: `ObjDef.lateralResponseWeight` @0x63)
`axialResponseWeight`|0x6B|`hitbox_field6B` (source: `ObjDef.axialResponseWeight` @0x64)
`stateIndex`|0xB0|`hitbox_fieldB0` (source: `ObjDef.hitboxStateIndex` @0x60)
`sourceMask`|0xB4|`hitbox_fieldB4` (source: `ObjDef.sourceHitMask` @0x70)
`targetMask`|0xB5|`hitbox_fieldB5` (source: `ObjDef.targetHitMask` @0x67)
`secondaryShapeFlags`|0xB6|`hitbox_flagsB6` (source: `ObjDef.secondaryHitboxShapeFlags` @0x90)

Every one of these seven pairs matches exactly, independently confirming both this repo's
`ObjHitsPriorityState` layout and the wiki's field descriptions for `ObjectFileStruct`.

### Open discrepancies (worth checking before trusting either source blindly)

- **`0x18` "offset_0x18" / `extraSetupData`**: the wiki guesses `ObjSeq*` (scripting triggers).
  But in this repo, `extraSetupData` is read by non-trigger classes for arbitrary per-class blobs
  — e.g. `src/dlls/objects/255/255.c`: `ref = (int)obj->anim.modelInstance->extraSetupData;`
  then `*(s8*)(ref + 0xb)` is used as a magic-type amount; `src/dlls/objects/237/237.c:167`
  reads it too. That's consistent with a generic "extra per-class setup data" blob whose *contents*
  vary by class (trigger objects might store an `ObjSeq` there, other classes store something
  else), rather than the field always being an `ObjSeq*`. Not a contradiction, but worth footnoting
  if a maintainer ever names this field for real.
- **`0x5f` render flags, bits `0x04`/`0x10`**: our `OBJDEF_RENDERFLAG_PROJECTED_SHADOW` (0x4) and
  `OBJDEF_RENDERFLAG_DEFERRED_RENDER` (0x10) don't obviously match the wiki's "shadow uses depth
  testing" (0x04) / "no shadow; force depth test if 0x01 also set" (0x10). Same bit positions, two
  different behavior stories — flagging for a maintainer to reconcile, not resolving here.
- **`0x73` "stateVar73"**: the wiki says `1=translucent; 3=invincible - not flags`. This repo's
  `object.c:1433-1436` reads the same byte (`cullScale = *(u8*)(obj->def + 0x73);`) as a numeric
  **cull-distance scale factor** (`if (cullScale != 0) max *= (lbl_803DE8CC * cullScale) / lbl_803DE8D0;`),
  named `fixedSortDepth` in `ObjDef`. These are two different hypotheses for the same byte —
  genuinely worth double-checking against a matched function that reads it, rather than assuming
  either is right.
- **`0x30`/`0x5c`/`0x5d` mod lines**: `loadObjectFile` stores `loadModLines()`'s buffer at `buf+0x30`,
  its record count at `buf+0x5c` (`size / 20`, and `sizeof(MapHitLine)==0x14`) and reads the
  `MODLINES.tab` index from `(s8)buf[0x5d]` — now `modLines`/`modLineCount`/`modLineIndex` in `ObjDef`.
  Note that `track_dolphin.c` declares `IntersectModLineObject`, a partial **duplicate** of this same
  `ObjDef` tail (0x30/0x34/0x38/0x3c/0x5c) that `object.c` casts to; the two should probably be one type.

## Ready-to-adopt code

None of this should be applied blindly — it's transcribed from the wiki table plus the
cross-references above, for a maintainer to fold into `include/main/objanim_internal.h` (or a new
header) after independently checking against a matched function.

```c
/* ObjectFileStruct.ObjectFileStructWeaponData - WEAPONDA.bin index entry.
   ObjDef.weaponDaTable currently declared as a bare s16*; this is its element shape. */
typedef struct ObjWeaponDaEntry {
  s16 id;     /* -1 = end of table */
  s16 offset; /* WEAPONDA.bin offset */
  s16 size;   /* max 0x800 */
} ObjWeaponDaEntry;

/* ObjectFileStruct.AttachPoint - bone-relative placement points (ObjDef+0x2C, count at
   ObjDef+0x58 per the wiki's "noplacements"). Not yet wired into ObjDef - neither the
   pointer nor the count field is named there today. */
typedef struct AttachPoint {
  f32 posX, posY, posZ;  /* offset from bone, world/model units */
  s16 rotX, rotY, rotZ;  /* offset from bone, engine angle units */
  s8  bone;              /* bone index, or -1 for model-origin-relative */
  s8  unk13;             /* wiki: "always equals bone index?" */
  s8  unk14;             /* wiki: "always equals bone index?" */
  s8  unk15;             /* wiki: "always 0xCD?" */
  s8  unk16;             /* wiki: "always 0xCD?" */
  s8  unk17;             /* wiki: "always 0xCD?" */
} AttachPoint; /* size 0x18 */

/* ObjFileStruct_ShadowType - ObjDef.shadowType (s16, @0x48). Values confirmed live in
   src/main/object.c (== 1, == 3, != 0) and src/main/newshadows.c (== 2). */
enum ObjShadowType {
  OBJ_SHADOW_TYPE_NONE = 0,
  OBJ_SHADOW_TYPE_BIG_BOX = 1,
  OBJ_SHADOW_TYPE_MODEL_GEOMETRIC = 2,
  OBJ_SHADOW_TYPE_CRASH = 3,      /* needs extra data; matches OBJLOAD_FLAG_SHADOW_TYPE3 */
  OBJ_SHADOW_TYPE_BLUE_GLOW_RECT = 4,
};

/* ObjFileStructFlags44 - ObjDef.flags (u32, @0x44). 0x800000 and (loosely) 0x800 are
   already confirmed live in this repo; the rest are transcribed from the wiki only. */
#define OBJDEF_FLAG_HAS_MODELS            0x00000001
#define OBJDEF_FLAG_DIFFERENT_LIGHT_COLOR 0x00000010
#define OBJDEF_FLAG_RELATED_TO_MODELS     0x00000020
#define OBJDEF_FLAG_HAS_CHILDREN          0x00000040
#define OBJDEF_FLAG_ENABLE_CULLING        0x00000400
/* #define OBJDEF_FLAG_DEFERRED_RENDER    0x00000800  -- already in objanim_internal.h */
#define OBJDEF_FLAG_CAN_HOLD_PLAYER       0x00008000 /* wiki: "maybe" */
#define OBJDEF_FLAG_DIFFERENT_CULLING     0x00080000
#define OBJDEF_FLAG_KEEP_HITBOX_INVISIBLE 0x00200000
#define OBJDEF_FLAG_HAS_EVENT             0x00400000 /* confirmed: objGetTotalDataSize */
#define OBJDEF_FLAG_LOADED_MODELS         0x00800000 /* confirmed: loadCharacter, runtime-set */
#define OBJDEF_FLAG_RELATED_TO_HIT_DETECT 0x01000000
```

The following are **not** proposed as adoptable `#define`s because the evidence in this repo
actively disagrees with (or hasn't confirmed) the wiki's semantics — listed here only so a
maintainer sees the wiki's guesses next to what this repo has instead:

- `ObjFileStructFlags5F` (0x5f, `ObjDef.renderFlags`): wiki lists 7 bits (translucent-effect,
  no-shadow-texture, shadow-depth-test, related-to-matrices, no-shadow, visible,
  different-textures); this repo only has `OBJDEF_RENDERFLAG_PROJECTED_SHADOW` (0x4) and
  `OBJDEF_RENDERFLAG_DEFERRED_RENDER` (0x10) named, with different stories for the same bits — see
  "Open discrepancies" above.
- `0x73` "stateVar73": wiki says `1=translucent, 3=invincible`; this repo's `fixedSortDepth` reads
  it as a numeric cull-scale factor. Don't adopt either without checking a matched call site.
- `helpTextIds[8]` at `ObjDef+0x7C`: strong (but not 100%-certain) evidence this should be
  `helpTextIds[4]` followed by explicit unknown/`lagVar88` padding through `0x8C` — see "Open
  discrepancies" above. Left as a flag, not a diff, since narrowing an array in a
  `STATIC_ASSERT`-guarded header needs a real recompile check.
