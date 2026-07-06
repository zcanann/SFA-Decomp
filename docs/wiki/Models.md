# Models

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Models). Reverse-engineering notes; not independently verified here.

Models are comprised of several structures. The game also calls them characters.

## Wrapper

The first 4 bytes of the model data tell what format it's wrapped in:

* `0x5A4C4200` ("ZLB\0"): ZLB archive
* `0xFACEFEED`: FACEFEED header
* `0xE0E0E0E0`: Uncompressed (following is size, offset — interpretation unclear upstream)

The contents within the wrapper are the same for all three types.

## Common structures

* Quaternion: `float x, y, z, w`
* vec2s: `s16 x, y`
* vec3f: `float x, y, z`
* vec3s: `s16 x, y, z`

## Header

Many fields are an offset into the model data which gets converted to a pointer on load.

| Offset | Type | Name | Note |
|---|---|---|---|
| 000000 | u8 | refCount | 0 in file, set on load |
| 000001 | ? | ? | |
| 000002 | ModelDataFlags2 | flags | u16 |
| 000004 | u16 | modelId | set on load |
| 000006 | ? | ? | |
| 000008 | dword | ? | |
| 00000c | u32 | fileSize | size of this file |
| 000010 | ? | ? | |
| 000018 | u16 | flags18 | |
| 00001a | u16 | ? | |
| 00001c | u32 | extraAmapSize | |
| 000020 | u32* | textures | -> texture IDs that get turned into pointers on load |
| 000024 | ModelDataFlags24 | flags_0x24 | |
| 000025 | byte | ? | relates to lighting |
| 000026 | ? | ? | |
| 000028 | vec3s* | vtxs | used by models whose flag_60 is set |
| 00002c | vec3s* | normals | |
| 000030 | u16* | colors | presumably 16bpp |
| 000034 | vec2s* | texCoords | |
| 000038 | Shader* | shaders | aka materials |
| 00003c | Bone* | bones | |
| 000040 | Quaternion* | boneQuats | |
| 000044 | u32[3] | ? | |
| 000050 | u32 | ? | |
| 000054 | ModelVtxGroup* | vtxGroups | |
| 000058 | HitSphere* | hitspheres | sometimes wrongly called hitboxes |
| 00005c | ? | ? | |
| 000064 | pointer | pAltIndBuf | |
| 000068 | pointer | pAnimBuf | |
| 00006c | short* | pModAnim | 0 in file; -> animation tables |
| 000070 | ushort[8] | animIdxs | related to animation - FFxx disables walk anim; last crashes if >7FFF |
| 000080 | u32 | amapTabEntry | |
| 000084 | ushort | ? | |
| 000086 | ? | ? | |
| 000087 | ? | ? | |
| 000088 | astruct_54 | ? | posFineSkinningConfig (vtxs) |
| 000098 | ? | ? | |
| 0000a4 | ObjInstance* | obj | posFineSkinningPieces; field_88.nVtxs = how many |
| 0000a8 | pointer | ? | posFineSkinningWeights |
| 0000ac | ? | ? | nrmFineSkinningConfig |
| 0000ae | word | ? | maybe #normals |
| 0000b0 | ? | ? | |
| 0000b8 | dword | ? | |
| 0000bc | ? | ? | |
| 0000c8 | pointer | bCopyNormalsOnLoad | -> sth 0x4 bytes; related to normals/textures; field AE = how many |
| 0000cc | pointer | ? | |
| 0000d0 | DisplayListPtr* | dlists | |
| 0000d4 | byte* | renderInstrs | bit-packed instruction code |
| 0000d8 | ushort | nRenderInstrs | # bytes |
| 0000da | ? | ? | |
| 0000dc | short** | ptrs_0xdc | relates to animations; crash if reduced; crazy if reduced by 2; actual ptrs never read!? |
| 0000e0 | short | ? | related to lighting, vtxs? converted to float |
| 0000e2 | ModelHeaderFlagsE2 | flagsE2 | related to textures; 2=use obj->colorIdx |
| 0000e4 | short | nVtxs | |
| 0000e6 | short | nNormals | |
| 0000e8 | short | nColors | |
| 0000ea | short | nTexCoords | |
| 0000ec | short | nAnimations | 0 in file??? |
| 0000ee | ? | ? | |
| 0000f2 | u8 | nTextures | |
| 0000f3 | u8 | nBones | # mtxs at Model->mtxs |
| 0000f4 | u8 | nVtxGroups | added to field nBones if that isn't zero |
| 0000f5 | u8 | nDlists | |
| 0000f6 | u8 | ? | |
| 0000f7 | u8 | nHitSpheres | |
| 0000f8 | u8 | nShaders | |
| 0000f9 | u8 | nPtrsDC | related to fuzz? |
| 0000fa | u8 | nTexMtxs | |
| 0000fb | u8 | ? | |

The texture IDs are not translated by TEXTABLE.bin, and are always treated as indices into TEX1. A model can have a maximum of 64 textures.

### ModelDataFlags2

Bit flags (u16):

| Val | Description |
|---|---|
| 0002 | No animations |
| 0010 | On load, make a copy of the vertices and use that |
| 0040 | Use local MODANIM.TAB |
| 0400 | No depth testing |
| 2000 | Enable alpha Z update |
| 8000 | Changes how some pointers are interpreted |

### ModelDataFlags24

Bit flags (u8):

| Val | Description |
|---|---|
| 02 | makes everything very bright |
| 08 | use 9 normals instead of 3 |

### ModelVtxGroup

| Offset | Type | Name | Description |
|---|---|---|---|
| 000000 | u8 | bone0 | bone index |
| 000001 | u8 | bone1 | |
| 000002 | u8 | weight | used as low byte of a float? bone1 weight is 1 - this |
| 000003 | u8 | ? | padding? |

noclip calls this CoarseBlend and says there should be two weights.

### HitSphere

| Offset | Type | Name | Description |
|---|---|---|---|
| 000000 | short | bone | Bone index to place this sphere at |
| 000000 | short | ? | Always 0? (offset likely 0x02; wiki table as-published shows both rows at 0x00) |
| 000004 | float | radius | Sphere radius |
| 000008 | vec3f | pos | Position offset from bone |
| 000014 | short | ? | Always 0? |
| 000016 | s8 | ? | Always equals the sphere's index in the list? |
| 000017 | s8 | ? | Same as 0x16? |

### astruct_54

| Offset | Type | Name | Description |
|---|---|---|---|
| 000000 | ? | ? | |
| 000002 | ushort | nVtxs | |
| 000004 | ? | ? | |
| 00000c | int | vtxOffs_0xc | |

### DisplayListPtr

| Offset | Type | Name | Description |
|---|---|---|---|
| 000000 | u32 | offset | pointer to display list |
| 000004 | u16 | size | number of bytes |
| 000006 | vec3s[2] | bbox | bounding box |
| 000012 | u16 | shader | shader index |
| 000014 | u16 | ? | offset relating to shader |
| 000016 | u16 | ? | offset |
| 000018 | u32 | ? | always 07 00 00 00 (N64 RSP segment leftover?) |

* only `offset` and `size` seem to be actually used
* shader index is redundant, since render instructions select a shader
* field 0x14 is zero if the shader index is zero
* field 0x16 increases with each list — if shader != 0, the two offsets both increase, as if whatever data they're referring to is interleaved (unknown what/where)

## Render Instructions

Each model's render data is a simple binary "script" packed into fields of various bit widths.

The first 4 bits are an opcode:

* 0: Unused, should function the same as 4
* 1: Select texture and shader — next 6 bits are the index (same for both texture and shader)
* 2: Call display list — next 8 bits are the index
* 3: Set vertex descriptors
    * 1 bit: Vertex position size (8/16 bits)
    * 1 bit (only if normals used): Normal size (8/16 bits)
    * 1 bit (only if colors used): COL0 size (8/16 bits)
    * 1 bit: TEXn size (8/16 bits; single bit for all n=0 to 7) — GameCube allows up to 8 cached textures (color, bump map, lighting, ...); not necessarily TEX0.bin/TEX1.bin
    * Character models use VAT 5; map blocks use VAT 6
* 4: renderOpMatrix (name from debug messages)
    * Next 4 bits are the number of matrices (game errors if > 20, impossible with only 4 bits)
    * 8 bits per matrix: the index (`model->mtxs`)
    * each matrix is initialized in some manner involving the camera matrix
    * "skipped by SFA block renderer" — the map block renderer handles this differently, looks like 64 bits/matrix (needs investigation)
* 5: End of script

## Bone

### Data structure

| Offset | Type | Name | Description |
|---|---|---|---|
| 000000 | s8 | parent | Parent bone index, -1 = none |
| 000001 | byte[3] | idx | Matrix idxs to write? High bit is a flag |
| 000004 | vec3f | head | aka translation |
| 000010 | vec3f | tail | aka bindTranslation |

The wiki states the tail doesn't appear to have any function in-game (see "In this codebase" below — this repo's matched code disagrees).

Krystal's bone tree is given in the source wiki page as a worked example (root at index 0, spine/clavicle/arm/leg/tail/ear/jaw/loincloth chains hanging off it); see the source link above for the full table. Fox's model has the same structure, with the loincloth bones unused or fine-tuning torso animation and the breast bone fine-tuning chest motion.

## In this codebase

All offsets below were cross-checked against `include/main/model.h` (`ModelFileHeader`, offsets confirmed with the `python` offset walk + existing `STATIC_ASSERT`s) and against field usage in `src/main/model.c` / `src/main/objprint_dolphin.c` / `src/main/objhits.c`. Where two independently-matched source files describe overlapping bytes of the same on-disk struct, both are listed.

**Wrapper.** `src/main/pi_dolphin.c` has `struct ZlbHeader` (`tag[4]` = `"ZLB"`/`"DIR"`, matching the wiki's `0x5A4C4200`) and `struct PackHeader` (`magic` = `0xFACEFEED` zlb-packed / `0xE0E0E0E0` stored raw — the exact two other wrapper values the wiki lists), used for romlist/`MAPS.BIN` sections. Field layout and magic values match the wiki's wrapper description exactly; not confirmed here as the precise code path for `.model`-specific loads, but almost certainly the same generic mechanism.

**Header → `ModelFileHeader` (`include/main/model.h`).** The struct is an offset-for-offset match with the wiki's Header table for every field either side has named:

| Wiki offset/name | Our field | Confidence |
|---|---|---|
| 0x00 refCount | `refCount` | exact |
| 0x02 flags (ModelDataFlags2) | `flags` (u16) | exact offset; see flag note below |
| 0x04 modelId | inside `unk04[8]`, but called out by name in an inline comment: `model.c:458` `*(u16*)((u8*)model+0x4) = id; /* modelId (in unk04) */` and `model.c:1160` | exact, already named in comments |
| 0x0c fileSize | `dataSize` ("anim data appended at header + dataSize") | exact offset, plausible semantics |
| 0x18 flags18 (+0x1a) | `unk18` (u8*, 4 bytes covering both u16 sub-fields) | offset match, not split out |
| 0x1c extraAmapSize | `unk1C` | offset match |
| 0x20 textures | `textureIds` | exact (`STATIC_ASSERT(offsetof(ModelFileHeader, textureIds) == 0x20)`) |
| 0x24 ModelDataFlags24 | `flags24` | exact |
| 0x28 vtxs | `vertices` | exact |
| 0x2c normals | `normals` | exact |
| 0x30 colors | `unk30` | offset match |
| 0x34 texCoords | `unk34` | offset match; confirmed used as a texcoord-presence check (`objprint_dolphin.c:1571`, gates `GX_VA_TEX0/1MTXIDX` setup) |
| 0x38 shaders (materials) | `renderOps` | **name mismatch, strong behavioral match**: `renderOps + i*0x44` is passed straight to `shaderInit()` (`model.c:590`), and the count field at 0xf8 (`renderOpCount`) lines up with the wiki's `nShaders` at the same offset — this repo's "renderOps" is the wiki's "Shader\*"/materials array |
| 0x3c bones | `jointData` | exact; also independently reconstructed in `include/main/objhits.h` as `ObjHitsModelFileHeader.joints` at the same offset (`STATIC_ASSERT(... == 0x3C)`) |
| 0x40 boneQuats | `unk40` | offset match, not yet confirmed by usage |
| 0x54 vtxGroups | `unk54` | offset match; only seen relocated (`model.c:362`), not otherwise exercised in reviewed code |
| 0x58 hitspheres | `unk58` in `model.h`; independently reconstructed as `ObjHitsModelFileHeader.hitVolumes` (`ObjHitsModelHitVolume*`) in `objhits.h` | exact offset, cross-file confirmation (see HitSphere section) |
| 0x64 pAltIndBuf | `animationModelPtrs` | offset match, name differs |
| 0x68 pAnimBuf | `animationDataSection` | offset match, semantically consistent |
| 0x6c pModAnim | `animationHeaderBuffer` ("per-joint s16 table") | offset match |
| 0x70 animIdxs (ushort[8]) | `unk70[0x10]` | exact size match (16 bytes) |
| 0x80 amapTabEntry | `animationDataFileOffset` | offset match |
| 0xae "word ? maybe #normals" | `blendAnimCount` (u16) | offset match — and see the 0xc8 pairing below |
| 0xc8 bCopyNormalsOnLoad, "field AE = how many" | `blendAnimEntries` (`STATIC_ASSERT(... == 0xC8)`) | **the wiki's own cross-reference ("field AE = how many") matches this repo's independent pairing of `blendAnimCount`@0xAE with `blendAnimEntries`@0xC8** — strong confirmation the two efforts found the same count/pointer relationship, even though the semantic name differs (wiki guesses normals-copy-on-load; we call it a blend-anim table) |
| 0xcc "pointer ?" | `blendAnimBase` | offset match |
| 0xd0 dlists | `displayLists` | exact; `GXCallDisplayList(*(void**)dl, *(u16*)(dl+4))` (`objprint_dolphin.c:1878` etc.) reads only `offset`(0x00)+`size`(0x04) — matches the wiki's "only offset and size seem to be actually used" note precisely |
| 0xd4 renderInstrs | `instrs` | exact; see Render Instructions section below |
| 0xd8 nRenderInstrs (# bytes) | `unkD8[4]`, used as `*(u16*)(m+0xd8) << 3` (bit length) | matches "# bytes" (× 8 = bits) |
| 0xdc ptrs_0xdc | `morphTargetPtrs` | offset match; **semantic disagreement** — wiki says the pointers are "never read"; this repo's code actively indexes `morphTargetPtrs[]` by `ObjModelBlendChannel.morphTargetA/B` (`model.c:945,953`) to fetch blend-shape targets. Worth a second look if reconciling. |
| 0xe0 "short ?, lighting/vtxs" | `cullDistance` | offset match only; name here is a guess, not confirmed by usage in the reviewed code |
| 0xe2 flagsE2, "2=use obj->colorIdx" | `shaderFlags` | **confirmed**: `objprint_dolphin.c:1791` — `if (((ModelFileHeader*)m)->shaderFlags & 2)` reads `gObjOverrideColor`/`gObjOverrideColorPending`, i.e. an object color override, matching the wiki's note exactly |
| 0xe4 nVtxs | `vertexCount` | exact |
| 0xe6 nNormals | `normalCount` | exact |
| 0xec nAnimations, "0 in file???" | `animationCount` ("nonzero = per-joint matrix buffers") | exact offset, refines the wiki's unclear note |
| 0xf2 nTextures | `textureCount` | exact |
| 0xf3 nBones, "# mtxs at Model->mtxs" | `jointCount` | exact; also `ObjHitsModelFileHeader.jointCount` in `objhits.h` at the same offset |
| 0xf4 nVtxGroups, "added to nBones if nonzero" | `extraJointCount` | **confirmed behaviorally**: `modelGetBoneMtx` (`model.c:2610`) computes `lim = jointCount + extraJointCount` when `jointCount != 0` — exactly the wiki's described rule |
| 0xf5 nDlists | unnamed (`unkF5` in the field list, not in the current header's named members) | **confirmed**: `model.c:415` relocation loop bound is `unkF5 + shadowDisplayListCount`, and `objprint_dolphin.c:2135` uses `unkF5` as the index *base* for the second display-list group — i.e. `unkF5` is the primary/first-group display-list count, matching the wiki's `nDlists` |
| 0xf6 "?" | `shadowDisplayListCount` ("count of the 2nd display-list group (shadow)") | this repo resolves what the wiki left unknown at 0xf6 |
| 0xf7 nHitSpheres | `ObjHitsModelFileHeader.hitVolumeCount` in `objhits.h` (`STATIC_ASSERT(... == 0xF7)`) | exact, cross-file confirmation |
| 0xf8 nShaders | `renderOpCount` | exact, consistent with the `renderOps`/`shaderInit` match above |
| 0xf9 nPtrsDC | `morphTargetCount` | offset match; paired with `morphTargetPtrs`@0xdc same as the wiki pairs `nPtrsDC` with `ptrs_0xdc` |
| 0xfa nTexMtxs | not a named field in `ModelFileHeader`, but **confirmed by usage**: `objprint_dolphin.c:1583` loops `for (i = 0; i < hdr[0xfa]; i++)` while setting up `GX_VA_TEXnMTXIDX` descriptors — this is exactly a texture-matrix count | ready to name (see below) |

**ModelDataFlags2 bits.** Two of the six wiki bits have named `#define`s in `include/main/model.h`: `MODEL_FLAG_DYNAMIC_VERTEX_BUFFERS` (0x10) and `MODEL_FLAG_VERTEX_ANIM_AREA` (0x40). The wiki's interpretation of these bits ("copy vertices on load" / "use local MODANIM.TAB") differs from this repo's current comments; usage in `model.c` (toggling around vertex-anim-area setup, `model.c:460-2179`) is consistent with "there is a second vertex-anim data area selected by this bit" but doesn't clearly confirm either exact wording. Treat both as plausible, not settled.

**ModelDataFlags24.** `MODEL_FLAGS24_NORMALS_9BYTE` (0x8) in `include/main/model.h` matches the wiki's "08 = use 9 normals instead of 3" exactly, including the bit value.

**Bone.** No named `Bone`/`ModelBone` struct exists yet in this repo — `jointData` is walked as a raw `u8*` with a hardcoded `0x1c`-byte stride (`model.c`: `modelInitBoneMtxs`, `modelInitBoneMtxs2`, `modelGetBoneMtx`'s callers). That stride matches the wiki's implied Bone size (`parent`(1) + `idx[3]`(3) + `head`(12) + `tail`(12) = 0x1c) exactly. Two additional confirmations:
  - `bone + 0x10` (the wiki's `tail`) is read and negated into `PSMTXTrans` as the bone's rest-pose translation for skinning (`model.c:2644-2649`) — **this contradicts the wiki's claim that tail "doesn't appear to have any function in-game"**; in this repo's matched code it's the inverse bind-pose translation used every frame.
  - `bone + 0x02` (the wiki's `idx[1]`) is written from a per-joint animation type-tag byte in `model.c:1411` (`*(u8*)(i + jointData + jointOff + 2) = *jointTypeSrc;`, `jointOff` stepping by `0x1c`) — consistent with the wiki's "matrix idxs to write".
  - `ObjHitsModelJointInfo` (`include/main/objhits.h`) independently reconstructs `s8 parentJoint` at offset 0 of a `0x1c`-stride array (`STATIC_ASSERT(sizeof(ObjHitsModelJointInfo) == 0x1C)`) — matches the wiki's `parent` field at the same offset and stride.

**HitSphere → `ObjHitsModelHitVolume` (`include/main/objhits.h`).** Total size matches exactly (`0x18` both sides). The back half matches closely: `linkedSpheres` (u16 @0x14), `sphereIndex` (s8 @0x16), `maskBit` (s8 @0x17) line up offset-for-offset with the wiki's "always 0?" (0x14), "always equals sphere's index in the list" (0x16), and "same as 0x16" (0x17) fields — and `objhits.c:2270` (`if (i == hitVolume->sphereIndex)`) literally confirms "always equals the sphere's index in the list". `linkedSpheres` turns out to be a nibble-packed chain of linked hit-volume indices (`objhits.c:2273` onward), not just "always 0" — it's 0 in the common (unlinked) case, matching the wiki's small sample. The front of the struct is less certain: this repo names `radius`/`x`/`y`/`z` at offsets 0x00-0x0f (no separate "bone" field), where the wiki proposes `bone`(short@0x00)/`?`(short@0x02) before `radius`(float@0x04)/`pos`(vec3f@0x08). The reviewed code paths in `objhits.c` don't clearly exercise `radius`/`x`/`y`/`z` by name, so this discrepancy is unresolved — flagging it rather than asserting either layout is wrong.

**Render Instructions → `instrs`.** `src/main/objprint_dolphin.c` (around line 862) has an explicit comment reconstructing the exact same bit-packed opcode grammar as the wiki, independently, from the retail asm:
```
1 = bind render op: 6-bit renderOps index (shader state setup)
2 = draw: 8-bit display-list index -> GXCallDisplayList
3 = vertex descriptor block: 1-bit pos/nrm/clr/tex size selectors
4 = load matrices: 4-bit count, then 8-bit joint-matrix indices
5 = end of stream
```
This matches the wiki's opcode table op-for-op (opcode 1 = select texture/shader with a 6-bit index, opcode 2 = call display list with an 8-bit index, opcode 3 = vertex descriptors, opcode 4 = `renderOpMatrix` with a 4-bit count + 8-bit indices, opcode 5 = end of script). The bit-cursor implementation is `MtxBitStream` (`data` + `pos`), walked by `modelLoadMtxsToGx` (opcode 4), `ModelHeader_setupPosTexFmt` (opcode 3), and the display-list/shader dispatch in `modelDoRenderInstrs`/`modelDoAltRenderInstrs`. Opcode 0 (wiki: "unused, same as 4") wasn't specifically checked here.

**DisplayListPtr → `displayLists`.** `0x1c`-byte stride (`model.c:42`: `displayLists + displayListIndex * 0x1c`) matches the wiki's implied `DisplayListPtr` size. `GXCallDisplayList(*(void**)dl, *(u16*)(dl + 4))` (`objprint_dolphin.c:1878`, `:2136`, `:2560`) reads exactly `offset`(0x00) and `size`(0x04) and nothing else in every call site checked — confirms the wiki's "only offset and size seem to be actually used".

**Shader/materials → `renderOps` / `ObjModelRenderOp`.** `src/main/objprint_dolphin.c` has a partial `ObjModelRenderOp` struct (`textureId`@0x18, `unk1C`, `unk24`, `envTextureId`@0x34, `flags`@0x3c) for the `0x44`-byte records the wiki calls `Shader`/materials. Not a full field-for-field reconstruction, but the same array, same per-entry stride, same role (bound by render-instruction opcode 1).

**ModelVtxGroup.** Present at the correct header offset (`unk54`) but not deeply exercised in the code paths reviewed here — no bone0/bone1/weight field usage found (`not found`).

**astruct_54 / fine-skinning region (wiki 0x88-0xc8).** This repo's independent reconstruction of the same byte range names it as vertex/blend animation tables (`vertexAnimCount`, `vertexAnimEntriesRaw`, `vertexAnimEntries`, `vertexAnimBase`, `blendAnimCount`, `blendAnimEntriesRaw`, `blendAnimEntries`, `blendAnimBase`) rather than the wiki's "fine skinning config/pieces/weights" theory. Both describe animated-vertex-blending machinery in the same region; the two interpretations haven't been reconciled field-by-field here.

## Ready-to-adopt code

Nothing here is applied to any header — for a maintainer to lift into `include/main/model.h` if desired.

```c
/* ModelFileHeader.flags (ModelDataFlags2) bits not yet named in model.h */
#define MODEL_FLAG_NO_ANIMATIONS       0x0002
/* 0x0010 = MODEL_FLAG_DYNAMIC_VERTEX_BUFFERS (already defined) */
/* 0x0040 = MODEL_FLAG_VERTEX_ANIM_AREA (already defined) */
#define MODEL_FLAG_NO_DEPTH_TEST       0x0400
#define MODEL_FLAG_ALPHA_Z_UPDATE      0x2000
#define MODEL_FLAG_ALT_POINTER_LAYOUT  0x8000

/* ModelFileHeader.flags24 (ModelDataFlags24) — 0x8 already defined as
 * MODEL_FLAGS24_NORMALS_9BYTE */
#define MODEL_FLAGS24_VERY_BRIGHT      0x02

/* ModelFileHeader.shaderFlags (wiki: ModelHeaderFlagsE2) — bit 2 confirmed
 * by objprint_dolphin.c:1791 (gObjOverrideColor path) */
#define MODEL_SHADERFLAGS_USE_OBJ_COLOR 0x0002

/* render-instruction stream opcodes (ModelFileHeader.instrs), 4-bit fields;
 * matches the comment already in objprint_dolphin.c almost verbatim */
enum ModelRenderInstrOpcode {
    MODEL_RENDEROP_MATRIX_ALT   = 0, /* unused; same handling as opcode 4 */
    MODEL_RENDEROP_BIND_SHADER  = 1, /* 6-bit renderOps/texture index */
    MODEL_RENDEROP_DRAW_DLIST   = 2, /* 8-bit display list index */
    MODEL_RENDEROP_SET_VTX_DESC = 3, /* 1-bit pos/nrm/clr/tex size selectors */
    MODEL_RENDEROP_LOAD_MATRIX  = 4, /* 4-bit count + 8-bit joint indices */
    MODEL_RENDEROP_END          = 5,
};

/* hdr[0xfa]: confirmed as a texture-matrix count by objprint_dolphin.c:1583 */
/* would slot into ModelFileHeader as: */
/* u8 texMtxCount;  offsetof == 0xFA */
```
