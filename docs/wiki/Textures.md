# Textures

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Textures). Reverse-engineering notes; not independently verified here.

Texture graphics are stored in three sets of files:

* `/mapname/TEX0.bin`, `/mapname/TEX0.tab` (mostly environment textures)
* `/mapname/TEX1.bin`, `/mapname/TEX1.tab` (mostly character/object textures)
* `/TEXPRE.bin`, `/TEXPRE.tab` (a sort of "TEX2" shared by all maps)

`TEX0` and `TEX1` appear in the disc root as well, but aren't used.

Each `.tab` file is a table describing where to find each texture in the corresponding `.bin` file.

## TEXn.tab

The table contains one `u32` per texture ID, a bitfield: `??CCCCCC OOOOOOOO OOOOOOOO OOOOOOOO`

* `?` = unknown, but used — probably similar to other table files.
  * For textures that are present, this value is 2 (the entry's highest bit is set).
  * For textures that aren't present, the value is 0 (the entire entry is `0x01000000`).
  * For most tables these two bits select which of two currently-loaded tables to read from, but
    the wiki doesn't believe this is ever actually exercised.
* `C` = Count — the number of animation frames this texture has.
* `O` = Offset, divided by 2.

An entry of `0xFFFFFFFF` marks the end of the list, followed by padding, a checksum (ignored by the
final retail build), and more padding to a multiple of 32 bytes. The checksum is the sum of every
byte before the `0xFFFFFFFF` terminator. The write order is: write all offsets, sum the bytes so far,
write the terminator, pad to 32 bytes, write the checksum, pad again. The old `default.dol` validates
by starting at the first word after the terminator and reading until a nonzero word.

## TEXn.bin

Stores the actual texture graphics.

* If `Count > 1`: at `Offset * 2` are `Count + 1` 32-bit integers, each an offset (added to
  `Offset * 2`) of a ZLB archive containing one animation frame.
* Otherwise, at `Offset * 2` is a single ZLB archive containing the one frame.

The ZLB archive contains a texture with a 0x60-byte header followed by pixel data (format given in
the header). The game accepts a `DIR\0` signature instead of ZLB (uncompressed) in some cases, but
only for `TEX1.bin`, and only once the whole file has already been loaded.

### Header

| Offs | F | Type | Name | Description |
|------|---|------|------|-------------|
| 0000 | X | Texture* | next | |
| 0004 | X | u32 | flags | |
| 0008 | X | s16 | xOffset | |
| 000A | | u16 | width | |
| 000C | | u16 | height | |
| 000E | | s16 | usage | reference count (1 in file) |
| 0010 | | s16 | frameVal10 | Low byte always 0 in file; overridden(?) on load; relates to number of frames |
| 0012 | X | s16 | - | always 0, never accessed |
| 0014 | | u16 | framesPerTick | how many frames to advance each tick |
| 0016 | | u8 | format | GXTexFmt |
| 0017 | | u8 | wrapS | |
| 0018 | | u8 | wrapT | |
| 0019 | | u8 | minFilter | |
| 001A | | u8 | magFilter | Always 1, but doesn't necessarily have to be |
| 001B | X | u8 | - | always 0, never accessed |
| 001C | | u8 | minLod | Minimum LOD value; bias is fixed at -2 |
| 001D | | u8 | maxLod | Maximum LOD value; LOD is not used if maxLod <= minLod |
| 001E | | u8 | unk1E | Padding? Always 0 or 255, never accessed |
| 001F | X | u8 | - | padding |
| 0020 | X | GXTexObj | texObj | All fields zero in file |
| 0040 | X | GXTexRegion* | texRegion | |
| 0044 | X | s32 | bufSize | raw image data size |
| 0048 | X | bool | bNoTexRegionCallback | use gxSetTexImage0 instead of gxCallTexRegionCallback |
| 0049 | X | bool | bDoNotFree | maybe u8 memory region (N64 had multiple regions) |
| 004A | X | s8 | unk4A | never accessed |
| 004B | X | s8 | unk4B | set to 10 when freeing, otherwise never accessed (memory region?) |
| 004C | X | u32 | bufSize2 | same as bufSize; seems to be "allocated size"; set but never read? |
| 0050 | | u32 | tevVal50 | 0:use 1 TEV stage, not 2 (maybe bHasTwoTevStages?) |
| 0054 | X | u32[3] | unk54 | most likely padding |

Fields marked `X` are always zero in the texture files but could have other values for
runtime-generated textures. `GXTexObj` and `GXTexFmt` are GameCube SDK types:

`GXTexObj` (0x20 bytes):

| Offs | Type | Name | Description |
|------|------|------|-------------|
| 0000 | u32 | mode0 | written to TX_SETMODE0 |
| 0004 | u32 | mode1 | written to TX_SETMODE1 |
| 0008 | u32 | image0 | written to TX_SETIMAGE0 |
| 000C | u32 | image3 | written to TX_SETIMAGE1 |
| 0010 | void* | userData | game stores the Texture* here |
| 0014 | GXTexFmt | format | |
| 0018 | u32 | tlutName | |
| 001C | u16 | loadCnt | |
| 001E | u8 | loadFmt | 0=CMPR 1=4bpp 2=8bpp 3=32bpp |
| 001F | u8 | flags | 1:mipmap; 2:isRGB |

`GXTexFmt`:

| # | Name | Description | Note |
|---|------|-------------|------|
| 00 | I4 | 4-bit intensity (monochrome) | |
| 01 | I8 | 8-bit intensity | |
| 02 | IA4 | 4-bit intensity, 4-bit alpha | |
| 03 | IA8 | 8-bit intensity, 8-bit alpha | |
| 04 | RGB565 | 16-bit RGB | |
| 05 | RGB5A3 | `0AAARRRRGGGGBBBB` or `1RRRRRGGGGGBBBBB` (alpha=max) | |
| 06 | RGBA8 | 32-bit RGBA | aka RGBA32 |
| 08 | C4 | 4-bit palette index | aka CI4 |
| 09 | C8 | 8-bit palette index | aka CI8 |
| 0A | C14X2 | 14-bit palette index, 2 bits unused | aka CI14X2 |
| 0E | CMPR | DXT1 compression | aka BC1 |

(Other formats are defined by the SDK but aren't valid for texture assets.)

Many textures are stored "upside down" for no apparent reason; they appear this way in-game too and
are flipped by the geometry.

## Texture IDs

Most texture IDs are stored as `u32` and converted to pointers at runtime. The ID is translated:

- `if(id < 0) id = -id; else id = TEXTABLE[id]`
  - file `TEXTABLE.bin` is an array of `u16` IDs
  - if the original ID was < 3000 or the new ID is 0, add 1 to the new ID
  - some entries map to `0xFFFF`, indicating a deleted texture ID
- `if(id & 0x8000)` then `id & 0x7FFF` is an index into `TEX1.tab`
- else, `if(id >= 3000)` then `id` (not `id - 3000`) is an index into `TEXPRE.tab`
- else, `id` is an index into `TEX0.tab`

## TEXPRE

Similar to the other texture files, and contains many textures that also appear in those files. The
first entry is strange: the table lists an offset of 0, and at that offset is a `DIRn` header giving
a length of 128 bytes — but unpacking it produces a ZLB archive containing a *copy of the placeholder
texture* rather than the texture itself. This is the only instance of such doubly-packed textures.

# Shaders

Models refer to shader IDs which refer to texture IDs. (The wiki author previously called these
"materials" — arguably a better name, since "Shader" has other meanings in 3D graphics.)

| Offs | Type | Name | Description |
|------|------|------|-------------|
| 0000 | s8 | ? | |
| 0001 | s8 | ? | |
| 0002 | s8 | ? | |
| 0003 | s8 | ? | |
| 0004 | u8 | r | Color used somewhere |
| 0005 | u8 | g | |
| 0006 | u8 | b | |
| 0007 | u8 | ? | |
| 0008 | s32 | auxTex0 | Texture index, unsure of use |
| 000C | u8 | alpha | Related to color above, unsure of use |
| 000D..0013 | ? | ? | |
| 0014 | s32 | auxTex1 | |
| 0018 | s32 | texture18 | |
| 001C | s32 | ? | -1 -> 0, -2 -> 0, else -> 1; relates to alpha22 |
| 0020 | s8 | colorIdx | index into a global shader texture array |
| 0021 | ? | ? | |
| 0022 | u8 | alpha22 | |
| 0023 | ? | ? | |
| 0024 | ShaderLayer[2] | layer | |
| 0034 | s32 | auxTex2 | |
| 0038 | s32 | furTexture | |
| 003C | u32 | flags | Controls various effects (ShaderFlags) |
| 0040 | u8 | attrFlags | Presence of various attributes in display lists |
| 0041 | u8 | nLayers | Max of 2 |
| 0042 | u16 | - | Padding |

Textures here are not IDs; they're indices into the model's own texture list (or -1 for none). They
are replaced with pointers to the texture when the shader is loaded — this also applies to
`ShaderLayer`.

## ShaderLayer

| Offs | Type | Name | Description |
|------|------|------|-------------|
| 0000 | s32 | texture | Index into model's texture list |
| 0004 | u8 | tevMode | Directly(?) written to TEV control |
| 0005 | u8 | polyGroupId | "enableTexChainStuff" — unknown |
| 0006 | u8 | scrollingTexMtx | idx into `trk_texscroll` |
| 0007 | ? | | Probably padding |

## ShaderFlags

| Value | Name | Note |
|-------|------|------|
| 0000 0001 | ? | Related to 0x1000 |
| 0000 0002 | Hidden | Used for normally-invisible geometry, exploded walls, etc. |
| 0000 0004 | Fog | Fog can appear in front of it |
| 0000 0008 | CullBackface | |
| 0000 0010 | ? | |
| 0000 0020 | ReflectSkyscape | |
| 0000 0040 | Caustic | Overlays a water-reflection texture |
| 0000 0080 | Lava | Glows red |
| 0000 0100 | Reflective | Overlays screen reflection texture |
| 0000 0200 | ? | |
| 0000 0400 | AlphaCompare | |
| 0000 0800 | ? | Becomes black; lights have little effect |
| 0000 1000 | ? | Same effect as above |
| 0000 2000 | ? | Only visible at certain angles |
| 0000 4000 | ShortFur | 4 layers (fur/grass effect) |
| 0000 8000 | MediumFur | 8 layers |
| 0001 0000 | LongFur | 16 layers |
| 0002 0000 | StreamingVideo | Used for displays in Great Fox |
| 0004 0000 | IndoorOutdoorBlend | Occurs near cave entrances/windows; needs special lighting handling |
| 0008 0000 | Unlit | Not affected by lights |
| 0010 0000 | GlowingPink | Player's eyes when they have a spirit |
| 0020 0000 – 1000 0000 | ? | (8 unnamed bits) |
| 2000 0000 | NoDepthTest | Further objects can appear in front |
| 4000 0000 | ? | |
| 8000 0000 | Water | Invisible; reflects lightning strangely |

## Attr Flags

Bit flags (`u8`):

| Val | Description |
|-----|-------------|
| 01 | Use Normals |
| 02 | Use Colors |
| 04 | ? used by some map blocks |

These tell whether normal vectors and vertex colors are present in the display lists (size bits for
each attribute in the render stream). Map blocks ignore the Normals flag; they never use normals.

# Animation

Any texture can have up to 64 animation frames, each a separate image, all bundled under the same ID.
There's a "frames per tick" setting in the frame header, but simply adding frames and setting this
value doesn't make a texture animate — the object holding the texture is presumably responsible for
manually changing the animation frame. Animation is used for characters' eye expressions; frames don't
need to play in order.

## Scrolling

Texture scrolling is controlled by `texscroll2` objects and the files `TABLES.bin`/`TABLES.tab`. The
`scrollingTexMtx` field of a shader layer says which scrolling texture matrix slot to use. Each slot
has a speed set for the X and Y axes and advances its offset by this amount every tick.

## In this codebase

Every mapping below was checked against real source in this repo; unmarked claims are direct reads
of the file/line cited, not inference.

### `Texture` header == the 0x60-byte TEXn.bin header

`include/main/texture.h` already has a named, `STATIC_ASSERT`-pinned struct for the wiki's texture
header, field-for-field:

```c
typedef struct Texture {
    u8 unk00[0xA];      /* next@0, flags@4, xOffset@8 (wiki) — not individually named here */
    u16 width;           /* 0xA */
    u16 height;          /* 0xC */
    u16 refCount;        /* 0xE  == wiki "usage" */
    u8 unk10[6];          /* frameVal10@0x10, unk12@0x12, framesPerTick@0x14 (wiki) */
    u8 format;            /* 0x16 == wiki GXTexFmt */
    u8 wrapS, wrapT, minFilter, magFilter, unk1B, minLod, maxLod;
    u8 unk1E[0x22];        /* incl. the embedded 0x20-byte GXTexObj at 0x20 */
    u32 *tmemAddr;         /* 0x40 == wiki's GXTexRegion* texRegion (see below) */
    u8 unk44[4];            /* bufSize */
    u8 preloaded;           /* 0x48 == wiki bNoTexRegionCallback */
    u8 cached;              /* 0x49 == wiki bDoNotFree */
    u8 unk4A;
    u8 evictTimer;          /* 0x4B — matches wiki's "set to 10 when freeing" for unk4B exactly */
    u8 unk4C[4];             /* bufSize2 */
    s32 imageOffset;         /* 0x50 — see discrepancy note below */
    u8 unk54[0xC];
} Texture;
STATIC_ASSERT(sizeof(Texture) == 0x60);
```

- `next` (wiki 0x0000, `Texture*`): confirmed by `textureFn_800541ac` (`rcp_dolphin.c:752`), which
  walks `node = *(int**)node` starting from a `Texture*` to reach the *n*-th animation frame — the
  in-memory frame chain the wiki's "next" field implies.
- `frameVal10` (wiki 0x0010): the same function reads `*(u16*)((char*)tex + 0x10)`, then
  `count = f10 >> 8` — confirming the wiki's "low byte always 0" claim (count lives in the high byte)
  and pinning down what "relates to number of frames" means concretely. `rcp_dolphin.c:600` (in
  `fn_80053C40`) writes `*(u16*)(obj + 16) = 1;` with an existing comment `/* 0x10: mip-chain word
  (count<<8), not named in Texture */` — independent corroboration in this repo's own commentary.
- `refCount` (wiki 0x000E "usage"): matches exactly — `rcp_dolphin.c` increments/decrements it on
  every `textureLoad`/`textureFn_800541ac`/`ShaderDef_free`/`shaderInit` acquire-release pair.
- **Discrepancy at 0x50**: the wiki calls this field `tevVal50` (`u32`, "0:use 1 TEV stage, not 2").
  This repo's `imageOffset` (`s32`, "image data lives at `(u8*)tex + 0x60 + imageOffset`") is a
  *different* interpretation of the same offset, backed by concrete use at `rcp_dolphin.c:1503`:
  `GXInitTexObj(obj, (u8*)(tex + ((Texture*)tex)->imageOffset + 0x60), ...)`. Both readings can't be
  simultaneously literal — worth a second look by whoever revisits this field; this repo's evidence
  (a real pointer-arithmetic use, not just a heuristic) currently outweighs the wiki's guess.
- `tmemAddr` (0x40): wiki names this `GXTexRegion*`. Every use in `rcp_dolphin.c`
  (`GXLoadTexObjPreLoaded(to, ((Texture*)tex)->tmemAddr, map)`, e.g. line 1087/1152/1217) passes it
  as the SDK's `GXTexRegion*` parameter (`include/dolphin/gx/GXTexture.h:28`) — so the wiki's field
  name is the more accurate one; `tmemAddr` undersells what the field actually is.
- `evictTimer` (0x4B): matches the wiki's unk4B description ("set to 10 when freeing") exactly —
  `rcp_dolphin.c:667/672/677` all do `((Texture*)tex)->evictTimer = 10;` on release paths.

### `GXTexFmt` / `GXTexObj` / `GXTexRegion` — verbatim SDK types

`include/dolphin/gx/GXEnum.h:128-159` defines `GXTexFmt` with the exact wiki values (`GX_TF_I4=0`,
`GX_TF_I8=1`, `GX_TF_IA4=2`, `GX_TF_IA8=3`, `GX_TF_RGB565=4`, `GX_TF_RGB5A3=5`, `GX_TF_RGBA8=6`,
`GX_TF_CMPR=0xE`), and `GXCITexFmt` (`GXEnum.h:161-165`) for the palette formats (`GX_TF_C4=8`,
`GX_TF_C8=9`, `GX_TF_C14X2=0xA`) — a 1:1 match to the wiki's table, values and all. `GXTexObj` is
`u32 dummy[8]` (`GXStruct.h:38`, 0x20 bytes — matches the wiki's `texObj` field size in the texture
header) and `GXTexRegion` is `u32 dummy[4]` (`GXStruct.h:46`, 16 bytes) — both intentionally-opaque
per the real Nintendo SDK convention, not something this repo re-derives.

### Texture-ID translation (`TEXTABLE.bin`, TEX0/TEX1/TEXPRE bank select)

`rcp_dolphin.c:2391-2426` (inside `textureLoad`) is a close match for the wiki's "Texture IDs"
algorithm:

```c
origTexId = texId;
if (texId < 0) { texId = -texId; }
else {
    if (texId >= 0xbb8 /* 3000 */) {           /* wiki: "if id >= 3000" */
        remapped = gRcpTexIdRemap[texId];
        if (remapped != 0) { texId = remapped + 1; goto resolved; }
    }
    texId = gRcpTexIdRemap[texId];              /* TEXTABLE.bin remap */
}
resolved:
id16 = texId & 0xffff;
if (texId & 0x8000) { bank = 1 /* TEX1 */; id16 &= 0x7fff; }
else if (origTexId >= 0xbb8) { bank = 2 /* TEXPRE */; }
else { bank = 0 /* TEX0 */; }
```

- `gRcpTexIdRemap` (`extern u16* gRcpTexIdRemap;`, `rcp_dolphin.c:1743`) is loaded by
  `loadAssetFileById(&gRcpTexIdRemap, 0x22)` (`rcp_dolphin.c:1792`) — table index `0x22` in
  `sResourceFileNameTable` (`pi_dolphin.c:7680`) is **`TEXTABLE.bin`** — matching the wiki's
  `u16`-array claim exactly, symbol and file both.
  - `0xbb8 == 3000` decimal, confirming the wiki's literal threshold constant.
  - The bank/high-bit selection (`0x8000` -> TEX1, `origTexId >= 3000` -> TEXPRE, else TEX0) matches
    the wiki's three-way rule exactly. The precise conditions under which `+1` is added differ in
    detail from the wiki's stated rule ("if original < 3000 or new id is 0, add 1") — this repo's
    code only adds 1 on the `texId >= 3000 && remapped != 0` path — worth a closer look if the exact
    edge cases ever matter, but the overall shape (TEXTABLE remap -> high-bit/origin-based bank pick)
    is the same mechanism.
- The three texture banks are loaded in `loadTextureFiles` (`rcp_dolphin.c:1747`):
  `gRcpTexBankTable[0] = getCurrentDataFile(0x24)` (**TEX0.tab**), `[1] = getCurrentDataFile(0x21)`
  (**TEX1.tab**), `[2] = getCurrentDataFile(0x50)` (**TEXPRE.tab**) — cross-checked against the same
  `sResourceFileNameTable` index list, confirming the wiki's three-bank structure 1:1.

### TEXn.tab bitfield (count/offset packing) — see `docs/wiki/Formats.md`

The `??CCCCCC OOOOOOOO...` bitfield and the `mergeTableFiles` primary/alternate-map merge are already
documented in detail in `docs/wiki/Formats.md` ("Texture TAB entries" and "`mergeTableFiles`"
sections), with the concrete match at `rcp_dolphin.c:2459-2460`
(`mips = (bankWord >> 24) & 0x3f;`). Not repeated here to avoid drift between the two docs.

### `Shader` (model render-op) == `ModelFileHeader.renderOps[i]`, 0x44-byte stride

`include/main/model.h`'s `ModelFileHeader.renderOps` (`u8 *renderOps; /* 0x44 each, renderOpCount */`)
is this repo's untyped placeholder for the wiki's `Shader` struct — the 0x44 stride matches the
wiki's struct size (`0x42` last field + 2 bytes padding = `0x44`) exactly. Three independent
partially-named overlays of the *same* record exist in different files (this repo's per-file local
struct convention, not a bug):

1. **`objprint_dolphin.c:81-92`**, `ObjModelRenderOp` — used for model rendering:
   ```c
   typedef struct ObjModelRenderOp {
       u8 pad0[0x18];
       u32 textureId;   /* 0x18 == wiki texture18 */
       u32 unk1C;       /* 0x1C == wiki's unnamed "-1->0,-2->0,else->1; relates to alpha22" field */
       u8 pad20[4];
       u32 unk24;       /* 0x24 == wiki layer[0].texture (ShaderLayer stride 8, see below) */
       u8 pad28[0xC];
       u32 envTextureId;/* 0x34 == wiki auxTex2 */
       u8 pad38[4];
       u32 flags;       /* 0x3C == wiki ShaderFlags */
   } ObjModelRenderOp;
   ```
   Its own comment (`objprint_dolphin.c:71-79`) independently states "byte 0x41 holds the layer count
   and byte 0x40 the layer blend flags (0x10 = additive path)" — matching the wiki's `nLayers`@0x41
   and `attrFlags`@0x40 exactly in *position*; the `0x10 = additive path` bit meaning is new
   information this repo can offer back (the wiki's Attr Flags table only documents bits
   `0x01`/`0x02`/`0x04`, leaving `0x10` open).
2. **`tex_dolphin.c:203-226`**, `MapShader`/`TexLayer` — used for map-block rendering:
   ```c
   typedef struct MapShader {       /* 0x44-stride, block->unk64 array (map_block.h: shaders) */
       u8 pad0[0x3C];
       u32 flags;        /* 0x3C == wiki ShaderFlags */
       u8 pad40;
       u8 layerCount;    /* 0x41 == wiki nLayers */
       u8 pad42[2];
   } MapShader;
   typedef struct TexLayer {         /* == wiki ShaderLayer, returned by Shader_getLayer */
       int texId;        /* 0x00 == wiki ShaderLayer.texture */
       u8 typeBits;       /* 0x04 == wiki tevMode (low 7 bits select blend mode per this file's comment) */
       u8 overrideByte;   /* 0x05 == wiki polyGroupId ("enableTexChainStuff") */
       u8 mtxIndex;       /* 0x06 == wiki scrollingTexMtx (0xff = none) */
       u8 pad7;
   } TexLayer;
   ```
3. **`rcp_dolphin.c:724`**, `shaderInit(u8* def, void** out, u8* obj)` — the shader-load-time texture
   patch step the wiki describes ("replaced with pointers... when the shader is loaded"):
   `def + 0x8` (== wiki `auxTex0`) and `def + 0x14` (== wiki `auxTex1`) are each resolved to a
   `Texture*` from a small fixed array (`gRcpDistortSlots`, a distortion-effect render-target slot
   table, `RcpDistortSlot`, stride 0x1C, `rcp_dolphin.c:1667-1681`) — i.e. wiki's "index into a
   global shader texture array" for `colorIdx`/`auxTex0`/`auxTex1` maps concretely to this repo's
   distortion-texture slot mechanism, not a generic texture list.

### `ModelFileHeader.textureIds` — the "index into model's texture list" resolution

`ObjModel_ResolveRenderOpTextures` (`model.c:474-544`) is the exact, field-by-field implementation of
the wiki's claim "Textures here are not IDs; they're indices into the model's list of textures (or -1
for none). They're replaced with pointers to the texture when the shader is loaded. This also applies
to ShaderLayer":

```c
op = *(u8**)(m + 0x38) + j * 0x44;               /* j-th Shader record (renderOps[j]) */
for (k = 0; k < op[0x41]; k++) {                  /* wiki nLayers */
    u8* e = op + k * 8;                           /* wiki ShaderLayer stride, base = layer[k] */
    if (*(int*)e != -1) *(int*)e = textureIds[*(int*)e]; else *(int*)e = 0;  /* layer[k].texture */
}
if (*(int*)(op + 0x34) != -1) *(int*)(op+0x34) = textureIds[*(int*)(op+0x34)]; else 0;  /* auxTex2 */
if (*(int*)(op + 0x38) != -1) *(int*)(op+0x38) = textureIds[*(int*)(op+0x38)]; else 0;  /* furTexture */
/* op+0x1c: -1->0, -2->0, else->1  -- this is the wiki's unnamed 0x1C field, verbatim */
if (*(int*)(op + 0x18) != -1) *(int*)(op+0x18) = textureIds[*(int*)(op+0x18)]; else 0;  /* texture18 */
```
(the real source, `model.c:487-495`, dereferences `e` through a `GameObject*` alias for `e[0]` — a
load-bearing re-spelling noted in-repo as keeping MWCC's alias/CSE class; simplified above for
clarity, offsets unchanged.)
(`m + 0x20` is `ModelFileHeader.textureIds`, `STATIC_ASSERT`-pinned at offset `0x20`.) The `op+0x1C`
`-1 -> 0, -2 -> 0, else -> 1` encoding is a byte-for-byte match of the wiki's guess for that unnamed
field, right down to the two distinguished sentinel values.

### `polyGroupId` / `scrollingTexMtx` — confirmed via `texscroll2` and `modelRenderFn_8003e98c`

`modelRenderFn_8003e98c` (`objprint_dolphin.c:2588` onward) reads `layer[5]` (wiki `polyGroupId`) as a
"material index" matched against `ObjDef->textureSlotDefs[k].materialIndex`
(`ObjTextureSlotDef`, `include/main/objanim_internal.h:185-188`) to substitute a per-object override
texture/UV-offset from `ObjTextureRuntimeSlot` (`objanim_internal.h:190-199`) — a concrete realization
of the wiki's "enableTexChainStuff — unknown" guess: it's the mechanism letting individual game
objects override specific shader-layer textures at runtime.

`dll_0134_texscroll2.c` (DLL `TEXSCROLL2_DLL_ID 0x134`, `include/main/dll/mmp_moonrock.h:11`) is the
wiki's own named example — `texscroll2_applyMapTextureScroll` (`dll_0134_texscroll2.c:43-126`) walks a
map block's shader/layer array with `material += 8` per iteration (the `ShaderLayer` stride) and reads
fixed offsets `+0x24` (== `ShaderLayer.texture`, since the loop's zero-th `material` pointer is the
*Shader* base and `0x24` is `Shader.layer[0]`'s offset) and `+0x2A` (== `ShaderLayer.scrollingTexMtx`,
`0x24 + 6`) — confirming both the `ShaderLayer` stride (8) and the `scrollingTexMtx` byte offset (+6
within a layer) precisely.

### Scrolling texture matrix — `mapTextureScrollAcquire`/`TABLES.bin`

`mapTextureScrollAcquire`/`mapTextureScrollSetStep` (`shader.c:448`, `shader.c:790`) implement the
wiki's "Scrolling" section directly: a fixed slot table (`lbl_803DCE68`, 0x3a = 58 slots, stride
0x10 — `s16 xStep`@+8, `s16 yStep`@+0xA, `u8 refCount`@+0xC, plus two running `f32` UV offsets) is
searched by `(xStep, yStep)`, ref-counted, and advanced every tick — the "speed set for X and Y axes,
advances its offset every tick" the wiki describes.
`dll_0134_texscroll2.c` gets its slot via `mapTextureScrollAcquire` and stores it in
`ShaderLayer`/`TexLayer.mtxIndex` equivalent (`material + 0x2A`, i.e. `scrollingTexMtx`) — matching
the wiki's "`scrollingTexMtx` field... tells which scrolling texture matrix slot to use" exactly.
(Note: `dll_0134_texscroll2.c`'s own `extern` declarations for these two functions carry two extra
"secondary step" parameters beyond `shader.c`'s definitions — a real signature mismatch already
present in this codebase, not introduced by this doc; the extra args are simply unread by the callee
on this ABI.)

`getTablesBinEntry` (`object.c:437`, prototyped in `include/main/object.h:24` and
`include/main/sfa_shared_decls.h:222`) reads `gObjTablesBinData`/`gObjTablesBinIndex`, loaded via
`loadAssetFileById(..., 0x16)` / `loadAssetFileById(..., 0x17)` (`object.c:2403-2404`) — indices
`0x16`/`0x17` in `sResourceFileNameTable` are **`TABLES.bin`**/**`TABLES.tab`** — confirming the wiki's
"`TABLES.bin` and `TABLES.tab`" claim for the scrolling-matrix backing files. `texscroll2` calls
`getTablesBinEntry(TEXSCROLL_TABLE_ID)` with `TEXSCROLL_TABLE_ID 0x0E` (`mmp_moonrock.h:21`).

### DLL IDs

| Wiki concept | DLL id | Source |
|---|---|---|
| `texscroll2` objects | `0x134` | `src/main/dll/dll_0134_texscroll2.c`, `TEXSCROLL2_DLL_ID` (`include/main/dll/mmp_moonrock.h:11`) |
| (sibling, not separately named by the wiki) `texscroll` | `0x135` | `src/main/dll/dll_0135_texscroll.c`, `TEXSCROLL_DLL_ID` (`mmp_moonrock.h:12`) |

### Not found / out of scope here

- No standalone struct for the wiki's raw `Shader` layout exists as one canonical named type — it's
  intentionally kept as three partial, file-local overlays (`ObjModelRenderOp`, `MapShader`+`TexLayer`,
  and the raw `def`/`op` byte arithmetic in `model.c`/`rcp_dolphin.c`), matching this repo's per-file
  ownership convention. See "Ready-to-adopt code" below for a proposed canonical version.
- `attrFlags`'s wiki-documented bits (`0x01` Use Normals, `0x02` Use Colors, `0x04` map-block flag)
  were not independently found exercised anywhere in `src/` under that name — only the position
  (offset 0x40) and a different bit (`0x10`, "additive path") are corroborated. Not a contradiction
  (the wiki itself only claims 3 of 8 bits), just unconfirmed here.

## Ready-to-adopt code

Nothing below changes behavior — it's a naming/typing lift for bytes already read via raw offsets.
A maintainer could fold this into `include/main/model.h` (Shader/ShaderLayer) and a new
`include/main/shader_flags.h` (or similar) once a canonical file for the shader record is picked:

```c
/* Shader (a.k.a. model "render op" / map-block "material") record.
 * 0x44 bytes, ModelFileHeader.renderOps[i] / MapBlockData.shaders[i] stride.
 * Texture-index fields (auxTex0/auxTex1/texture18/auxTex2/furTexture/layer[].texture)
 * hold indices into the owning model's texture list until ObjModel_ResolveRenderOpTextures
 * patches them to Texture* pointers at load time. */
typedef struct ShaderLayer {
    s32 texture;          /* 0x00: model-texture-list index, patched to Texture* on load */
    u8  tevMode;           /* 0x04: TEV control byte */
    u8  polyGroupId;       /* 0x05: matches ObjTextureSlotDef.materialIndex for per-object override */
    u8  scrollingTexMtx;   /* 0x06: slot index into the mapTextureScrollAcquire table, 0xff = none */
    u8  pad07;
} ShaderLayer;
STATIC_ASSERT(sizeof(ShaderLayer) == 0x08);

typedef struct Shader {
    s8  unk00[4];
    u8  r, g, b, unk07;    /* 0x04: color, use unconfirmed */
    s32 auxTex0;           /* 0x08: texture-list index; also a gRcpDistortSlots selector via shaderInit */
    u8  alpha;             /* 0x0C */
    u8  unk0D[7];
    s32 auxTex1;           /* 0x14 */
    s32 texture18;         /* 0x18 */
    s32 unk1C;             /* 0x1C: -1->0, -2->0, else->1; relates to alpha22 */
    s8  colorIdx;          /* 0x20: gRcpDistortSlots index */
    u8  unk21;
    u8  alpha22;           /* 0x22 */
    u8  unk23;
    ShaderLayer layer[2];  /* 0x24 */
    s32 auxTex2;           /* 0x34 */
    s32 furTexture;        /* 0x38 */
    u32 flags;             /* 0x3C: ShaderFlags */
    u8  attrFlags;         /* 0x40 */
    u8  nLayers;           /* 0x41: max 2 */
    u16 pad42;
} Shader;
STATIC_ASSERT(sizeof(Shader) == 0x44);

/* ShaderFlags (Shader.flags @0x3C) */
#define SHADER_FLAG_UNK1              0x00000001u /* related to SHADER_FLAG_UNK1000 */
#define SHADER_FLAG_HIDDEN            0x00000002u /* confirmed: tex_dolphin.c early-outs render on this bit */
#define SHADER_FLAG_FOG               0x00000004u
#define SHADER_FLAG_CULL_BACKFACE     0x00000008u
#define SHADER_FLAG_UNK10             0x00000010u
#define SHADER_FLAG_REFLECT_SKYSCAPE  0x00000020u
#define SHADER_FLAG_CAUSTIC           0x00000040u
#define SHADER_FLAG_LAVA              0x00000080u
#define SHADER_FLAG_REFLECTIVE        0x00000100u /* confirmed: obj/tex_dolphin.c fn_8004D928 env-tex-mtx path */
#define SHADER_FLAG_UNK200            0x00000200u
#define SHADER_FLAG_ALPHA_COMPARE     0x00000400u /* confirmed: shaderSetGxFlags alpha-compare setup */
#define SHADER_FLAG_UNK800            0x00000800u /* confirmed: forces black chan color in tex_dolphin.c */
#define SHADER_FLAG_UNK1000           0x00001000u /* confirmed: same "force black" effect as UNK800 */
#define SHADER_FLAG_UNK2000           0x00002000u /* confirmed: gates a secondary frustum-plane (mirror?) test */
#define SHADER_FLAG_SHORT_FUR         0x00004000u
#define SHADER_FLAG_MEDIUM_FUR        0x00008000u
#define SHADER_FLAG_LONG_FUR          0x00010000u
#define SHADER_FLAG_STREAMING_VIDEO   0x00020000u /* confirmed: skips light selection in tex_dolphin.c */
#define SHADER_FLAG_INDOOR_OUTDOOR_BLEND 0x00040000u
#define SHADER_FLAG_UNLIT             0x00080000u /* confirmed: forces light count to 0 in tex_dolphin.c */
#define SHADER_FLAG_GLOWING_PINK      0x00100000u
#define SHADER_FLAG_NO_DEPTH_TEST     0x20000000u
#define SHADER_FLAG_UNK40000000       0x40000000u /* this repo's own comment: "force blend"; also seen
                                                      bypassing a mirror-angle visibility test */
#define SHADER_FLAG_WATER             0x80000000u
/* bits 0x00200000-0x10000000 still fully unlabeled in the wiki and unconfirmed here */

/* Shader.attrFlags @0x40 (wiki: display-list attribute presence) */
#define SHADER_ATTR_USE_NORMALS  0x01u
#define SHADER_ATTR_USE_COLORS   0x02u
#define SHADER_ATTR_UNK04        0x04u /* wiki: "used by some map blocks" */
#define SHADER_ATTR_UNK10        0x10u /* objprint_dolphin.c's own comment: "additive path" */
```
