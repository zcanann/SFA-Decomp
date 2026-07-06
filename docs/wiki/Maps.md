# Maps

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Maps). Reverse-engineering notes; not independently verified here.

Maps are one of the most important and most complex subsystems in the game. They define the
world the player navigates. Internally the game sometimes calls maps "tracks" — a holdover from
this engine's origin in Diddy Kong Racing (this codebase's own map-block/collision translation
unit is literally named `track_dolphin.c`, and the collision struct is `TrackTriangle`).

See also (wiki pages, not yet imported here): *List of maps*, *Romlist* (placement of objects in
a map), *Warptab* (warp points).

## Layers

Five layers of map grids exist; the only way to move between layers is via warps or scripted
events. The choice of layer for a map is arbitrary (grids carry no height information); layers -1
and 1 let one map sit over/under another, and -2/2 exist mainly so those "extra" layers don't
bloat the main layers' bounds.

| Layer | Contents |
|---|---|
| -2 | Deep underground; only the DarkIce Mines boss arena |
| -1 | Underground; a few caves |
| 0 | Surface; most maps |
| 1 | Surface; Drakor boss arena and ThornTail shop |
| 2 | Space; Arwing levels |

## Map IDs and Directories

Each map has both a Map ID and a Directory ID. A table embedded in the executable gives the
corresponding Map ID for each Directory ID. The Directory ID indexes a list of directory names;
several unused indices point at `animtest` or at missing/empty directories. In many places (save
files, etc.) the game instead specifies global coordinates + a map layer, not a map ID.

## Coordinate Systems

* **Global Coordinates** — object/player-in-RAM position; paired with a layer number.
* **Global Grid Coordinates** — Global Coordinates with X/Z each divided by 640 and truncated.
* **Map Coordinates** — used by romlist entries.
* **Map Grid Coordinates** — Map Coordinates with X/Z each divided by 640 and truncated.

## Assets

Each map directory contains (case is inconsistent in the originals):

| Files | Contents |
|---|---|
| `ANIM.BIN`/`ANIM.TAB` | Animation data |
| `ANIMCURV.bin`/`ANIMCURV.tab` | Animation curves |
| `MODELIND.bin` | Model ID → `MODELS.tab` index table |
| `MODELS.bin`/`MODELS.tab` | Character/object models |
| `OBJSEQ.bin`/`OBJSEQ.tab` | Object animation sequence data |
| `OBJSEQ2C.tab` | Assigns animation curves to object sequences |
| `TEX0.bin`/`TEX0.tab` | Textures (primarily map geometry) |
| `TEX1.bin`/`TEX1.tab` | Textures (primarily character models) |
| `VOXMAP.bin`/`VOXMAP.tab` | Voxel data — wiki says "relates to camera, possibly unused" (see below; this codebase's own code disagrees) |

Each map bundles a copy of every model/texture/animation it uses to reduce disc-seek load times.
Each map directory also has at least one `modXX.zlb.bin` (+ matching `modXX.tab`) holding the
[map block models](#block-model-data).

## MAPS.bin / MAPS.tab

`MAPS.tab` has one entry per map, indexed by Map ID (not Directory ID); each field is an offset
into `MAPS.bin`:

| Offset | Type | Name | Description |
|---|---|---|---|
| 0x00 | s32 | infoOffset | Offset of map info (grid dimensions, see below) |
| 0x04 | s32 | blockTable | Offset of the block list (`sizeX*sizeZ` `u32`s, see below) |
| 0x08 | s32 | rects1 | Rects that somehow define visible regions |
| 0x0C | s32 | rects2 | more rects |
| 0x10 | s32 | rects3 | more rects |
| 0x14 | s32 | rects4 | more rects |
| 0x18 | s32 | listSize | A `FACEFEED` header giving the romlist's allocation size |

In the kiosk demo the romlist follows the `FACEFEED` header directly inside `MAPS.bin`; the final
game moves it to an external file and leaves only the header. The header's uncompressed-size
field tells the game how much memory to reserve before loading the external romlist file (the
final game still falls back to the in-`MAPS.bin` romlist if the external file is missing, but this
path is never actually exercised).

### `infoOffset` — map info

| Offset | Type | Name | Description |
|---|---|---|---|
| 0x00 | u16 | sizeX | Columns |
| 0x02 | u16 | sizeZ | Rows |
| 0x04 | u16 | originX | Origin column |
| 0x06 | u16 | originZ | Origin row |
| 0x08 | u32 | ? | |
| 0x0C | u32[4] | ? | possibly related to rects |
| 0x1C | s16 | nBlocks | |
| 0x1E | u16 | ? | possibly flags/padding |

The origin cell is where global coordinate (0,0,0) (relative to the map) lands when the map is
placed on the global grid; it need not contain a block, or even fall inside the rectangle.

### Block List

`sizeX * sizeZ` `u32`s, one per grid cell:

```
unk1 =  val >> 31;          // probably unused
mod  = (val >> 23) & 0xFF;
sub  = (val >> 17) & 0x3F;
unk2 =  val        & 0x1FF;
```

`mod == 0xFF` means no block here. Otherwise, if `mod >= 5`, add 1 to it; the result selects
`/<mapdir>/mod<N>.bin` + `.tab`, and `sub` selects which model inside that file. `TRKBLK.tab` (an
array of `u16` indexed by Directory ID) gives a base offset that `sub` is added to, to index into
that `.tab`. The game's code refers to (nonexistent) `BLOCKS.bin`/`BLOCKS.tab` — the code that
would read them reads the `modXX` files instead. A map's total block count appears capped at 512
regardless of actual usage (except Drakor's boss map, which somehow exceeds it — `0x80059248` in
the original binary).

## Block Model Data

`modXX.tab` is a normal `.tab` file (high byte = unknown flags, rest = offset into `modXX.bin`).
At that offset is a ZLB archive containing one block's model, format similar to character models:

| Off | Type | Name | Description |
|---|---|---|---|
| 0x00 | u32 | unused00 | set from `0x80060b90` — unconfirmed as truly unused |
| 0x04 | u16 | flags_0x4 | 0x40 = need init hits?, 0x1 = toggled on render |
| 0x08 | s32 | length | file size |
| 0x0C | Mtx43 | mtx | unsure, seems unused *in the file* |
| 0x4C | pointer | GCpolygons | invisible, hit detection, can be null |
| 0x50 | pointer | polygonGroups | hit detection, can be null |
| 0x54 | u32* | textures | texture IDs |
| 0x58 | vec3s* | vertexPositions | |
| 0x5C | u16* | vertexColors | RGBA4444 |
| 0x60 | vec2s* | vertexTexCoords | |
| 0x64 | Shader* | shaders | how to render polygons |
| 0x68 | DisplayListPtr* | displayLists | native GX display lists |
| 0x6C | LineHit* | linehits | |
| 0x70 | HitsBinEntry* | hits | from `HITS.bin`; 0 in the file itself |
| 0x74 | ?32 | | set to 0 in initHits |
| 0x78/0x7C/0x80 | BitStream* | renderInstrsMain/Transp/Water | normal / transparent+glow / water+reflective geometry streams |
| 0x84/0x86/0x88 | u16 | nRenderInstrsMain/Transp/Water | stream sizes in bytes |
| 0x8A/0x8C/0x8E | s16 | yMin/yMax/yOffset | must be added to vertex Y |
| 0x90 | u16 | nVtxs | |
| 0x92 | u16 | nUnk | |
| 0x94 | u16 | nColors | |
| 0x96 | u16 | nTexCoords | |
| 0x98 | u16 | nPolygons | |
| 0x9A | u16 | nPolyGroups | |
| 0x9C | u16 | nHits | |
| 0x9E | ?16 | hitField_9e | set to 0 in initHits |
| 0xA0 | u8 | nTextures | |
| 0xA1 | u8 | nDlists | |
| 0xA2 | u8 | nShaders | |
| 0xA3 | u8 | | probably padding |
| 0xA4 | char[11] | name | unused, e.g. `"mod6.12"` |

Total struct size 0xB8. (Rare's own debug-message strings are the source for several of these
names.)

### Render Streams

Each of the three `BitStream*` fields points at a 4-bit-opcode stream (high bits first):

| Op | Meaning |
|---|---|
| 0 | unused, behaves like 4 |
| 1 | select texture/shader: read 6-bit index, set current shader = `shaders[index]` |
| 2 | call display list: read 8-bit index; if current shader isn't "hidden" (or none set), call `displayLists[index]` |
| 3 | change vertex format for VAT5 (blocks)/VAT6 (characters): 1 bit POS fmt; blocks skip the NRM bit characters have; 1 bit COL0 fmt iff `curShader.attrFlags & 2`; 1 bit TEX fmt applied to all enabled slots (count = `curShader.nLayers`, or just TEX0 if no shader) |
| 4 | read matrix data: 4-bit count, 8 bits/matrix index (map blocks read but don't use these) |
| 5 | end of stream |
| else | unused, probably like the others |

Textures are read from the map's own directory plus `TEXPRE.bin`. A block's nominal 640×640 XZ
footprint doesn't actually constrain its geometry — out-of-range geometry can pop in/out as blocks
stream in/out around the player.

## Grids

### Individual maps

`MAPS.bin`'s block list is arranged as a `sizeX * sizeZ` rectangle around the map's declared
origin cell; many maps' rectangles are oversized and padded with empty/unused blocks.

### Global Map Grid

`globalma.bin` places each map on one of the five layer grids (an array of structs, terminated by
`map < 0`):

| Offset | Type | Name | Note |
|---|---|---|---|
| 0x00 | s16 | x | Global grid X |
| 0x02 | s16 | z | Global grid Z |
| 0x04 | s16 | layer | -2..2, cast to s8 |
| 0x06 | s16 | map | Map ID (end of list if < 0) |
| 0x08 | s16[2] | link | Linked map IDs |

Cells with no block are ignored, so maps can overlap. The two `link` IDs preload another map's
romlist while the player is in this one, to hide load times (e.g. `swaphol`'s and `swapholbot`'s
objects load together). `globalmap.bin` (no final `p`) is an older, unused version of this file.

## Collision

Collision is a secondary mesh (in the block model) plus a set of lines (`HITS.bin`) mostly used
for ledge grab/jump detection — deleting `HITS.bin` barely affects gameplay.

### Collision Mesh

Same vertex pool as visible geometry, not necessarily wired the same way; all triangles.
`GCpolygons[nPolygons]`:

| Off | Type | Name | Note |
|---|---|---|---|
| 0x00 | u16 | v0 | index into vertexPositions |
| 0x02 | u16 | v1 | |
| 0x04 | u16 | v2 | |
| 0x06 | u16 | subBlocks | which sub-blocks this polygon covers |

Actual triangle coordinates are the raw vertex shorts divided by 8 (hardcoded, not derived from
the GX `POSSHFT`). `GCpolygons` — extracted from `default.dol`'s own strings — probably stands for
"Geometry Collision", not GameCube.

#### Sub-Blocks

High byte = Z axis, low byte = X axis; each divides the block into 8 strips (0..640 in steps of
80), one bit per strip set if the polygon overlaps it.

#### Polygon Groups

`polygonGroups[nPolyGroups]`:

| Off | Type | Name | Note |
|---|---|---|---|
| 0x00 | u16 | firstPolygon | index into `GCpolygons[]` |
| 0x02-0x0C | s16×6 | x1,x2,y1,y2,z1,z2 | bounding box |
| 0x0E/0x0F | ? | | |
| 0x10 | u8 | id | game accesses these fields as u32 |
| 0x11 | u8 | surfaceType | |
| 0x12 | u16 | flags | |

Looks auto-generated from the visible geometry (includes unreachable areas, glow-only polys, etc).

#### Surface Types

| ID | Description |
|---|---|
| 0x00 | Generic; underwater ground, out-of-bounds trees |
| 0x01 | Grass |
| 0x02 | Sand |
| 0x03 | Snow |
| 0x08 | Instant death (DragRockBot only) |
| 0x09 | Ice platform? (cannon in Ice Mountain) |
| 0x0D | Ice (slippery) |
| 0x0E | Water (splash effects) |
| 0x10 | Gold (CloudRunner mine) |
| 0x12 | Rough stone |
| 0x13 | Magic Cave walls/floors |
| 0x18 | Wood |
| 0x19 | Stone/hard surfaces (incl. hot stone, DarkIce Mines) |
| 0x1A | Lava (sets you on fire) |
| 0x1B | Ice walls |
| 0x1D | Conveyor belts |
| 0x21 | Unknown; seen in Arwing levels |
| 0x22 | Metal |

### HITS.bin

Invisible planes: ladder/climbable-wall regions, ledge fall/jump/block behavior, ledge-jump
gating, "invisible wall" outlines (e.g. around Arwing landing spots), enemy/camera-only barriers,
push-block boundaries. Each entry:

| Off | Type | Name | Description |
|---|---|---|---|
| 0x00-0x0A | s16×6 | x1,x2,y1,y2,z1,z2 | position within the block |
| 0x0C | u8[2] | height | see below |
| 0x0E | u8 | flags | high bit selects height interpretation |
| 0x0F | u8 | type | see below |
| 0x10/0x12 | ?16×2 | | |

If `flags`'s high bit is 0, `height` is two separate heights (y1,y2); if 1, both bytes are one
`s16` applied to both ends. Resulting shape: `(x1,y1,z1)-(x1,y1+h1,z1)-(x2,y2+h2,z2)-(x2,y2,z2)`.
The block's Y offset is *not* applied.

#### Types

The top two bits carry other meaning beyond the type value itself.

| ID | Description |
|---|---|
| 0x01 | General barrier |
| 0x02 | Ledge — auto-grab if you walk off |
| 0x03 | Climbable wall |
| 0x04 | Ledge you can jump off |
| 0x05 | Ledge you can jump off (differs unclear; used in Animtest) |
| 0x06 | Ledge you climb/jump up to (automatic, by height) |
| 0x0A | Ladder |
| 0x0D | Push-block barrier |
| 0x0E | Crawl-through tunnel |
| 0x10 | Presumably lets you climb out of water |
| 0x11 | Unknown; game clears top 2 bits and changes type to 0x13 |

`HITS.tab` gives each entry's offset, indexed by `mod#` (as remapped through `TRKBLK.tab`) plus
`sub#`; entry count = next tab entry minus this one. Several maps have leftover/out-of-place
entries (ThornTail Hollow has some floating in the sky and buried underground) that the game
appears to genuinely still read.

### Display List Bounding Boxes

Each `displayLists[]` entry:

| Off | Type | Name | Description |
|---|---|---|---|
| 0x00 | void* | list | raw GX command data |
| 0x04 | u16 | size | list size in bytes |
| 0x06 | vec3s[2] | bbox | bounding box |
| 0x12 | ? | | |
| 0x13 | u8 | shaderId | |
| 0x14 | u16 | specialBitAddr | offset relating to shaders |
| 0x16 | u16 | | offset of some sort |
| 0x18 | u32 | | always `07 00 00 00`? (leftover N64 segmented address?) |

Used to test whether the list should even be rendered.

## Misc Files

### MAPINFO.bin

Mostly-unused per-map debug info: `char[28] name` (padded, not terminated), `u8 type` at 0x1C
(0=normal, 1=normal sub-map, 2/3=special (deletes all objects, unused), 4=special/Arwing/title/
world map — only 0/1/4 used, plus one unused map using 3), `u8` always 6 at 0x1D, `u16 objType` at
0x1E (unused; previously an ObjDef ID for the player object, only for type-1 maps).

### VOXMAP

`VOXMAP.bin`/`.tab` per map directory; wiki says purpose unknown, "relates to camera, possibly
unused" (swapping or deleting them had no visible effect in RE testing). See below — this
codebase's own code points at a different, concrete purpose.

---

## In this codebase

Cross-references verified by reading the source at the paths below. Confidence is generally very
high for anything under "Block Model Data" — many of the wiki's guessed offsets are independently
confirmed by two or three different call sites here, occasionally down to the exact struct stride.

### Files, tables, layers

- `src/main/pi_dolphin.c` defines the on-disc filename constants exactly as the wiki lists them,
  in a 90-entry `sResourceFileNameTable[]`: `sResourceFileNameMapsBin`/`MapsTab` (`"MAPS.bin"`/
  `"MAPS.tab"`), `sResourceFileNameMapinfoBin` (`"MAPINFO.bin"`), `sResourceFileNameWarptabBin`,
  `sResourceFileNameGlobalmaBin` (`"globalma.bin"`, confirming the wiki's *current* filename, not
  the older `globalmap.bin`), `sResourceFileNameTrkblkTab`, `sResourceFileNameHitsBin`/`HitsTab`,
  `sResourceFileNameBlocksBin`/`BlocksTab` (present as filename constants even though — per the
  wiki — nothing on disc actually has those names; `MapBlock_loadFromFile`/block loading in
  `track_dolphin.c` load through the `modXX` files instead, matching the wiki's "the code that
  would read them instead reads the modXX files"), `sResourceFileNameVoxmapBin`/`VoxmapTab`,
  `sResourceFileNameModelsBin`/`ModelsTab`, `sResourceFileNameModelindBin`,
  `sResourceFileNameObjseq2cTab`, `sResourceFileNameAnimTab`/`AnimBin`,
  `sResourceFileNameAnimcurvBin`/`AnimcurvTab`, `sResourceFileNameTex0Bin`/`Tex0Tab`/`Tex1Bin`/
  `Tex1Tab`.
- **Layers**: `s8 curMapLayer` (`src/main/shader.c`) is clamped to exactly **-2..2** by
  `goToPrevMapLayer`/`goToNextMapLayer` — confirms the wiki's 5-layer range verbatim.
- **Map ID ↔ Directory ID**: `int mapGetDirIdx(int mapId)` (`src/main/pi_dolphin.c:3267`,
  `0x800481B0` per `config/GSAE01/symbols.txt`) indexes `sMapFileNameIndexRemapTable[]` (a 75-entry
  `u32[]` defined at `pi_dolphin.c:8071`) to turn a Map ID into a directory index; it's called from
  dozens of DLLs (`lockLevel(mapGetDirIdx(...), ...)`, `mapUnload(mapGetDirIdx(...), ...)`) — this
  is the concrete implementation of the wiki's "table which gives the corresponding Map ID for
  each Directory ID" (same table, consumed in the mapId→dirIdx direction here).
  `sMapFileNameByMapIdTable[]` (`pi_dolphin.c:8049`) is a parallel `char*[]` indexed directly by
  Map ID giving the directory-name string, and repeatedly points at `sMapFileNameAnimtest` for
  unused slots — matches the wiki's "several unused indices point to the name animtest" exactly.
- **Linked-map preloading**: `loadMapAndParent(int mapId)` (`src/main/objprint_dolphin.c:3782`,
  `0x80042F78`) looks up `sMapFileNameAdjacencyTable[]` (a `s16[]`, `-1` = none) via the same
  `sMapFileNameIndexRemapTable` remap, and if the linked ("parent") map's blocks aren't already
  loaded, loads *that* map's data files instead — this is the runtime behavior the wiki describes
  for `globalma.bin`'s `link` field (though this table only carries one link per map, not the
  wiki's `link[2]` pair).
- **Global grid math**: `mapLoadBlocksFn_800685cc` (`src/main/track_dolphin.c:4082`, `0x800685CC`)
  divides world coordinates by a named-but-unconfirmed constant `lbl_803DECE0` (very likely
  `640.0f`) to get grid cell indices, walks `layer` from 0 to 5 (`while (layer < 5)`, confirming
  the 5-layer grid), and calls `mapGetBlockAtPos(gx, gz, layer)` (`0x8005AF2C`) per cell — this is
  the "look up a block on one of the five layer grids" step the wiki's Global Map Grid section
  describes. The same function computes each polygon's Sub-Blocks coverage mask with
  `for (pos = 0; pos != 0x280; pos += 0x50) ...` (0x280 = 640, 0x50 = 80) run once for X and once
  for Z — an exact, byte-for-byte match of the wiki's "8 strips of 80 units" description.
- `gTrackGridOrigin` (`.bss:0x8038DE44`, size 0x104) is the in-memory table of currently-resident
  blocks' grid-relative origins that `mapLoadBlocksFn_800685cc` populates and walks.

### Block Model Data — offset-by-offset

`include/main/map_block.h`'s `MapBlockData` (the record `mapGetBlock()` returns) already carries
`flags4`@0x04, `vertices`@0x58, `vertexCount`@0x90, `polyGroupCount`@0x9A, `edgeCount`@0xA1,
`layerCount`@0xA2 with padding elsewhere; `src/main/tex_dolphin.c` separately (re-)declares a
narrower local `MapBlockData` with `shaders`@0x64 (`MapShader*`) and `bounds`@0x68
(`MapBlockBoundsRec*`). Reading the block-accessor helpers in `track_dolphin.c` and their callers
fills in nearly every remaining offset the wiki lists for this struct, matching **exactly**:

| Wiki offset/field | Confirmed here |
|---|---|
| 0x4C `GCpolygons` | `fn_800606DC(obj, idx)` = `obj[0x4C/4] + idx*8` — stride 8 matches `MapTriIndex` (`track_dolphin.c`: `u16 vert[3]` + `u16 cellMask`), the exact v0/v1/v2/subBlocks layout the wiki gives for `GCpolygons`. |
| 0x50 `polygonGroups` | `mapBlockFn_800606ec(obj, idx)` = `obj[0x50/4] + idx*0x14` — stride 0x14 matches `MapTriGroup` (`firstTri`,minX..maxZ bbox, `flags`), the wiki's Polygon Groups record size. |
| 0x58 `vertexPositions` | `setupToRenderMapBlock` (`track_dolphin.c`): `GXSetArray(GX_VA_POS, *(void**)(block+0x58), 6)` — stride 6 = `vec3s`. Also `map_block.h`'s `vertices` field. |
| 0x5C `vertexColors` | same function: `GXSetArray(GX_VA_CLR0, *(void**)(block+0x5C), 2)` — stride 2 = `u16` (RGBA4444). |
| 0x60 `vertexTexCoords` | same function: `GXSetArray(GX_VA_TEX0/TEX1, *(void**)(block+0x60), 4)` — stride 4 = `vec2s`. |
| 0x64 `shaders` | `fn_8006070C(obj, idx)` = `obj[0x64/4] + idx*0x44`; `tex_dolphin.c`'s `MapShader` is exactly 0x44 bytes. |
| 0x68 `displayLists` | `fn_800606FC(obj, idx)` = `obj[0x68/4] + idx*0x1C`; `tex_dolphin.c`'s `MapBlockBoundsRec` is exactly 0x1C bytes and its first 0x12 bytes (`dlist`,`dlistSize`,6×s16 AABB) match the wiki's Display List Bounding Box table field-for-field. |
| 0x70 `hits` | `MapBlock_initHits` (`track_dolphin.c:1099`, loads file ID `0x28` = `HitsBin`'s slot in `sResourceFileNameTable`) allocates and DVD-loads straight into `obj+0x70` — matches "0 in file, populated from `HITS.bin`" exactly. Entry size used (`size/20`) confirms the wiki's 0x14-byte HITS.bin entry, and the per-entry bounds check reads `entry+0`/`+2` (x1/x2) and `entry+8`/`+0xA` (z1/z2) against `[0, 0x280]` — matching the wiki's x1/x2/z1/z2 field positions. |
| 0x74 | `MapBlock_initHits` writes `anim.hitVolumeTransforms = 0` (offset 0x74 by `STATIC_ASSERT` in `objanim_internal.h`) — matches "set to 0 in initHits" verbatim (this function *is* the wiki's guessed "initHits"). |
| 0x78/0x7C/0x80 `renderInstrsMain/Transp/Water` | `renderMapBlock(o, type)` (`track_dolphin.c:282`, `0x8005FBC4`) reads the pointer via `anim.hitVolumeBounds` (type main), `anim.banks` (type 1, transparent), `anim.previousLocalPosX` (type 2, water) — these `ObjAnimComponent` fields are `STATIC_ASSERT`-pinned at 0x78/0x7C/0x80 respectively in `objanim_internal.h`. |
| 0x84/0x86/0x88 `nRenderInstrsMain/Transp/Water` | same function reads the matching counts as raw `*(u16*)(o+0x84/0x86/0x88)`. |
| 0x90 `nVtxs` | `map_block.h`'s `vertexCount`; also read directly in `mapLoadBlocksFn_800685cc`'s `cacheAllocAndCopy(..., *(u16*)(blk+0x90) * 6, ...)` (stride 6 = vertex size). |
| 0x98 `nPolygons` | same function: `cacheAllocAndCopy(..., *(u16*)(blk+0x98) << 3, ...)` (`<<3` = ×8 = `MapTriIndex` stride) — the count for the 0x4C `GCpolygons` array. |
| 0x9A `nPolyGroups` | `map_block.h`'s `polyGroupCount`. |
| 0x9C `nHits` | written by `MapBlock_initHits` as `size/20` right after the `HITS.bin` load, at `obj+0x9c`. |
| 0x9E `hitField_9e` | `MapBlock_initHits` writes `*(u16*)(obj+0x9e) = 0` right next to the 0x74 write above — matches "set to 0 in initHits" for this field too. |
| 0xA1 `nDlists` | `MapBlock_init` (`track_dolphin.c:1069`) fixes up the `displayLists` array in a loop bounded by `*(u8*)(obj+0xA1)`, stride 0x1C — the same array `fn_800606FC` walks. `map_block.h` currently names this field `edgeCount` (see Ready-to-adopt below). |
| 0xA2 `nShaders` | bounds the `fn_8006070C`/`shaders` walk in `dll_0134_texscroll2.c` (`for (layerIdx = 0; layerIdx < block->layerCount; ...)`). `map_block.h` currently names this field `layerCount`, which collides in spirit with `MapShader`'s own per-entry `layerCount` (`nLayers`) at shader+0x41 — two different counts sharing a similar name (see Ready-to-adopt below). |

### The "block header reuses `ObjAnimComponent` field slots" pattern

`MapBlock_init` (`track_dolphin.c:1069`) fixes up a freshly-loaded block's file-relative pointers
into absolute ones by adding the block's own base address — and it does so entirely through
`GameObject`/`ObjAnimComponent` accessor field names, not raw offsets, because a map block and a
normal game object apparently share the same base record layout in this engine. Cross-referencing
`STATIC_ASSERT`s in `include/main/objanim_internal.h` against the wiki's block-header table shows
the reused fields line up exactly:

| `ObjAnimComponent` field (asserted offset) | Reused as (wiki name) |
|---|---|
| `placementData`/`placement` (0x4C) | `GCpolygons` |
| `modelInstance` (0x50) | `polygonGroups` |
| `hitReactState` (0x54) | `textures` |
| — (0x58, no named field; `MapBlock_init` uses a raw `*(int*)(obj+0x58)`) | `vertexPositions` |
| `weaponDaTable` (0x5C) | `vertexColors` |
| `eventTable` (0x60) | `vertexTexCoords` |
| `modelState` (0x64) | `shaders` |
| `dll` (0x68) | `displayLists` |
| `textureSlots` (0x70) | `hits` |
| `hitVolumeTransforms` (0x74) | (unnamed 0x74 field, "set to 0 in initHits") |
| `hitVolumeBounds` (0x78) | `renderInstrsMain` |
| `banks` (0x7C) | `renderInstrsTransp` |
| `previousLocalPosX` (0x80) | `renderInstrsWater` |

This also explains the wiki's guess that the on-disk `Mtx43 mtx` at 0x0C "seems unused in file":
this codebase's runtime code repurposes that exact byte range for its own bookkeeping —
`MapBlockData.allocHandle` (0x10) and `MapBlockData.flags` (0x30, tested as
`block->flags & 0x2000`/`& 0x20` in `track_dolphin.c`) both land inside 0x0C–0x3C.

### Collision / surface types

- `TrackTriangle` (`track_dolphin.c:493`) is the runtime (unpacked) form of a `GCpolygons` entry;
  its `surfaceType` field is explicitly commented "copied into intersect-line records".
  `MapTriIndex`/`MapTriGroup` (same file) are the packed on-disk forms, matching `GCpolygons` and
  Polygon Groups byte-for-byte (see table above).
- `PlayerState.surfaceType` (`dll/player.c`, switch at line 11132) confirms several of the wiki's
  Surface Type semantics against actual gameplay-effect code: `case 3` (Snow) reduces target speed;
  `case 13` (0x0D, Ice) changes the velocity-smoothing rate to a slippery preset; `case 8`
  (Instant Death) fires a single lethal `ObjHits_RecordObjectHit`; `case 26` (0x1A, Lava) fires a
  periodic damage hit exactly matching "sets you on fire"; `case 29` (0x1D, Conveyor) looks up the
  nearest `CFGUARDIAN_OBJGROUP` object and derives a push velocity from it, matching "conveyor
  belts". (The same switch also has cases for 6, 28 (0x1C), 31 (0x1F), and 32 (0x20) that aren't in
  the wiki's Surface Type table at all — presumably surface IDs the wiki's author never encountered
  in the maps they inspected.)
- `playerStateGrabLedge`, `playerStateOnLadder`, `playerStateClimbWall` (`dll/player.c`) are the
  named player states for HITS.bin types 0x02 (ledge auto-grab), 0x0A (ladder), and 0x03
  (climbable wall) respectively — conceptual confirmation only; no numeric `== 0x0A` etc. type
  check was traced back to a HITS-entry read in this pass.
- `struct PackHeader` (`src/main/pi_dolphin.c:160`), header-commented "romlist blocks, MAPS.BIN
  sections", is exactly the wiki's `FACEFEED` header: `u32 magic` (0xFACEFEED = zlb-packed,
  0xE0E0E0E0 = stored raw), `decompressedSize`, `auxSize`, `compressedSize`. `mapsBinGetRomlistSize`
  (`pi_dolphin.c:6178`, `0x80048BA4`) is the function that reads the size fields the wiki describes
  MAPS.bin's `listSize` field pointing at.

### VOXMAP — this codebase suggests a different purpose than the wiki's guess

The wiki calls `VOXMAP.bin`/`.tab`'s purpose "unknown", tentatively "relates to camera, possibly
unused". `src/main/voxmaps.c` (`include/main/voxmaps.h`) tells a different story: it implements an
occupancy-bitmap route-finding grid — `voxmaps_getRouteNode` walks a per-row popcount over a
bitmap to find graph nodes for pathing (`VOXMAPS_ROUTE_NODE_CAPACITY 200` route nodes,
`CurveHeap_SiftDown`-based open-list search shared with the RomCurve system's heap). Worth flagging
upstream to the wiki: this looks like a voxel-grid pathfinding aid (likely for AI navigation), not
a camera-only or dead system, though it's still possible the *feature* was cut and only the
loader/parser code survives unused, which lines up with the wiki's empirical test (swapping the
data around had no visible effect in-game).

### Not found in this codebase (checked, absent)

- No parser for `MAPS.bin`'s `infoOffset` struct (`sizeX`/`sizeZ`/`originX`/`originZ`/`nBlocks`)
  was found by name — likely inlined into whatever loads `MAPS.bin`, not yet decompiled/named.
  (Note: unrelated `originX`/`originZ` fields exist elsewhere in this codebase — e.g.
  `ModelChain`/`VoxMapState` in `model.c`/`voxmaps.c` — but they are local-origin fields for other
  systems, not this table.)
  - Update in this pass: `mapsBinGetRomlistSize` (`pi_dolphin.c:6178`) reads `s16` pairs at
    `+0x1C`/`+0x1E` off a per-map-ID row in the in-memory `MAPS.tab` — offsets that don't match
    `infoOffset`'s own layout, so this is a different (likely `blockTable`-relative) table, not
    confirmed to be `infoOffset` itself.
- No struct for `MAPINFO.bin`'s `name`/`type`/`objType` record was found — only the filename
  constant (`sResourceFileNameMapinfoBin`) is present; nothing reads it by field name in this pass.
- No numeric HITS.bin `type` (0x01–0x11) check was traced to source in this pass, beyond the
  conceptual player-state names above.
- `DisplayListPtr`/bounding-box `shaderId`/`specialBitAddr` fields (wiki 0x13/0x14/0x16/0x18) have
  no confirmed reader in this codebase beyond `MapBlockBoundsRec`'s raw byte layout in
  `tex_dolphin.c`.

## Ready-to-adopt code

1. `include/main/map_block.h`'s `MapBlockData` currently pads out 0x34–0x58 and 0x5C–0x90 as
   unknown. Per the offset table above, a maintainer could fill those ranges in (keeping the
   existing "true size unverified" caveat) as:

   ```c
   typedef struct MapBlockData
   {
       u8 pad0[0x4 - 0x0];
       u16 flags4;              /* 0x04 */
       u8 pad6[0xC - 0x6];
       s32 unkC;                /* runtime reuse of on-disk Mtx43 (unused in file) */
       s32 allocHandle;         /* runtime reuse of on-disk Mtx43 */
       u16 unk14;
       u8 pad16[0x30 - 0x16];
       s32 flags;               /* runtime reuse of on-disk Mtx43; tested & 0x2000, & 0x20 */
       u8 pad34[0x4C - 0x34];
       MapTriIndex* gcPolygons;  /* 0x4C, stride 8, count = nPolygons @0x98 */
       MapTriGroup* polygonGroups; /* 0x50, stride 0x14, count = polyGroupCount @0x9A */
       u32* textures;           /* 0x54 */
       s32 vertices;            /* 0x58, stride 6 */
       u16* vertexColors;       /* 0x5C, stride 2 */
       s16* vertexTexCoords;    /* 0x60, stride 4 (vec2s) */
       MapShader* shaders;      /* 0x64, stride 0x44, count = shaderCount @0xA2 */
       MapBlockBoundsRec* displayLists; /* 0x68, stride 0x1C, count = dlistCount @0xA1 */
       void* linehits;          /* 0x6C */
       void* hits;              /* 0x70, loaded from HITS.bin; 0 in file */
       u32 unk74;               /* 0x74, zeroed by MapBlock_initHits */
       void* renderInstrsMain;  /* 0x78 */
       void* renderInstrsTransp;/* 0x7C */
       void* renderInstrsWater; /* 0x80 */
       u16 nRenderInstrsMain;   /* 0x84 */
       u16 nRenderInstrsTransp; /* 0x86 */
       u16 nRenderInstrsWater;  /* 0x88 */
       s16 yMin, yMax, yOffset; /* 0x8A, 0x8C, 0x8E */
       u16 vertexCount;         /* 0x90 */
       u16 nUnk;                /* 0x92 */
       u16 nColors;             /* 0x94 */
       u16 nTexCoords;          /* 0x96 */
       u16 nPolygons;           /* 0x98 */
       u16 polyGroupCount;      /* 0x9A */
       u16 nHits;               /* 0x9C, set by MapBlock_initHits */
       u16 hitField9e;          /* 0x9E, zeroed by MapBlock_initHits */
       u8 nTextures;            /* 0xA0 */
       u8 dlistCount;           /* 0xA1, currently named edgeCount */
       u8 shaderCount;          /* 0xA2, currently named layerCount */
       u8 padA3;
   } MapBlockData;
   ```

   (`MapTriIndex`/`MapTriGroup`/`MapShader`/`MapBlockBoundsRec` already exist, just scattered
   across `track_dolphin.c`/`tex_dolphin.c` rather than a shared header — unifying them would also
   resolve the current situation where `tex_dolphin.c` re-declares its own narrower
   `MapBlockData`.)

2. Rename `map_block.h`'s `layerCount` (0xA2) to something like `shaderCount` — as currently
   spelled, it reads as a duplicate of `MapShader.layerCount` (0x41, the wiki's per-shader
   `nLayers`, in `tex_dolphin.c`), but the two are unrelated counts (array length of `shaders[]` vs.
   texture-layer count *within one* shader entry).

3. A surface-type enum, restricted to values this pass could confirm actually change behavior
   (rather than transcribing the wiki's full, partly-speculative list verbatim):

   ```c
   /* Collision surface type (MapTriGroup/GCpolygons Polygon Group +0x11; see
      docs/wiki/Maps.md "Surface Types" for the full, less-certain wiki list). Only
      values with confirmed gameplay effect in dll/player.c are named here. */
   typedef enum SurfaceType
   {
       SURFACE_GENERIC       = 0x00,
       SURFACE_GRASS         = 0x01,
       SURFACE_SAND          = 0x02,
       SURFACE_SNOW          = 0x03, /* player.c: reduces target anim speed */
       SURFACE_INSTANT_DEATH = 0x08, /* player.c: single lethal hit */
       SURFACE_ICE           = 0x0D, /* player.c: slippery velSmoothRateBase */
       SURFACE_WATER         = 0x0E,
       SURFACE_LAVA          = 0x1A, /* player.c: periodic burn damage */
       SURFACE_CONVEYOR      = 0x1D, /* player.c: pushes toward CFGUARDIAN_OBJGROUP */
       SURFACE_METAL         = 0x22,
   } SurfaceType;
   ```
