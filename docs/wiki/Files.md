# Files

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Files). Reverse-engineering notes; not independently verified here.

Most files on the disc are pairs of `.bin` (the actual data) and `.tab` (a table of offsets
into the `.bin`).

## Files specific to each map

Found in each [map directory](MapList). To improve load time, every map carries its own copy
of every asset it uses: loading a map means reading a few large files and converting offsets
to pointers, rather than seeking around for many small files. This costs disc space but discs
have fixed capacity anyway.

| .bin | .tab | Description |
|---|---|---|
| ANIM.BIN | ANIM.TAB | [Character animations](Animation) |
| ANIMCURV.bin | ANIMCURV.tab | [Animation Curves](Scripting#ANIMCURV) |
| modXX.zlb.bin | modXX.tab | [Map geometry and structure](MapLoading) |
| MODELIND.bin | (none) | maps model IDs to indices |
| MODELS.bin | MODELS.tab | [Character models](Models) |
| (none) | OBJSEQ2C.tab | Maps object sequences to animation curves |
| OBJSEQ.bin | OBJSEQ.tab | [Object sequences](Scripting#OBJSEQ) |
| TEX0.bin | TEX0.tab | [Textures](Textures), eg environment |
| TEX1.bin | TEX1.tab | [Textures](Textures), eg characters |
| VOXMAP.bin | VOXMAP.tab | Voxel data, relates to camera |

Each of these names is also present in the disc root; not sure if those root copies are used.
Not every `modXX.zlb.bin` has a corresponding `modXX.tab` in the root.

## Data files in the disc root

Excludes the map-specific files above.

| .bin | Bin Size | .tab | Tab Size | Description |
|---|---:|---|---:|---|
| AMAP.BIN | 206240 | AMAP.TAB | 5056 | related to [Animation](Animation) (probably maps animation IDs to indices) |
| BITTABLE.BIN | 15680 | (none) | - | Table of [GameBit](GameBits) offsets and table indexes |
| CAMACTIO.bin | 2048 | (none) | - | Defines camera movements |
| ENVFXACT.bin | 98304 | (none) | - | Defines weather effects |
| globalma.bin | 768 | (none) | - | Defines the global coordinates of each map |
| HITS.bin | 392544 | HITS.tab | 6400 | related to map hit detection |
| MAPINFO.bin | 3744 | (none) | - | name, type, params for each map - [Map List](MapList) - mostly unused in final version |
| MAPS.bin | 111648 | MAPS.tab | 3296 | Defines the blocks that make up each map |
| MODANIM.BIN | 11232 | MODANIM.TAB | 2528 | ? related to [Animation](Animation) |
| MODLINES.bin | 7424 | MODLINES.tab | 192 | ? related to models |
| OBJECTS.bin | 301696 | OBJECTS.tab | 5920 | [Object definitions](Objects) |
| OBJEVENT.bin | 9568 | (none) | - | ? may not be used |
| OBJHITS.bin | 27584 | (none) | - | hitboxes? looks like a sparse table |
| OBJINDEX.bin | 4384 | (none) | - | maps object IDs to indices |
| PREANIM.BIN | 946880 | PREANIM.TAB | 10400 | something relating to animation |
| TABLES.bin | 736 | TABLES.tab | 96 | relates to texture animation - deleting it stops waterfall animations |
| TEXPRE.bin | 482048 | TEXPRE.tab | 832 | textures for something (sort of "TEX2") |
| TEXTABLE.bin | 6496 | (none) | - | maps texture IDs to indices |
| (none) | - | TRKBLK.tab | 160 | relates to map blocks |
| WARPTAB.bin | 2048 | (none) | - | [Warp destinations](Warptab) |
| WEAPONDA.bin | 51264 | (none) | - | relates to staff animations |

## Misc files in the disc root

| File Name | FileSize | Description |
|---|---:|---|
| openingXX.bnr | 6496 | (XX=EU,JP,US,(blank)) banner image for somewhere |
| starfox.thp | 48931320 | title screen movie |

### Unused files

Only quick testing, so some of these might be used somewhere.

**Never accessed** (mostly old versions of other files):

| File Name | FileSize | Description |
|---|---:|---|
| CACHEFONTSTAB.bin | 0 | |
| CACHEFONTSTEX.bin | 0 | |
| CAMACTIONS.bin | 2048 | a few differences |
| CHAPBITS.bin | 81920 | [almost all zeros](ChapBits) |
| DLLS.tab | 32 | 4 entries: 0x58, 0xAB, 0, 0xC3 - leftover from N64 version |
| ENVFXACTIONS.bin | 98304 | many differences |
| globalmap.bin | 608 | old map grid |
| OBJECTS.bin2 | 301952 | many differences - incompatible with existing table |
| splashScreen.bin | 614400 | [Unused splash screen](https://tcrf.net/File:Starfoxadv-splashscreen.png) |
| SPRITES.bin | 176 | |
| SPRITES.tab | 64 | |
| SPRTABLE.bin | 174 | |
| VOXOBJ.bin | 0 | |
| VOXOBJ.tab | 32 | empty table |

**Read, but not used** (game reads these at startup but seems to do nothing with them):

| File Name | FileSize | Description |
|---|---:|---|
| FONTS.bin | 22432 | presumably font graphics; named inside; similar format to Diddy Kong Racing |
| GAMETEXT.bin | 69376 | Old version of gametext, has unused dialogue |
| GAMETEXT.tab | 20672 | |
| LACTIONS.bin | 40960 | Some functions read from this, but do nothing with the data; 0x28-byte entries, related to lights |
| SAVEGAME.bin | 6144 | vaguely similar to an actual savegame file |
| SAVEGAME.tab | 32 | |
| SCREENS.bin | 307232 | contains two unused images - loaded but not used |
| SCREENS.tab | 32 | offsets into SCREENS.bin |

## Non-map directories in the disc root

| Dir Name | Description |
|---|---|
| [audio](Audio) | all sound effect archives, midi |
| card | save file icons for display in console's memory card menu |
| gametext | the used gametext files for each map |
| modules | two files that appear to be unused |
| musyxbin | two empty dirs |
| savegame | save game files used for debug chapter select |
| [streams](AudioStreams) | audio streams (long voice clips, music?) |

## Files that need investigation (per the wiki)

**Animation**: `/CAMACTIO.bin` format?; `/MODANIM.BIN,TAB` presumably model animations;
`/PREANIM.BIN,TAB` presumably animation; `/WEAPONDA.bin` format, what's in here?

**Graphics**: `/TABLES.bin,tab` involved in texture animation (deleting stops waterfall
animation, otherwise harmless); `/TEXPRE.bin,tab` related to PREANIM? textures?

**Map related**: `/[mapname]/VOXMAP.bin,tab`; `/HITS.bin,tab` (related to map hit boxes, modXX
files refer to these); `/modXX.zlb.bin, /modXX.tab` - root copies vs per-map copies, are they
different, why do only some have a root `.tab`?

**Objects**: `/MODLINES.bin,tab` (objects refer to these somehow); `/OBJEVENT.bin`;
`/OBJHITS.bin` (object hitboxes? related to HITS.bin?)

**Text**: `/GAMETEXT.bin,tab` format? Not used, but contains old dialogue versions.

**Unknown**: [`/CHAPBITS.bin`](ChapBits) (almost all zeros, used? related to debug chapter
select? ~5 entries per GameBit); `/SAVEGAME.bin,tab` used? maybe debug chapter select or old
demo code; `/[mapname]/BLOCKS.bin,tab` don't actually exist on disc - the asset loader ignores
this listed entry and loads `modXX.zlb.bin` instead (might exist in the demo version).

**Empty files**: `/CACHEFONTSTAB.bin`, `/CACHEFONTSTEX.bin`, `/VOXOBJ.bin,tab`,
`/musyxbin/global`, `/musyxbin/starfox`.

Some are referenced by `default.dol`; unfortunately it expects them in a different format than
those of any released version.

---

## In this codebase

The entire "Data files in the disc root" + "Files specific to each map" mechanism above is
implemented by **`src/main/pi_dolphin.c`** (header `include/main/pi_dolphin.h`). This is a
substantial, already-decompiled subsystem and gives a much more precise picture than the wiki
page alone - concrete fileIds, buffer strides, and record formats, verified by reading the
consuming code.

### The master file table (`sResourceFileNameTable`)

`src/main/pi_dolphin.c` defines `char* sResourceFileNameTable[90]`, indexed by an integer
`fileId` (0x00-0x59) used throughout the engine. This table *is* the wiki's file list, plus
the numeric id every loader call site actually uses:

| fileId | Name | String | fileId | Name | String |
|---|---|---|---|---|---|
| 0x00 | `sResourceFileNameAudioTab` | AUDIO.tab | 0x2d | `sResourceFileNameModanimTab` | MODANIM.TAB |
| 0x01 | `sResourceFileNameAudioBin` | AUDIO.bin | 0x2e | `sResourceFileNameModanimBin` | MODANIM.BIN |
| 0x02 | `sResourceFileNameSfxTab` | (SFX.tab) | 0x2f | `sResourceFileNameAnimTab` | ANIM.TAB |
| 0x03 | `sResourceFileNameSfxBin` | (SFX.bin) | 0x30 | `sResourceFileNameAnimBin` | ANIM.BIN |
| 0x04 | `sResourceFileNameAmbientTab` | AMBIENT.tab | 0x31 | `sResourceFileNameAmapTab` | AMAP.TAB |
| 0x05 | `sResourceFileNameAmbientBin` | AMBIENT.bin | 0x32 | `sResourceFileNameAmapBin` | AMAP.BIN |
| 0x06 | `sResourceFileNameMusicTab` | MUSIC.tab | 0x33 | `sResourceFileNameBittableBin` | BITTABLE.bin |
| 0x07 | `sResourceFileNameMusicBin` | MUSIC.bin | 0x34 | `sResourceFileNameWeapondaBin` | WEAPONDA.bin |
| 0x08 | `sResourceFileNameMpegTab` | MPEG.tab | 0x35 | `sResourceFileNameVoxobjTab` | VOXOBJ.tab |
| 0x09 | `sResourceFileNameMpegBin` | MPEG.bin | 0x36 | `sResourceFileNameVoxobjBin` | VOXOBJ.bin |
| 0x0a | `sResourceFileNameMusicactBin` | MUSICACT.bin | 0x37 | `sResourceFileNameModlinesBin` | MODLINES.bin |
| 0x0b | `sResourceFileNameCamactioBin` | CAMACTIO.bin | 0x38 | `sResourceFileNameModlinesTab` | MODLINES.tab |
| 0x0c | `sResourceFileNameLactionsBin` | LACTIONS.bin | 0x39 | `sResourceFileNameSavegameBin` | SAVEGAME.bin |
| 0x0d | `sResourceFileNameAnimcurvBin` | ANIMCURV.bin | 0x3a | `sResourceFileNameSavegameTab` | SAVEGAME.tab |
| 0x0e | `sResourceFileNameAnimcurvTab` | ANIMCURV.tab | 0x3b | `sResourceFileNameObjseqBin` | OBJSEQ.bin |
| 0x0f | `sResourceFileNameObjseq2cTab` | OBJSEQ2C.tab | 0x3c | `sResourceFileNameObjseqTab` | OBJSEQ.tab |
| 0x10 | `sResourceFileNameFontsBin` | FONTS.bin | 0x3d | `sResourceFileNameObjectsTab` | OBJECTS.tab |
| 0x11/0x12 | `sResourceFileNameCachefonBin` (both slots) | CACHEFON.bin | 0x3e | `sResourceFileNameObjectsBin` | OBJECTS.bin |
| 0x13 | `sResourceFileNameGametextBin` | GAMETEXT.bin | 0x3f | `sResourceFileNameObjindexBin` | OBJINDEX.bin |
| 0x14 | `sResourceFileNameGametextTab` | GAMETEXT.tab | 0x40 | `sResourceFileNameObjeventBin` | OBJEVENT.bin |
| 0x15 | `sResourceFileNameGlobalmaBin` | globalma.bin | 0x41 | `sResourceFileNameObjhitsBin` | OBJHITS.bin |
| 0x16 | `sResourceFileNameTablesBin` | TABLES.bin | 0x42 | `sResourceFileNameDllsBin` | DLLS.bin |
| 0x17 | `sResourceFileNameTablesTab` | TABLES.tab | 0x43 | `sResourceFileNameDllsTab` | DLLS.tab |
| 0x18 | `sResourceFileNameScreensBin` | SCREENS.bin | 0x44 | `sResourceFileNameDllsimpoBin` | DLLSIMPO.bin |
| 0x19 | `sResourceFileNameScreensTab` | SCREENS.tab | 0x45 | `sResourceFileNameModelsTab` | MODELS.tab (2nd slot) |
| 0x1a | `sResourceFileNameVoxmapTab` | VOXMAP.tab | 0x46 | `sResourceFileNameModelsBin` | MODELS.bin (2nd slot) |
| 0x1b | `sResourceFileNameVoxmapBin` | VOXMAP.bin | 0x47 | `sResourceFileNameBlocksBin` | BLOCKS.bin (2nd slot) |
| 0x1c | `sResourceFileNameWarptabBin` | WARPTAB.bin | 0x48 | `sResourceFileNameBlocksTab` | BLOCKS.tab (2nd slot) |
| 0x1d | `sResourceFileNameMapsBin` | MAPS.bin | 0x49 | `sResourceFileNameAnimTab` | ANIM.TAB (2nd slot) |
| 0x1e | `sResourceFileNameMapsTab` | MAPS.tab | 0x4a | `sResourceFileNameAnimBin` | ANIM.BIN (2nd slot) |
| 0x1f | `sResourceFileNameMapinfoBin` | MAPINFO.bin | 0x4b | `sResourceFileNameTex1Bin` | TEX1.bin (2nd slot) |
| 0x20 | `sResourceFileNameTex1Bin` | TEX1.bin | 0x4c | `sResourceFileNameTex1Tab` | TEX1.tab (2nd slot) |
| 0x21 | `sResourceFileNameTex1Tab` | TEX1.tab | 0x4d | `sResourceFileNameTex0Bin` | TEX0.bin (2nd slot) |
| 0x22 | `sResourceFileNameTextableBin` | TEXTABLE.bin | 0x4e | `sResourceFileNameTex0Tab` | TEX0.tab (2nd slot) |
| 0x23 | `sResourceFileNameTex0Bin` | TEX0.bin | 0x4f | `sResourceFileNameTexpreBin` | TEXPRE.bin |
| 0x24 | `sResourceFileNameTex0Tab` | TEX0.tab | 0x50 | `sResourceFileNameTexpreTab` | TEXPRE.tab |
| 0x25 | `sResourceFileNameBlocksBin` | BLOCKS.bin | 0x51 | `sResourceFileNamePreanimBin` | PREANIM.bin |
| 0x26 | `sResourceFileNameBlocksTab` | BLOCKS.tab | 0x52 | `sResourceFileNamePreanimTab` | PREANIM.tab |
| 0x27 | `sResourceFileNameTrkblkTab` | TRKBLK.tab | 0x53 | `sResourceFileNameVoxmapTab` | VOXMAP.tab (2nd slot) |
| 0x28 | `sResourceFileNameHitsBin` | HITS.bin | 0x54 | `sResourceFileNameVoxmapBin` | VOXMAP.bin (2nd slot) |
| 0x29 | `sResourceFileNameHitsTab` | HITS.tab | 0x55 | `sResourceFileNameAnimcurvBin` | ANIMCURV.bin (2nd slot) |
| 0x2a | `sResourceFileNameModelsTab` | MODELS.tab | 0x56 | `sResourceFileNameAnimcurvTab` | ANIMCURV.tab (2nd slot) |
| 0x2b | `sResourceFileNameModelsBin` | MODELS.bin | 0x57 | `sResourceFileNameEnvfxactBin` | ENVFXACT.bin |
| 0x2c | `sResourceFileNameModelindBin` | MODELIND.bin | 0x58/0x59 | `sResourceFileNameNull` | (unused) |

`sResourceFileNameSfxTab`/`sResourceFileNameSfxBin` (0x02/0x03) are extern in this TU - their
string literals live in another (audio-side) source file, not found in `src/main/pi_dolphin.c`
itself.

The **2nd-slot** entries (0x45-0x56) exist because per-map resources are double-buffered so
two maps can be resident at once during a transition - this is exactly the wiki's "every map
has its own copy of every asset" note, generalized into a fixed dual-slot pool rather than
one-slot-per-map. This is implemented by `mapLoadDataFile(int mapId, int fileId)`, which
`switch`es on `fileId` with paired `case` labels (e.g. `case 0xd: case 0x55:` for
ANIMCURV.bin) and picks whichever of the two physical slots is free or already owns `mapId`.
The backing storage is `struct MldfTables` at `lbl_80345E10` (see the struct comment in
`pi_dolphin.c` for the full slot layout: `ids`, `sizes`, `ptrs`, `owners`, plus per-resource
merge buffers `mergeAnimCurv`/`mergeVoxMap`/`mergeBlocks`/`mergeTex1`/`mergeTex0`/`mergeAnim`/
`mergeModels`), and file-name formatting comes from `struct MldfNames` (per-map format strings
`fmtAnimCurvBin`, `fmtVoxmapBin`, `fmtModBin`, etc., built with `sMapFileNameTable[]` - the
117-map-name table also defined at the bottom of `pi_dolphin.c`).

Only 14 of the resource kinds actually get a dual slot in `mapLoadDataFile`
(ANIMCURV bin+tab, VOXMAP bin+tab, TEX1 bin+tab, TEX0 bin+tab, BLOCKS bin+tab, MODELS bin+tab,
ANIM bin+tab); MODELIND, OBJSEQ2C, OBJSEQ, TEXPRE, PREANIM and ENVFXACT are loaded through a
single slot each, consistent with those being smaller/one-shot files that don't need
transition double-buffering.

For **disc-root** (non-map) files, the simpler loaders `fileLoad(int id)`,
`fileLoadToBuffer(int id, void* buf)` and `fileLoadToBufferOffset(int id, void* buf, int
offset, int size)` (also in `pi_dolphin.c`) open `sResourceFileNameTable[id]` directly through
`DVDOpen`/`DVDRead` with no per-map pairing - this is the code that reads the "Data files in
the disc root" table. `src/main/gameloop.c` wraps these in an async `AssetReq`/`loadAsset`
request struct (`resourceId`, `dest`, `offset`, `argC` fields) for the game's asynchronous
streaming path.

Per-map compressed blocks (`modXX.zlb.bin`) are handled separately by
`piRomLoadSection(int romOffset, int mapIndex, int destBuf)`, which opens
`sMapFileNameTable[mapIndex]` via the `sRomlistZlbPathFormat` path format and parses the
16-byte `struct PackHeader` (`magic` 0xFACEFEED = zlb-packed / 0xE0E0E0E0 = stored raw,
`decompressedSize`, `auxSize`, `compressedSize`) - this is the "ZLB"/"DIR"-tagged
`struct ZlbHeader` format also defined in `pi_dolphin.c`.

### Per-file findings (fileId, consumer, and confirmed/refined format)

| Wiki file | fileId(s) | Consumer in this codebase | What we can add |
|---|---|---|---|
| ANIM.BIN/TAB | 0x30/0x2f (+0x4a/0x49) | `src/main/model.c` (`ObjModel_Load` / `modelLoadAnimations`) | animation data referenced from a model's `ModelFileHeader` |
| ANIMCURV.bin/tab | 0x0d/0x0e (+0x55/0x56) | `mapLoadDataFile`; consumed via `include/main/dll/rom_curve_interface.h` (`RomCurveDef`, `RomCurveWalker`) | matches wiki's `Scripting#ANIMCURV` link - our "rom curve" object-movement-path interface |
| modXX.zlb.bin/tab | n/a | `piRomLoadSection` + `struct PackHeader`/`struct ZlbHeader` | magic/size header fully decoded (see above) |
| MODELIND.bin | 0x2c | `src/main/model.c: ObjModel_Load` | `fileLoadToBufferOffset(0x2c, gModelResourceBuffer, idc*2, 8)`; word 0 of the 8-byte record is the resolved "real" model id used for the `MODELS.bin` lookup - directly confirms "maps model IDs to indices" |
| MODELS.bin/TAB | 0x2b/0x2a (+0x46/0x45) | `src/main/model.c`, `src/main/objprint_dolphin.c` | dual-slot per-map streaming (see above) |
| OBJSEQ2C.tab | 0x0f | table slot only | no consuming reader found in decompiled source yet |
| OBJSEQ.bin/tab | 0x3b/0x3c | table slot only for the *file*; the runtime bytecode interpreter is `include/main/objseq.h` (`struct ObjSeqState`, `ObjSeq_EvaluateCondition`) and `src/main/objseq.c` | the interpreter for the sequence bytecode is fully decompiled; the raw file-load call site by fileId wasn't found (may be behind an indirection not yet traced) |
| TEX0.bin/tab | 0x23/0x24 (+0x4d/0x4e) | `include/main/texture.h` (`textureLoad`/`textureFree`) | "environment" textures per wiki |
| TEX1.bin/tab | 0x20/0x21 (+0x4b/0x4c) | same texture system | "character" textures per wiki |
| VOXMAP.bin/tab | 0x1a/0x1b (+0x53/0x54) | `mapLoadDataFile` only (`voxMapReadCb`/`voxMapTabReadCb` externs) | consuming reader not found yet |
| AMAP.BIN/TAB | 0x32/0x31 | `src/main/model.c` | 0x31 (`AMAP.TAB`) is `gModelAnimOffsetTable`, a per-4-anim-group 0x20-byte offset block (`(id & ~3) << 2` stride); 0x32 (`AMAP.BIN`) backs `ModelFileHeader::animationDataSection`/`animationDataFileOffset` - refines the wiki's guess: the **.TAB is the id->offset index**, the **.BIN is the animation payload** it points into |
| BITTABLE.BIN | 0x33 | table slot only | `include/main/gamebits.h` defines the runtime `enum GameBitId` (symbolic ids for `mainGetBit`/`mainSetBits`) but does not itself parse this file - not found |
| CAMACTIO.bin | 0x0b | table slot only | not found |
| ENVFXACT.bin | 0x57 | table slot only | `src/main/dll/dll_011E_magiccavebottom.c` uses `envFxAct`/`EnvfxAct`-named locals, consistent with "weather effects", but the loader itself wasn't traced |
| globalma.bin | 0x15 | table slot only | not found |
| HITS.bin/tab | 0x28/0x29 | `src/main/track_dolphin.c` (`fileLoadToBufferOffset(0x28, ...)`) | confirms "related to map hit detection" |
| MAPINFO.bin | 0x1f | table slot only | no consumer found - consistent with wiki's "mostly unused in final version" |
| MAPS.bin/tab | 0x1d/0x1e | `src/main/shader.c` (0x1d) | 0x1e (`.tab`) consumer not found |
| MODANIM.BIN/TAB | 0x2e/0x2d | `src/main/model.c` | 0x2d (`.TAB`) is a per-model animation-header index (`id << 1` stride, 0x10-byte record); 0x2e (`.BIN`) backs `ModelFileHeader::animationHeaderBuffer` (a per-joint `s16` table per the header's own comment) |
| MODLINES.bin/tab | 0x37/0x38 | `src/main/object.c` | 0x38 (`.tab`) is an offset table (`idx << 2` stride, reads two adjacent `u32` offsets to derive size); 0x37 (`.bin`) records are 20 bytes each (`size / 20` count) |
| OBJECTS.bin/tab | 0x3e/0x3d | `src/main/object.c` (`gObjFileOffsetTable`) | 0x3d (`.tab`) is a `-1`-terminated `u32` offset array (`loadAssetFileById(&gObjFileOffsetTable, 0x3d)`), one offset per object-def id; per-object record format is further documented in `docs/dll_naming_manifest.md`: object name at def+0x91 (11-char fixed field), DLL id at def+0x50 |
| OBJEVENT.bin | 0x40 | `src/main/object.c` (`eventTable->entries`, `eventTable->byteCount`) | **actively used** - this contradicts the wiki's "may not be used" |
| OBJHITS.bin | 0x41 | `src/main/objHitReact.c` (`OBJHITREACT_ENTRY_TAB_FILE_ID` = 0x41, `include/main/objHitReact.h`) | confirms "sparse table": `ObjHitReact_LoadMoveEntries` walks a per-model `hitReactMoveTable` of `{moveId, s16 byteOffset, s16 byteCount}` triples and pulls the matching byte range out of OBJHITS.bin via `getTabEntry`/`fileLoadToBufferOffset` - i.e. sparse per-move hit-reaction data, indexed indirectly through the model's own move table rather than a flat index |
| OBJINDEX.bin | 0x3f | `src/main/object.c` (`gObjSeqToObjIdMax = (getDataFileSize(0x3f) >> 1) - 1`) | confirms 2-byte (`s16`) stride, i.e. an array of ids - matches "maps object IDs to indices" |
| PREANIM.BIN/TAB | 0x51/0x52 | `src/main/model.c` (0x52 read as a 4-byte `flags` value at `id << 2`) | partial format confirmation only |
| TABLES.bin/tab | 0x16/0x17 | table slot only | not found; wiki's waterfall-animation claim not independently re-verified here |
| TEXPRE.bin/tab | 0x4f/0x50 | table slot only | not found |
| TEXTABLE.bin | 0x22 | table slot only | not found |
| TRKBLK.tab | 0x27 | table slot only | not found (name suggests a relation to `src/main/track_dolphin.c`'s track-block system, not verified) |
| WARPTAB.bin | 0x1c | `src/main/rcp_dolphin.c` (`warpToMap`) | **fully confirmed format**: `getTabEntry(p, 28, idx << 4, 16)` - 16-byte records, decoded into `struct WarpDestination { f32 x, y, z; s16 angle0, angle1; }`; `include/main/gamebits.h`'s `GAMEBIT_MagicCaveExitWarp` comment independently calls out a "WARPTAB index" |
| WEAPONDA.bin | 0x34 | `src/main/object.c` (`weaponDaTable->entries`) | name match confirms "relates to staff animations" |
| FONTS.bin | 0x10 | table slot only | not found - consistent with wiki's "read but not used" |
| CACHEFON.bin | 0x11 and 0x12 | table slot only (both slots point at the *same* string, `"CACHEFON.bin"`) | the wiki lists two distinct always-empty files, `CACHEFONTSTAB.bin`/`CACHEFONTSTEX.bin`; our decompiled string is `CACHEFON.bin` (singular, no TAB/TEX suffix) for both slots - possibly a truncation or a genuinely different filename; not resolved here |
| GAMETEXT.bin/tab | 0x13/0x14 | table slot only | this is the wiki's *old, unused, root-only* copy; the actually-used per-map/per-sequence text lives under the `gametext/` directory and is loaded by `src/main/textrender.c` via `sGameTextMapPathFormat = "gametext/%s/%s.bin"` and `sGameTextSequencePathFormat = "gametext/Sequences/%d_%s.bin"` - two separate mechanisms, consistent with the wiki's root-vs-directory distinction |
| LACTIONS.bin | 0x0c | table slot only | not found; wiki's "0x28-byte entries, related to lights" not independently re-verified here |
| SAVEGAME.bin/tab | 0x39/0x3a | table slot only in `pi_dolphin.c` | `src/xref/packets/savegame.json` records a distinct path format string `"/savegame/save%d.bin"` (one function, not yet located/named) - consistent with wiki's "debug chapter select" guess |
| SCREENS.bin/tab | 0x18/0x19 | table slot only | not found |
| DLLS.bin/tab, DLLSIMPO.bin | 0x42/0x43/0x44 | table slots only | these are **not** the same file as the wiki's "Never accessed" root `DLLS.tab` (32 bytes / 4 entries, listed as an N64 leftover) - no direct evidence connects the two. Separately, the wiki's leftover entries **0x58 and 0xAB do exist** in this codebase as literal do-nothing DLL stubs: `src/main/dll/dll_0058_dummy58.c` ("a placeholder/no-op object DLL... exists to occupy its DLL id slot") and `src/main/dll/dll_00AB_projdummy.c` ("retired projectile object... no behaviour left"). DLL id `0xC3` was not found as a separate source file here |
| BLOCKS.bin/tab | 0x25/0x26 (+0x47/0x48) | dual-slotted in `mapLoadDataFile`, but no direct read call site found | consistent with the wiki's own note under `/[mapname]/BLOCKS.bin,tab` that the loader ignores this listed entry and loads `modXX.zlb.bin` instead - the slots exist in the table but appear otherwise dead |
| VOXOBJ.bin/tab | 0x35/0x36 | table slot only | not found - consistent with wiki's "empty file" |
| CHAPBITS.bin | n/a | **not found anywhere** in this codebase (no string, no fileId slot) | consistent with wiki's "never accessed" |
| splashScreen.bin, SPRITES.bin/tab, SPRTABLE.bin | n/a | not found | consistent with wiki's "never accessed" |

### Related structs/headers already in this codebase

- `include/main/objseq.h` - `struct ObjSeqState` (0x138 bytes), the runtime per-object sequence
  interpreter state (`curFrame`, `eventIds`, `cmds`, `trackRunLength`, etc.) - the consumer of
  whatever OBJSEQ.bin's bytecode format turns out to be; see also `include/main/objseq_control.h`.
- `include/main/objHitReact.h` - `struct ObjHitReactState`, `OBJHITREACT_ENTRY_TAB_FILE_ID`.
- `src/main/rcp_dolphin.c` - `struct WarpDestination { f32 x, y, z; s16 angle0, angle1; }`,
  the fully-confirmed 16-byte WARPTAB.bin record, read by `warpToMap()`.
- `include/main/model.h` - `struct ModelFileHeader`, the in-memory header of a loaded model
  (fields for `textureIds`, `vertices`, `normals`, `renderOps`, `collisionTriangles`,
  `collisionBlocks`, `animationModelPtrs`, `animationDataSection`, `animationHeaderBuffer`).
- `include/main/gamebits.h` - `enum GameBitId`, symbolic quest/story/event flag ids (relevant
  to BITTABLE.BIN's "table of GameBit offsets", though the header itself is runtime-only).
- `docs/dll_naming_manifest.md` - documents the OBJECTS.bin per-object-definition record
  layout (name field, DLL id field) used to recover canonical DLL source filenames.
- `src/main/dll/` - 729 `dll_XXXX_*.c` files, one per object-behaviour DLL id; this is the
  in-memory side of whatever DLLS.bin/DLLSIMPO.bin describe on disc.

## Ready-to-adopt code

Every `fileId` in the table below was verified against `sResourceFileNameTable` and/or an
actual `fileLoad*`/`mapLoadDataFile` call site in this codebase (see table above) - a
maintainer could lift this into `include/main/pi_dolphin.h` and replace the raw hex literals
at call sites (`model.c`, `object.c`, `track_dolphin.c`, `shader.c`, `rcp_dolphin.c`,
`objHitReact.c`, `pi_dolphin.c` itself) with named constants. `_A`/`_B` suffixes mark the two
physical slots of a dual-buffered per-map resource (see "The master file table" above).

```c
/* Resource fileIds indexed into sResourceFileNameTable[] / used by fileLoad(),
 * fileLoadToBuffer(), fileLoadToBufferOffset() and mapLoadDataFile(). */
enum MldfFileId {
    MLDF_FILEID_AUDIO_TAB       = 0x00, /* AUDIO.tab */
    MLDF_FILEID_AUDIO_BIN       = 0x01, /* AUDIO.bin */
    MLDF_FILEID_SFX_TAB         = 0x02, /* SFX.tab (string defined outside pi_dolphin.c) */
    MLDF_FILEID_SFX_BIN         = 0x03, /* SFX.bin */
    MLDF_FILEID_AMBIENT_TAB     = 0x04, /* AMBIENT.tab */
    MLDF_FILEID_AMBIENT_BIN     = 0x05, /* AMBIENT.bin */
    MLDF_FILEID_MUSIC_TAB       = 0x06, /* MUSIC.tab */
    MLDF_FILEID_MUSIC_BIN       = 0x07, /* MUSIC.bin */
    MLDF_FILEID_MPEG_TAB        = 0x08, /* MPEG.tab */
    MLDF_FILEID_MPEG_BIN        = 0x09, /* MPEG.bin */
    MLDF_FILEID_MUSICACT_BIN    = 0x0a, /* MUSICACT.bin */
    MLDF_FILEID_CAMACTIO_BIN    = 0x0b, /* CAMACTIO.bin */
    MLDF_FILEID_LACTIONS_BIN    = 0x0c, /* LACTIONS.bin */
    MLDF_FILEID_ANIMCURV_BIN_A  = 0x0d, /* ANIMCURV.bin, slot A */
    MLDF_FILEID_ANIMCURV_TAB_A  = 0x0e, /* ANIMCURV.tab, slot A */
    MLDF_FILEID_OBJSEQ2C_TAB    = 0x0f, /* OBJSEQ2C.tab */
    MLDF_FILEID_FONTS_BIN       = 0x10, /* FONTS.bin */
    MLDF_FILEID_CACHEFON_BIN_A  = 0x11, /* CACHEFON.bin, slot A */
    MLDF_FILEID_CACHEFON_BIN_B  = 0x12, /* CACHEFON.bin, slot B (dup) */
    MLDF_FILEID_GAMETEXT_BIN    = 0x13, /* GAMETEXT.bin (old/root copy) */
    MLDF_FILEID_GAMETEXT_TAB    = 0x14, /* GAMETEXT.tab (old/root copy) */
    MLDF_FILEID_GLOBALMA_BIN    = 0x15, /* globalma.bin */
    MLDF_FILEID_TABLES_BIN      = 0x16, /* TABLES.bin */
    MLDF_FILEID_TABLES_TAB      = 0x17, /* TABLES.tab */
    MLDF_FILEID_SCREENS_BIN     = 0x18, /* SCREENS.bin */
    MLDF_FILEID_SCREENS_TAB     = 0x19, /* SCREENS.tab */
    MLDF_FILEID_VOXMAP_TAB_A    = 0x1a, /* VOXMAP.tab, slot A */
    MLDF_FILEID_VOXMAP_BIN_A    = 0x1b, /* VOXMAP.bin, slot A */
    MLDF_FILEID_WARPTAB_BIN     = 0x1c, /* WARPTAB.bin - 16-byte WarpDestination records */
    MLDF_FILEID_MAPS_BIN        = 0x1d, /* MAPS.bin */
    MLDF_FILEID_MAPS_TAB        = 0x1e, /* MAPS.tab */
    MLDF_FILEID_MAPINFO_BIN     = 0x1f, /* MAPINFO.bin */
    MLDF_FILEID_TEX1_BIN_A      = 0x20, /* TEX1.bin, slot A */
    MLDF_FILEID_TEX1_TAB_A      = 0x21, /* TEX1.tab, slot A */
    MLDF_FILEID_TEXTABLE_BIN    = 0x22, /* TEXTABLE.bin */
    MLDF_FILEID_TEX0_BIN_A      = 0x23, /* TEX0.bin, slot A */
    MLDF_FILEID_TEX0_TAB_A      = 0x24, /* TEX0.tab, slot A */
    MLDF_FILEID_BLOCKS_BIN_A    = 0x25, /* BLOCKS.bin, slot A */
    MLDF_FILEID_BLOCKS_TAB_A    = 0x26, /* BLOCKS.tab, slot A */
    MLDF_FILEID_TRKBLK_TAB      = 0x27, /* TRKBLK.tab */
    MLDF_FILEID_HITS_BIN        = 0x28, /* HITS.bin */
    MLDF_FILEID_HITS_TAB        = 0x29, /* HITS.tab */
    MLDF_FILEID_MODELS_TAB_A    = 0x2a, /* MODELS.tab, slot A */
    MLDF_FILEID_MODELS_BIN_A    = 0x2b, /* MODELS.bin, slot A */
    MLDF_FILEID_MODELIND_BIN    = 0x2c, /* MODELIND.bin - model id -> index, 8-byte records */
    MLDF_FILEID_MODANIM_TAB     = 0x2d, /* MODANIM.TAB - per-model anim header index */
    MLDF_FILEID_MODANIM_BIN     = 0x2e, /* MODANIM.BIN - per-model anim header buffer */
    MLDF_FILEID_ANIM_TAB_A      = 0x2f, /* ANIM.TAB, slot A */
    MLDF_FILEID_ANIM_BIN_A      = 0x30, /* ANIM.BIN, slot A */
    MLDF_FILEID_AMAP_TAB        = 0x31, /* AMAP.TAB - anim id -> offset index */
    MLDF_FILEID_AMAP_BIN        = 0x32, /* AMAP.BIN - anim data payload */
    MLDF_FILEID_BITTABLE_BIN    = 0x33, /* BITTABLE.bin */
    MLDF_FILEID_WEAPONDA_BIN    = 0x34, /* WEAPONDA.bin - weaponDaTable entries */
    MLDF_FILEID_VOXOBJ_TAB      = 0x35, /* VOXOBJ.tab */
    MLDF_FILEID_VOXOBJ_BIN      = 0x36, /* VOXOBJ.bin */
    MLDF_FILEID_MODLINES_BIN    = 0x37, /* MODLINES.bin - 20-byte records */
    MLDF_FILEID_MODLINES_TAB    = 0x38, /* MODLINES.tab - u32 offset pairs */
    MLDF_FILEID_SAVEGAME_BIN    = 0x39, /* SAVEGAME.bin */
    MLDF_FILEID_SAVEGAME_TAB    = 0x3a, /* SAVEGAME.tab */
    MLDF_FILEID_OBJSEQ_BIN      = 0x3b, /* OBJSEQ.bin */
    MLDF_FILEID_OBJSEQ_TAB      = 0x3c, /* OBJSEQ.tab */
    MLDF_FILEID_OBJECTS_TAB     = 0x3d, /* OBJECTS.tab - -1-terminated u32 offsets */
    MLDF_FILEID_OBJECTS_BIN     = 0x3e, /* OBJECTS.bin - object definitions */
    MLDF_FILEID_OBJINDEX_BIN    = 0x3f, /* OBJINDEX.bin - s16 array */
    MLDF_FILEID_OBJEVENT_BIN    = 0x40, /* OBJEVENT.bin - eventTable entries (used) */
    MLDF_FILEID_OBJHITS_BIN     = 0x41, /* OBJHITS.bin - sparse per-move hit-reaction data */
    MLDF_FILEID_DLLS_BIN        = 0x42, /* DLLS.bin */
    MLDF_FILEID_DLLS_TAB        = 0x43, /* DLLS.tab */
    MLDF_FILEID_DLLSIMPO_BIN    = 0x44, /* DLLSIMPO.bin */
    MLDF_FILEID_MODELS_TAB_B    = 0x45, /* MODELS.tab, slot B */
    MLDF_FILEID_MODELS_BIN_B    = 0x46, /* MODELS.bin, slot B */
    MLDF_FILEID_BLOCKS_BIN_B    = 0x47, /* BLOCKS.bin, slot B */
    MLDF_FILEID_BLOCKS_TAB_B    = 0x48, /* BLOCKS.tab, slot B */
    MLDF_FILEID_ANIM_TAB_B      = 0x49, /* ANIM.TAB, slot B */
    MLDF_FILEID_ANIM_BIN_B      = 0x4a, /* ANIM.BIN, slot B */
    MLDF_FILEID_TEX1_BIN_B      = 0x4b, /* TEX1.bin, slot B */
    MLDF_FILEID_TEX1_TAB_B      = 0x4c, /* TEX1.tab, slot B */
    MLDF_FILEID_TEX0_BIN_B      = 0x4d, /* TEX0.bin, slot B */
    MLDF_FILEID_TEX0_TAB_B      = 0x4e, /* TEX0.tab, slot B */
    MLDF_FILEID_TEXPRE_BIN      = 0x4f, /* TEXPRE.bin */
    MLDF_FILEID_TEXPRE_TAB      = 0x50, /* TEXPRE.tab */
    MLDF_FILEID_PREANIM_BIN     = 0x51, /* PREANIM.bin */
    MLDF_FILEID_PREANIM_TAB     = 0x52, /* PREANIM.tab */
    MLDF_FILEID_VOXMAP_TAB_B    = 0x53, /* VOXMAP.tab, slot B */
    MLDF_FILEID_VOXMAP_BIN_B    = 0x54, /* VOXMAP.bin, slot B */
    MLDF_FILEID_ANIMCURV_BIN_B  = 0x55, /* ANIMCURV.bin, slot B */
    MLDF_FILEID_ANIMCURV_TAB_B  = 0x56, /* ANIMCURV.tab, slot B */
    MLDF_FILEID_ENVFXACT_BIN    = 0x57, /* ENVFXACT.bin */
    MLDF_FILEID_UNUSED_58       = 0x58, /* sResourceFileNameNull */
    MLDF_FILEID_UNUSED_59       = 0x59, /* sResourceFileNameNull */
};
```

Note: `WarpDestination` (the WARPTAB.bin 16-byte record: `f32 x,y,z; s16 angle0,angle1;`) is
**already implemented** in `src/main/rcp_dolphin.c` - it's listed under "Related
structs/headers" above, not repeated here since there's nothing left to adopt for it.
