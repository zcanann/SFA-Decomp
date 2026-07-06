# Common File Formats

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Formats). Reverse-engineering notes; not independently verified here.

Most SFA data blobs can be identified by a four-byte magic/signature at offset 0.

## E0E0E0E0

Header for some non-compressed data.

| Offset | Type  | Description |
|--------|-------|--------------|
| 000000 | u8[4] | Signature: `0xE0, 0xE0, 0xE0, 0xE0` |
| 000004 | u32   | Length of data, in bytes |
| 000008 | u32   | Offset of data (add 0x18 to this value) |
| 00000C | ?     | Presumably extra metadata goes here? |

Followed by uncompressed data of any format.

## F0F0F0F0

Similar to `E0E0E0E0`, but for compressed data. Not sure if this is used in the final version.

| Offset | Type  | Description |
|--------|-------|--------------|
| 000000 | u8[4] | Signature: `0xF0, 0xF0, 0xF0, 0xF0` |
| 000004 | u32   | Length of decompressed data, in bytes |
| 000008 | u32   | Offset of data (add 0x28, **not** 0x18, to this value) |
| 00000C | u32   | Length of compressed data, in bytes |
| 000010 | ?     | Presumably extra metadata goes here? |

In `default.dol`, what follows is expected to be LZO-compressed.

## FACEFEED

Header for some formats (mainly models) that allows context-specific extra data to be added.

| Offset | Type  | Description |
|--------|-------|--------------|
| 000000 | u8[4] | Signature: `0xFA, 0xCE, 0xFE, 0xED` |
| 000004 | u32   | Length of uncompressed data, in bytes |
| 000008 | u32   | Offset of ZLB data (skips header) |
| 00000C | u32   | Length of compressed data, in bytes |
| 000010 | ?     | Zero or more words, whose count is in field 0x8, including the ZLB header |

Full header size = `(offset - 3) * 4`, where `offset` is field 0x8. Often, what follows is a ZLB
header, or an `0xE0E0E0E0` signature.

## LZO

Unknown compressed-data format. Expected by `default.dol`, but no files are available in this
format in the retail disc image. Seems to be simpler than ZLB.

## TAB

Table file. These don't have a specific format or signature, but most are one of three types:

- An array of `u32` offsets. In some cases the actual offset is this value times 2 or 4.
- An array of `u32` offsets in which the high bits have special meaning:
  - Usually `0x10` means load from this map, `0x20` means load from the other loaded map (??? why?),
    `0x00` means don't load this (i.e. the asset isn't present in this map), and the other bits are
    ignored.
  - For textures, `0x80` and `0x40` tell which map to load for/from, and the remaining 6 bits are a
    count telling how many mipmaps and/or animation frames the texture has.
- An array of `u16` offsets or indices. Usually these map IDs to indices into a table file; e.g.
  `MODELIND.bin` is an array of indices into `MODELS.tab`, with each element corresponding to a
  model ID.

## ZLB

Standard `zlib`-deflated data.

| Offset | Type  | Description |
|--------|-------|--------------|
| 000000 | u8[4] | Signature: `0x5A, 0x4C, 0x42, 0x00` (ASCII `ZLB\0`) |
| 000004 | u32   | Version (always 1) |
| 000008 | u32   | Length of uncompressed data, in bytes |
| 00000C | u32   | Length of compressed data, in bytes |
| 000010 | -     | Compressed data |

The Python `zlib` module (or any ordinary zlib implementation) can read and write this format. The
game appears to compress with `level=9, wbits=13`, but can decompress data produced with any
parameters.

### DIR

"Direct", i.e. uncompressed data. Used in place of ZLB when compression is unhelpful (e.g. for
already-compressed texture formats). Signature is `DIR\0` or `DIRn`. Only supported for certain
asset types (maybe only textures?). The header is the same nominal format as ZLB; the two length
fields should be the same, though the game only appears to check the latter field.

## In this codebase

All of the concrete matches below are from `src/main/pi_dolphin.c` (the disc/ROM resource loader)
and `src/main/rcp_dolphin.c` (texture bank resolution), which together are this repo's
implementation of the loader the wiki page above describes.

### `PackHeader` == `E0E0E0E0` / `FACEFEED`

`src/main/pi_dolphin.c:160` defines a local struct matching the wiki's `E0E0E0E0`/`FACEFEED`
layout, used for both magics through one accessor:

```c
struct PackHeader
{
    u32 magic;            /* 0xFACEFEED = zlb-packed, 0xE0E0E0E0 = stored raw */
    int decompressedSize; /* +0x04 */
    int auxSize;          /* +0x08: extra bytes between header and payload */
    int compressedSize;   /* +0x0c */
};
```

- `loadAndDecompressDataFile` (`.text:0x800464C8`, `pi_dolphin.c:2589`), case `fileId == 0x2b || 0x46`
  — both of which resolve (via `sResourceFileNameTable`) to **`MODELS.bin`** — reads `hdr->magic`:
  - `0xe0e0e0e0`: `memcpy`'s `decompressedSize` bytes starting at `hdr + auxSize + 0x18`. This
    matches the wiki's "add 0x18" rule for `E0E0E0E0` exactly (`PackHeader` is 0x10 bytes;
    `auxSize` is the wiki's field-0x8 "offset of data", and the constant differs from 0x10 by the
    extra 8 bytes the wiki's table doesn't account for).
  - `0xfacefeed`: calls `zlbDecompress` on data starting at `hdr + auxSize + 0x28` (`compressedSize
    - 0x10`, i.e. the block's own compressed-size field already includes a nested 16-byte ZLB
    header that gets stripped) — the extra `0x10` versus the raw-data case is exactly the size of
    a ZLB header, confirming the wiki's "what follows is a ZLB header" note for `FACEFEED`.
  - This confirms the wiki's parenthetical "(mainly models)" for `FACEFEED` — in this codebase it's
    used, at minimum, for `MODELS.bin` records.
- `piRomLoadSection` (`.text:0x80048328`, `pi_dolphin.c:2713`) reads a `PackHeader` at
  `lbl_8035F3E8[0x1d] + romOffset` — `lbl_8035F3E8` is the loader's `ptrs[]` table and index
  `0x1d` (29) is **`MAPS.bin`** in `sResourceFileNameTable` — matching the existing source comment
  "header of a packed rom section (romlist blocks, MAPS.BIN sections)". Only the `0xfacefeed` case
  is handled here (raw `0xe0e0e0e0` romlist sections are apparently not exercised by this call
  site).

### `ZlbHeader` == `ZLB` / `DIR`

`src/main/pi_dolphin.c:146`:

```c
struct ZlbHeader
{
    char tag[4];          /* "ZLB" (sZlbBlockTag) / "DIR" (sDirBlockTag) */
    u32 unk4;
    u32 decompressedSize; /* +0x08 */
    int compressedSize;   /* +0x0c */
};
```

Field-for-field identical to the wiki's ZLB table (`tag`, version/`unk4`, `decompressedSize`,
`compressedSize`). `unk4` ("version") is never read anywhere in this file — consistent with the
wiki's "always 1, but the game doesn't seem to check it" framing.

- `sZlbBlockTag` / `sDirBlockTag` are real symbols: `config/GSAE01/symbols.txt:12861-12862`,
  `.sdata:0x803DB5C0` / `.sdata:0x803DB5C4`, each `size:0x4 data:string` — i.e. exactly the 4-byte
  tag strings (`"ZLB\0"`, `"DIR\0"`) the wiki describes. Every check in this file does
  `strncmp(..., 3)`, matching the wiki's note that the signature is only the first 3 bytes
  (`"ZLB"`/`"DIR"`) and the 4th byte can vary (`"DIRn"`).
- Every `strncmp(..., &sZlbBlockTag, 3)` hit in `loadAndDecompressDataFile` decompresses starting
  at `fileBuf + 0x10` — the wiki's fixed 16-byte ZLB header — into `zlbDecompress`.
- The wiki's open question "Only supported for certain types of assets (maybe only textures?)" for
  `DIR` is answered by this file: the only `fileId`s whose case bodies check `sDirBlockTag` at all
  are `0x20`/`0x4b` and `0x4f`, which resolve via `sResourceFileNameTable` to **`TEX1.bin`** and
  **`TEXPRE.bin`** respectively — textures, exactly as guessed. (`TEX0.bin`, case `fileId ==
  0x23 || 0x4d`, only ever checks the ZLB path — no `DIR` fast path for that bank in this
  function.)
  - Oddity worth flagging for a future reader: the `DIR` branch for those two cases returns
    `MLDF_QPTR + (entryIndex + 0x20)` (skips 32 bytes past the tag), not the generic 16-byte ZLB
    header size used everywhere else in the same function — texture `DIR` records apparently carry
    an additional embedded (texture-format) sub-header the generic wiki description doesn't cover.

### `zlbDecompress` — the actual inflate

`zlbDecompress` (`.text:0x8004B658`, `pi_dolphin.c:7131`) is a hand-rolled DEFLATE decoder (bit
readers `ZROT1`/`ZROT8`/`ZGB8`/`ZGB16`, Huffman length/dist tables). It starts reading from
`srcv + 2`, skipping a 2-byte zlib stream header — consistent with the wiki's note that the
payload is standard zlib/DEFLATE data (the surrounding 16-byte `ZlbHeader`/`PackHeader` is
game-specific framing, not part of the zlib stream itself).

### TAB high-bit convention — `loadAndDecompressDataFile`

The wiki's generic "0x10 = this map, 0x20 = other map" TAB high-bit rule is exactly what
`loadAndDecompressDataFile` (`.text:0x800464C8`, `pi_dolphin.c:1489`) implements per `fileId`, e.g.
case `0xd` (ANIMCURV):

```c
if ((entryIndex & 0x20000000) == 0 && (entryIndex & 0x10000000) == 0)
    tab0 = MLDF_PTR(0xe);
if ((entryIndex & 0x80000000) == 0 && (entryIndex & 0x40000000) == 0)
    tab1 = MLDF_PTR(0x56);
hiSel = offsetFlags & 0x80000000;
...
offsetFlags = offsetFlags & 0xfffffff;   /* mask the flag bits back off before indexing */
```

Every case in this ~0x1CE8-byte function repeats the same shape at a different bit position
(`0x1000000`/`0x2000000`/`0x4000000`/`0x8000000` for the `0x1b` VOXMAP case, etc.) — one pair of
high bits selects which of the two map-owned TAB slots (primary/alternate) to read from, then masks
itself off the low offset before indexing the table. This is the concrete, per-resource-type
version of the wiki's generic TAB high-bit paragraph.

### Texture TAB entries — `0x80`/`0x40` + 6-bit count

`rcp_dolphin.c:2459-2460` is the literal match for the wiki's texture TAB paragraph:

```c
bankWord = gRcpTexBankTable[bank][id16];
mips = (bankWord >> 24) & 0x3f;
```

`bankWord` is one `u32` TAB entry from a texture bank (`TEX0.tab`/`TEX1.tab`/`TEXPRE.tab`, selected
by `bank`); bits 31/30 (`0x80000000`/`0x40000000`) select the source map (see
`mergeTableFiles`, `objprint_dolphin.c:4040`, which ORs in `0x40000000` when copying a cross-map
entry), and `(bankWord >> 24) & 0x3f` is exactly the wiki's "remaining 6 bits are a count" of
mipmaps/animation frames — passed as the `mips` parameter to `tex0GetFrame`/`tex1GetFrame`/
`texPreGetMipmap`.

### `mergeTableFiles` — the paired-slot TAB merge

`mergeTableFiles` (`.text:0x80043CE8`, defined at `objprint_dolphin.c:4040`, also referenced from
`pi_dolphin.c`) merges the "primary" and "alternate" map's TAB tables into one working table per
resource kind (`mergeAnimCurv`, `mergeVoxMap`, `mergeBlocks`, `mergeTex1`, `mergeTex0`, `mergeAnim`,
`mergeModels` fields of `struct MldfTables`, `pi_dolphin.c:99`), entry count matching the wiki's
"array of u32 offsets" TAB description (0x800/0x1000/0x1fd0/3000 entries per table, matching known
per-map asset counts).

### Resource file-name table == which `.tab`/`.bin` pair a `fileId` means

`sResourceFileNameTable[90]` (`pi_dolphin.c:7680`) is the master `fileId -> filename` table walked
by nearly every case above; e.g. index `0x1d` = `MAPS.bin`, `0x20`/`0x4b` = `TEX1.bin`, `0x23`/`0x4d`
= `TEX0.bin`, `0x2b`/`0x46` = `MODELS.bin`, `0x4f` = `TEXPRE.bin`, `0x42` = `DLLS.bin`, `0x43` =
`DLLS.tab`. The full list of `.tab`/`.bin` archive names referenced in this codebase
(all defined as string literals around `pi_dolphin.c:7954-8023`):

`AUDIO`, `SFX`, `AMBIENT`, `MUSIC`, `MPEG`, `MUSICACT`, `CAMACTIO`, `LACTIONS`, `ANIMCURV`,
`OBJSEQ2C`, `FONTS`, `CACHEFON`, `GAMETEXT`, `globalma`, `TABLES`, `SCREENS`, `VOXMAP`, `WARPTAB`,
`MAPS`, `MAPINFO`, `TEX1`, `TEXTABLE`, `TEX0`, `BLOCKS`, `TRKBLK`, `HITS`, `MODELS`, `MODELIND`,
`MODANIM`, `ANIM`, `AMAP`, `BITTABLE`, `WEAPONDA`, `VOXOBJ`, `MODLINES`, `SAVEGAME`, `OBJSEQ`,
`OBJECTS`, `OBJINDEX`, `OBJEVENT`, `OBJHITS`, `DLLS`, `DLLSIMPO`, `TEXPRE`, `PREANIM`, `ENVFXACT`.

This matches the wiki's `MODELIND.bin`/`MODELS.tab` example verbatim (`MODELIND.bin` at table index
0x2c, `MODELS.tab` at index 0x2a) and confirms `DLLS.tab`/`DLLS.bin` (index 0x42/0x43) as the
archive backing this repo's `include/main/dll/dll_XXXX_*.h` / `src/main/dll/*.c` per-object-script
DLLs (see `docs/dll_naming_manifest.md` for the DLL-id naming campaign; that's a separate topic
from this wiki page).

### FACEFEED as a heap-tag — not the same use

`fileio.c:170` (`loadFileByPathAsync`) calls `mmAlloc(0x3c, 0xFACEFEED, NULL)`. This `0xFACEFEED` is
an **`mmAlloc` block-owner tag** (the SDK/engine convention of tagging heap allocations with a
memorable hex word — compare `0x7d7d7d7d`, `0x7f7f7fff` used elsewhere in the same file for other
allocations), unrelated to the `FACEFEED` file-format magic above; flagging so it isn't confused
with a format hit when grepping.

### LZO — not found

No `LZO` string, symbol, or decompressor call was found anywhere in `src/` or `include/`. This is
consistent with the wiki's own note that "no files are available in this format" in the retail
data — there'd be nothing here to decompile.

## Ready-to-adopt code

Nothing here is currently missing as a *named* type in the codebase in a way that would change
behavior — `PackHeader` and `struct ZlbHeader` already exist (file-local to `pi_dolphin.c`) with
accurate field comments. The one gap is the texture TAB bank-word encoding
(`rcp_dolphin.c:2459-2460`), which is currently three raw shift/mask expressions with no named
constants. A maintainer could lift this into `include/main/rcp_dolphin.h` or
`include/main/tex_dolphin.h`:

```c
/* TEX0.tab/TEX1.tab/TEXPRE.tab entry (bankWord in rcp_dolphin.c) */
#define TEX_TAB_MAP_A       0x80000000u /* wiki: "0x80" high bit, source-map select */
#define TEX_TAB_MAP_B       0x40000000u /* wiki: "0x40" high bit, source-map select */
#define TEX_TAB_MIP_COUNT_SHIFT 24
#define TEX_TAB_MIP_COUNT_MASK  0x3f    /* mipmap/animation-frame count, 6 bits */
#define TEX_TAB_OFFSET_MASK     0x00ffffffu
```

and the generic paired-slot TAB high bits used throughout `loadAndDecompressDataFile`
(`pi_dolphin.c`), which repeat per-resource-type at different bit offsets and are currently bare
hex literals (`0x10000000`/`0x20000000`, `0x1000000`/`0x2000000`, etc.) — not consolidated into one
enum here since each resource type occupies a different bit pair and a single shared enum would
obscure that rather than clarify it.
