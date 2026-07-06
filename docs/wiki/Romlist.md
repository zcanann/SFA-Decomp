# Romlist

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Romlist). Reverse-engineering notes; not independently verified here.

Each map has a `[mapname].romlist.zlb` file in the root of the disc. This file is a
[ZLB](Formats.md#zlb)-compressed list of objects on the map.

## Entry format

Entries in this list are variable length, following this format:

| Offset | Type   | Name      | Description |
|--------|--------|-----------|--------------|
| 000000 | s16    | type      | Object type (`ObjDef`) |
| 000002 | u8     | size      | Entry length in (4-byte) words |
| 000003 | u8     | acts0     | Bitmask of map acts to load in |
| 000004 | u8     | loadFlags | Loading flags |
| 000005 | u8     | acts1     | Bitmask of map acts to load in |
| 000006 | u8     | bound     | Load if distance to player is less than `bound * 8` |
| 000007 | u8     | cullDist  | Cull object when distance to player is less than `cullDist * 8` |
| 000008 | vec3f  | position  | Object position |
| 000014 | u32    | id        | Unique ID |
| 000018 | varies | -         | Parameters depending on object type |

(The wiki's own aside — "is it `cullDist * 8` or `* 80`?" — is resolved by this codebase: it's `* 8`.
See [In this codebase](#in-this-codebase) below.)

The object type is translated:
- If it's positive, the corresponding entry in `OBJINDEX.bin` (which is simply an array of `s16`) is
  used.
- Otherwise, the absolute value is used.

The resulting ID is an index into `OBJECTS.tab`, which gives the offset in `OBJECTS.bin` of the
`ObjectFileStruct`.

(Why are these in the disc root, instead of the map directory? No idea.)

The unique ID is used to persist the object in the save file. The coordinates of up to 63 objects can
be saved using this ID. This ID is also used to look up the object in scripting. Every object in the
romlist files has a unique ID. (Exception: multiple objects in unused maps have the ID `0xC5D`.)
Dynamically created objects have ID `0xFFFFFFFF`.

Each bit of `acts0` and `acts1` corresponds to an act number:

| Bit   | Act 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|-------|-------|---|---|---|---|---|---|---|---|----|----|----|----|----|----|
| acts0 | 01    |02 |04 |08 |10 |20 |40 |80 |   |    |    |    |    |    |    |
| acts1 |       |   |   |   |   |   |   |   |80 |40  |20  |10  |08  |04  |02  |

- If the given bit is *not* set, the object will load in this act.
- The lowest bit of `acts1` appears to be unused.
- Act 0 loads *all* objects.
- Act -1 loads no objects, but since the act number ranges from 0 to 15, this is impossible.
- Some object types might be using these fields for some other purpose, since they seem to have
  arbitrary, strange values here, and `loadFlags` allow bypassing this system. (**Confirmed** — see
  `loadCharacter`'s reuse of byte offset 5 below.)

LoadFlags:

| Flag | Name                  | Description |
|------|-----------------------|--------------|
| 0x01 | isLevelObject         | Load if act bits allow |
| 0x02 | isManualLoad          | Always load - used for dynamically created objects |
| 0x04 | OnlyLoadIfNearPlayer  | Use `bound` |
| 0x08 | ?                     | ? |
| 0x10 | loadForOtherMap       | Load for a different map ID |
| 0x20 | isBlockObject         | Load regardless of position |
| 0x40 | ?                     | ? |
| 0x80 | ?                     | ? |

(Names are inferred from debug messages.)

Refer to
[dlls.xml](https://github.com/RenaKunisaki/StarFoxAdventures/blob/master/browser/data/U0/dlls.xml)
for object-specific parameters. (Warning: very large file.)

## OBJINDEX.bin

An array of one `s16` per object ID. This maps the IDs given in `romlist` files to indices into
`OBJECTS.bin`. Unused entries map to `-1`.

A `romlist` can use negative object IDs to bypass this mapping. (This is not a bug; the game
explicitly checks for this case. This applies to most such index mapping, not only objects.)

It's not clear why this mapping is done. It makes sense for other assets such as models, where each
map has its own copy (the mapping tells which asset ID is at which entry in the map's file); perhaps
at one time, each map had a copy of `OBJECTS.bin` as well?

## In this codebase

Every concrete piece of this page is matched, and the match is unusually tight: `LoadedObj.data`
(the field the disc entry pointer is stored through, `src/main/object.c:1096`) sits at struct offset
`0x4C`, and `ObjAnimComponent.placementData` is independently asserted to be at offset `0x4C`
(`include/main/objanim_internal.h:567`). Since `loadCharacter`'s local `tmpl` is `memcpy`'d whole
into the live object (`memcpy(obj, &tmpl, 0x10c)`, `object.c:1303`), **`anim.placementData` is the
raw romlist-entry pointer itself**, verbatim, still pointing at the disc-format bytes described above.
That one fact is what ties every match below together.

### Loading the file: `piRomLoadSection`

`src/main/pi_dolphin.c:2713` (`piRomLoadSection`, `.text:0x80048328`) builds the path with
`sprintf(buf, sRomlistZlbPathFormat, sMapFileNameTable[mapIndex])` and `DVDOpen`s it — this is the
`[mapname].romlist.zlb` file the wiki describes, opened from the disc root as stated. `sRomlistZlbPathFormat`
itself (`.data:0x802CC524`) is currently only `extern`-declared (`pi_dolphin.c:43`); its literal
`"%s.romlist.zlb"`-shaped format string has not been placed in source yet.

`mapGetRomListAndOffsets` (`shader.c:937`, `.text:0x80059EE0`) reads the per-map `OBJECTS`-style tab
entry (`lbl_803DCE7C`, 7 words/map), calls `mapsBinGetRomlistSize`, `mmAlloc`s a buffer sized from it,
and calls `piRomLoadSection` to fill it — this is the "each map has its own romlist" load path.
`mapProcessRomList` (`shader.c:853`, `.text:0x80059CB0`) is the per-map-event slot manager around it
(`gShaderRomListSlots`, `gShaderRomListSlotCount` — `.bss:0x8038224C`/`.sbss:0x803DCDEC`), and pumps
`isRomListLoading()`/`loadDataFiles()` while the DVD read is in flight.

Loaded pages are kept in `gLoadedRomListPages` (`.bss:0x80386468`, size `0x1E0` = 120 × 4-byte
pointers), exposed via `RomList_GetLoadedPages` (`lightmap.c:519`, `.text:0x8005AFA0`).
`mapRomListFindItem` (`lightmap.c:825`, `.text:0x8005B490`) linearly scans all 120 pages, walking
each page's entries by `size` (byte `+2`, `<<2` = words→bytes, exactly the wiki's "size: entry length
in 4-byte words") and comparing the **unique ID at `+0x14`** against a needle — this is precisely
"this ID is also used to look up the object in scripting."  Two call sites confirm the "look up by
unique ID" usage described in the wiki:
- `src/main/dll/dll_0243_dbholecontrol1.c:161`: `mapRomListFindItem(0x4658A, 0, 0, 0, 0)` — a DLL
  looking up one specific, hard-coded map object by its unique romlist ID to spawn a copy of it.
- `src/main/dll/dll_0255_snowbike.c:231`: looks up an ID from `gSnowBikeMountRomListTable` and, on
  success, reads the found entry's `+0x8/+0xc/+0x10` as `x/y/z` (`snowbike.c:236-238`) — the position
  vec3f at offset 8, exactly as the wiki's table says.

### The 0x18-byte common header

Three independently-named structs in this codebase all describe the same 0x18-byte header, and they
agree on every field:

- `include/main/obj_placement.h` — `ObjPlacement` (the struct carried at `anim.placementData`,
  confirmed above to be the raw entry). Its fields line up byte-for-byte with the wiki table:
  `unk00`/`unk02` (2+2 bytes, offset 0) = `type`+`size`+`acts0` merged as a 2+2 read; `color[4]`
  (offset 4) = `loadFlags`+`acts1`+`bound`+`cullDist` merged as a 4-byte read; `posX/Y/Z` (offset 8) =
  `position`; `mapId` (offset `0x14`, `s32`) = the wiki's `id`. The header's own comment already flags
  offset 0-3 as "CLASS-DEPENDENT" — i.e. once the loader has consumed `type`/`size`/`acts0`/`loadFlags`
  for its own purposes, individual object classes are free to re-read those same bytes for a
  completely different, class-specific meaning. `include/main/worldobj.h`'s `WorldObjSetup.objectId`
  (`s16`, offset 0) is one instance of this: for that class the wiki's own `type` field doubles as a
  per-instance variant ID (plausible here since each world-map icon is plausibly its own `OBJECTS.bin`
  type sharing one DLL).
- `src/main/dll/dll_0017_savegame.c:151` — `SaveGameRomListPosition` (`pad0[8]`, then `x/y/z` at
  `0x8/0xc/0x10`, then `objectId` `u32` at `0x14`) is the *most literal* transcription of the wiki
  header of anything in the repo — right down to the name. It's used by
  `saveGame_restoreObjectPosToRomList` (`.text:0x800E8100`) and `saveGame_unsaveObjectPos`
  (`.text:0x800E8168`), both reading/writing `SAVEGAME_OBJECT_POSITION_COUNT` (`= 0x3f = 63`,
  `dll_0017_savegame.c:112`) slots keyed by that `objectId` — this is an exact, numeric confirmation
  of the wiki's "the coordinates of up to 63 objects can be saved using this ID."
- `src/main/objlib.c:54` — `ObjLibRegionEntry`/`ObjLibRegionList` (used by
  `ObjHitRegion_FindContainingId`, `.text:0x800386BC`) is a concrete *custom* per-type entry: `type`
  (`s16`, `OBJHITREGION_ROM_ENTRY_TYPE` = `0x130`), `wordCount` (`u8`, = the wiki's `size`), then 5
  bytes of padding to reach `x/y/z` at offset 8 — matching the common header up through `position` —
  and its own `id` (a `u16`, at offset `0x18`, i.e. inside the wiki's "varies" region, not the
  header's `u32` unique ID at `0x14`). `OBJLIB_PRIMARY_ROM_PAGE_COUNT` (`0x50` = 80) is the boundary
  `mapRomListFindItem` also uses (`outer >= 0x50`) to flag a page as belonging to the "last"/extra set
  of loaded pages.

### Act/LoadFlags bits: `objShouldLoad`

`objShouldLoad` (`src/main/shader.c:42`, `.text:0x80055980`) is the load-decision function, and it
implements the wiki's bit tables exactly, reading straight off an `int obj` pointer that is the raw
entry (not yet `anim.placementData` — this runs before the object exists):

- `t == -1` → don't load (wiki: "Act -1 loads no objects").
- `t == 0` → load unconditionally (wiki: "Act 0 loads all objects").
- `1 <= t <= 8` → tests `(*(u8*)(obj+3) >> (t-1)) & 1` — byte `+3` is `acts0`; bit `(t-1)` for act
  `t` matches the wiki table (`act1`→bit0/`0x01` … `act8`→bit7/`0x80`) exactly.
- `9 <= t <= 15` → tests `(*(u8*)(obj+5) >> (16-t)) & 1` — byte `+5` is `acts1`; bit `(16-t)` for act
  `t` matches the wiki table (`act9`→bit7/`0x80` … `act15`→bit1/`0x02`) exactly, and bit 0 is indeed
  never tested (the wiki's "lowest bit of acts1 appears to be unused").
- `*(u8*)(obj+4) & 0x01` (`isLevelObject`) → load.
- `*(u8*)(obj+4) & 0x02` (`isManualLoad`) → **don't** auto-load here (consistent with the wiki: these
  are "used for dynamically created objects," i.e. spawned explicitly elsewhere — e.g. exactly the
  `mapRomListFindItem` + manual-alloc pattern in `dll_0243_dbholecontrol1.c` above — rather than by
  this per-frame act scan).
- `*(u8*)(obj+4) & 0x20` (`isBlockObject`) → load unconditionally, before the position check (wiki:
  "load regardless of position").
- `*(u8*)(obj+4) & 0x04` (`OnlyLoadIfNearPlayer`) gates a distance check against
  `range = (*(u8*)(obj+6) << 3)` — byte `+6` is `bound`, and `<< 3` is `* 8`, confirming the wiki's
  `bound * 8` load-radius rule.
- Flags `0x08`, `0x10` (`loadForOtherMap`), `0x40`, `0x80` are **not found** in `objShouldLoad` — not
  handled by this function (`loadForOtherMap` is presumably resolved earlier, when selecting which
  map-event group's list to scan at all).

`cullDist` (byte `+7`) is not read here at all — it's a separate, purely-visual culling radius,
confirmed in `loadCharacter` below, also `* 8`.

### `loadCharacter`: reading the entry to spawn the object

`loadCharacter` (`src/main/object.c:1137`, `.text:0x8002D55C`) takes `s16* data` — the raw entry — and:
- `seq = *data` is the wiki's `type` field. `id = flags&2 ? seq : gObjSeqToObjIdTable[seq]` is exactly
  the wiki's type-translation rule (translate through `OBJINDEX.bin`, unless a flag says bypass —
  the sign check the wiki describes is evidently done by the caller, which sets this flag and passes
  the absolute value when `type` was negative).
- `tmpl.x/y/z = *(f32*)(data+4/6/8)` — since `data` is `s16*`, this is byte offset `8/0xc/0x10`: the
  `position` field.
- `tmpl.f3c = (u8)data[6] << 3` and `tmpl.f40 = (u8)data[7] << 3` — bytes `+6`/`+7` (`bound`,
  `cullDist`) both scaled by `<< 3` (`* 8`). This is the direct, numeric confirmation that the wiki's
  "(XXX is it `cullDist * 8` or was that a typo for `* 80`?)" should read `* 8` — the same shift is
  applied to `bound`, which the wiki is already confident is `* 8`, and both come from the identical
  code shape here.
- `n = ((u8*)data)[5] & 0x18) >> 3` reads byte `+5` — the wiki's `acts1` — but as an indexed-model
  selector (`tmpl.ff2`), completely unrelated to load-act bits. This is a direct, concrete instance of
  the wiki's own caveat: "some object types might be using these fields for some other purpose... and
  LoadFlags allow bypassing this system" (here, `isManualLoad`-spawned/`ObjSeq`-driven objects reuse
  the byte for model selection since the act-bit system doesn't apply to them).
- `tmpl.data = data` is stored at `LoadedObj` offset `0x4C` — see the opening paragraph: this becomes
  `anim.placementData`.

### `OBJECTS.tab` / `OBJECTS.bin` / `OBJINDEX.bin`

`Obj_InitObjectSystem` (`object.c:2373`, `.text:0x8002E994`) loads, by numeric file ID (see
`sResourceFileNameTable`, `pi_dolphin.c:7680`, a 90-entry table of DVD filenames):

| File ID | Filename        | Loaded into            | Wiki role |
|---------|------------------|-------------------------|-----------|
| `0x3d`  | `OBJECTS.tab`    | `gObjFileOffsetTable`   | Offsets into `OBJECTS.bin`, `s32`-terminated by `-1` |
| `0x3e`  | `OBJECTS.bin`    | (streamed per-id by `loadObjectFile`) | The `ObjectFileStruct` blobs themselves |
| `0x3f`  | `OBJINDEX.bin`   | `gObjSeqToObjIdTable`   | "An array of one `s16` per object ID" |

`gObjSeqToObjIdMax` is computed as `(getDataFileSize(0x3f) >> 1) - 1` — i.e. file size in bytes ÷ 2,
because each entry is one `s16` — matching the wiki's description of `OBJINDEX.bin` exactly.
`loadObjectFile` (`object.c:2423`, `.text:0x8002C450`) then does `base = offsets[id]; size =
offsets[id+1] - base;` and `fileLoadToBufferOffset(0x3e, buf, base, size)` — this is precisely "an
index into `OBJECTS.tab`, which gives the offset in `OBJECTS.bin`."

The `ObjectFileStruct` itself is `ObjDef` (== `ObjModelInstance`,
`include/main/objanim_internal.h:206-265`) — documented there as "the minimal recovered shape of the
model pointer carried by `ObjAnimComponent`"; only `0x94` of its bytes are named so far.

### Not found

- The literal path-format string for `sRomlistZlbPathFormat` (only `extern`-declared so far).
- Any code path resolving `OBJINDEX.bin`'s `-1` "unused" sentinel or the negative-ID bypass rule by
  name (the bypass is inferred here from `loadCharacter`'s `flags & 2` parameter, not from a sign
  check visible in a matched TU).
- The `loadForOtherMap` (`0x10`), and the three `?` (`0x08`/`0x40`/`0x80`) `loadFlags` bits, and the
  `0xC5D` duplicate-ID / `0xFFFFFFFF` dynamic-object-ID sentinels — no matched code was found
  referencing these specific values.

## Ready-to-adopt code

Every offset in the wiki's entry-header table is independently confirmed three times over (`ObjPlacement`,
`SaveGameRomListPosition`, and the raw `*(u8*)(obj+N)` arithmetic in `shader.c`/`object.c`), but the
generic 0x18-byte header has no *single* named type — each site re-derives it as raw pointer offsets
or a bespoke local struct. A maintainer could lift a canonical version (matching this repo's existing
`u8`-for-flags / bitfield conventions) into a shared header such as `include/main/romlist.h`:

```c
typedef struct RomListEntryHeader
{
    s16 type;       /* index into OBJINDEX.bin if positive; abs(type) otherwise */
    u8 size;        /* entry length, in 4-byte words */
    u8 acts0;       /* act 1..8 suppress-load bitmask (bit clear -> loads in that act) */
    u8 loadFlags;
    u8 acts1;       /* act 9..15 suppress-load bitmask; bit 0 unused */
    u8 bound;       /* load radius = bound * 8, when loadFlags & ROMLIST_LOADFLAG_NEAR_PLAYER_ONLY */
    u8 cullDist;    /* cull radius = cullDist * 8 */
    f32 posX, posY, posZ;
    u32 id;         /* unique ID: save-persistence key, scripting lookup key */
} RomListEntryHeader;

#define ROMLIST_LOADFLAG_IS_LEVEL_OBJECT     0x01 /* load if act bits allow */
#define ROMLIST_LOADFLAG_IS_MANUAL_LOAD      0x02 /* never auto-loaded; spawned explicitly */
#define ROMLIST_LOADFLAG_NEAR_PLAYER_ONLY    0x04 /* load only within `bound * 8` of the player */
#define ROMLIST_LOADFLAG_LOAD_FOR_OTHER_MAP  0x10 /* load for a different map ID */
#define ROMLIST_LOADFLAG_IS_BLOCK_OBJECT     0x20 /* load regardless of position */
```

`objShouldLoad`'s `(*(u8*)(obj+3) >> (t-1)) & 1` / `(*(u8*)(obj+5) >> (16-t)) & 1` pair could become
named helpers once/if a maintainer confirms the two branches are worth merging (they're currently
two different shift directions for `acts0` vs `acts1`, so a single `RomList_ActSuppressed(hdr, act)`
helper would need an `if (act <= 8) ... else ...` inside it — not a pure win for readability, which is
likely why the source keeps them separate).
