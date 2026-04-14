# `orig/GSAE01/files/OBJECTS.*` notes

This pass turns `OBJECTS.bin`, `OBJECTS.tab`, and `OBJINDEX.bin` into a reusable scaffold for object recovery instead of treating them as just a name source.

## Tool

- `python tools/orig/object_catalog.py`
  - Recovers the real object-record count from the EOF-style `OBJECTS.tab`.
  - Resolves placement-space object IDs through `OBJINDEX.bin`.
  - Cross-links canonical object defs with romlist placement counts, DLL IDs, class IDs, fixed map affinities, and inline substructure offsets.
  - Supports direct lookup by object name, def ID, DLL ID, class ID, or map ID.

## High-value findings

### 1. `OBJECTS.tab` gives real per-object boundaries, not just a flat offset list

The EN retail files contain:

- `1478` offsets before the `0xFFFFFFFF` terminator
- `1477` real object defs plus one EOF offset

That means the record size for every object is already recoverable from retail data, with no heuristics needed.

The most common record spans are:

- `0xA0` bytes: 679 defs
- `0xC0` bytes: 426 defs
- `0xE0` bytes: 191 defs
- `0x100` bytes: 93 defs

This is useful when carving out a real `ObjectFileStruct` and checking where inline arrays begin and end.

### 2. Several pointer-like fields are provably inline offsets within each object record

`object_catalog.py` confirms these fields land back inside the same variable-length record:

- `pModelList` at `+0x08`: 1477 defs
- `field_0x18` at `+0x18`: 53 defs
- `pSeq` at `+0x1C`: 413 defs
- `pEvent` at `+0x20`: 55 defs
- `pHits` at `+0x24`: 41 defs
- `pWeaponDa` at `+0x28`: 5 defs
- `hitboxes` at `+0x2C`: 602 defs
- `aButtonInteraction` at `+0x40`: 275 defs

That is a direct source-recovery win: `OBJECTS.bin` is not just a fixed header plus external tables. It already contains many inline substructures whose ownership and lifetime are tied to each object record.

### 3. `OBJINDEX.bin` is mostly a two-to-one canonicalization table, not a giant alias bucket

Inside the live object-def range `0x0000` through `0x05C4`:

- 901 defs remap to another canonical def
- 576 stay identity
- 1477 placement-space IDs collapse onto 1133 canonical defs
- max fanout in that live range is only `2`

Across the full `OBJINDEX.bin`, the only bigger outlier is canonical def `0x0000`, which is fed by 7 placement IDs.

This is useful because it means `OBJINDEX.bin` behaves like a real canonicalization/renumbering layer. It is not an arbitrary many-to-one alias blob, so canonical object defs are still good naming anchors.

### 4. DLL IDs and class IDs already expose useful object families

Top DLL families by canonical romlist placements:

- `0x0125`: only `curve`, 5480 placements
- `0x0100`: only `TrickyWarp`, 2139 placements
- `0x0126`: trigger family (`TrigPnt`, `TrigCyl`, `TrigPln`, `TrigArea`, ...), 1483 placements
- `0x02AD`: soft-body / foliage-heavy family, 994 placements
- `0x02B1`: `CmbSrc*` family, 922 placements

Top class-ID families by canonical romlist placements:

- `0x002C`: only `curve`, 5480 placements
- `0x0061`: 213 defs, 2907 placements
- `0x0030`: 404 defs, 2358 placements
- `0x007F`: 37 defs, 1825 placements
- `0x0015`: only `TrigPln`, 1225 placements

This is a good way to prioritize object work. High-placement DLL/class families are likely to pay off faster than isolated one-offs.

### 5. The fixed map field at `+0x78` is live and already cross-links object variants to specific maps

`42` object defs carry a non-`0xFFFF` map ID, spanning `25` unique maps.

Examples:

- map `0x5D` `dimpushblock`: 8 defs, including `DIMPushBloc`, `DIM2IceBloc`, `CCboulder`, `NW_boulder`, `SH_boulder`
- map `0x6D` `dim2stonepillar`: 3 defs, including `DIM2StonePi`, `LINKE_stone`, `linkB_Stone`
- map `0x71` `wctemplelift`: 2 defs, `WCMoonTempl` and `WCSunTemple`

This is a strong hint that some object defs are intended as map-scoped variants or shared templates across related maps, which can help with subsystem grouping and source-file boundaries.

## Practical use

- Summary: `python tools/orig/object_catalog.py`
- CSV dump: `python tools/orig/object_catalog.py --format csv`
- Search by object, DLL, class, or map:
  - `python tools/orig/object_catalog.py --search curve`
  - `python tools/orig/object_catalog.py --search dll:0x0126 def:0x051C`
  - `python tools/orig/object_catalog.py --search map:dimpushblock`
