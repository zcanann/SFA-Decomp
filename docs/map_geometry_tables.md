# Typed map collision tables

Target: EN v1.0 (`GSAE01`), game compiler GC/1.3.

`MapBlockData.gcPolygons` (+0x4c) and `polygonGroups` (+0x50) now carry their
established `MapTriIndex*` and `CollisionPolygonGroup*` types. Relocation
continues through the existing byte-offset helper. The polygon accessor
returns an eight-byte triangle record and the group accessor returns a
0x14-byte group, with both declarations in `track_dolphin_map_api.h`.

`trackBuildBlockTriangles` follows native group pointers from the array base
to `base + polyGroupCount`. Each group's next `firstTri` still closes its
triangle range. Cached triangle traversal uses `MapTriIndex*` and increments
by a record, retaining the existing cache-bank addresses and queue ordering.
Bounds and flags come directly from the shared group fields; the low and
high bytes of `cellMask` continue to filter X and Z coverage separately.

The XYZ animator intentionally reuses a halfword cursor for group and
triangle phases. Its triangle phase now selects the accessor result's
`vert` array, preserving the three-index loop and its compiler-proven local
lifetimes. No record overlay or new cast is introduced there.

The exact `mapBlockCountTrianglesByType` keeps its byte-offset cursor.
Replacing that cursor with `polygonGroups[i]` changes 12 instruction bytes
through register allocation, despite preserving the function's 84-byte size.
The stride now uses `sizeof(CollisionPolygonGroup)`; the proven access shape
is retained. Native pointers work without instruction changes in the larger
map collision walker.

Validation: all 30 functions in `track_dolphin.o` and all 33 functions in
`tex_dolphin.o` preserve their instruction bytes. Allocated sections, named
symbol positions, and relocation destinations are unchanged. One anonymous
relocation name changes in `track_dolphin.o`; the other 1,001 source objects
are byte-identical. The full objdiff report is unchanged, with
`trackBuildBlockTriangles` at 3,060 bytes and 98.475815%. Both the strict
retail checksum and `all_source` pass.
