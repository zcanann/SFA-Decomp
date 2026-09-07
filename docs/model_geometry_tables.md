# Model geometry tables

Target: EN v1.0 (`GSAE01`), game compiler GC/1.3.

Three consecutive model getters at 0x80028354, 0x80028364, and 0x80028374
index the collision-triangle, collision-group, and display-list arrays with
strides 8, 0x14, and 0x1c. Their header pointers are at +0x5c, +0x60, and
+0xd0 respectively. The header, getters, relocation, and direct callers now
use their canonical record types.

## Shared collision groups

`CollisionPolygonGroup` replaces the map-only `MapTriGroup` name. Models and
maps both consume all six signed-halfword bounds, the first-triangle index,
and the flag word at +0x10, with the same 0x14-byte record stride. Both call
`trackGetPackedSurfaceType`, which extracts flags bits 16 through 23. Map
animation uses the upper flag byte as its separate group selector.

The model walker reads the current first-triangle index at +0 and the end
index at +0x14 (EN 0x80067ea0/0x80067ea4). This is the next group's first
index, matching the map walker's `group[1].firstTri` contract. It is not an
extra field inside the current group, so the type remains 0x14 bytes. The
last range also requires a following boundary halfword; this reconstruction
does not infer the size or contents of any storage beyond that boundary.

The common header is `include/main/collision_polygon.h`. Map accessors and
five existing DLL consumers use that same type, preserving their existing
flags, traversal, and geometry behavior. Model bounds are multiplied by the
caller's scale; map bounds retain their existing coordinate conversions.
The two unknown bytes at +0x0e remain opaque.

`ModelCollisionTriangle` has three unsigned-halfword vertex indices and two
unknown trailing bytes. The model consumer reads exactly the first three
indices. The map triangle's last halfword is a grid-cell mask, but there is
no model-side use establishing that meaning, so it is not imposed here.

## Display lists

`ModelDisplayListEntry` retains its established pointer at +0, length at +4,
and unknown bytes from +6 through +0x1b. The model header now points to this
type and relocation uses `displayLists[i].dlist`. The getter returns the
record directly. No neighboring map display-list layout is substituted.

Primary and shadow lists occupy consecutive groups in the same array.
Relocation processes the sum of their counts; the shadow draw adds the
primary count to its decoded index. The typed getter preserves that caller
contract.

Validation: all 1,002 source objects are byte-identical, including the model,
renderer, both collision consumers, and the five map-animation DLLs. The
full objdiff report is unchanged. All three getters remain 16-byte exact
matches, and `trackBuildModelTriangles` remains 2,632 bytes at 100%. The
strict retail checksum and `all_source` both pass. No runtime behavior or
asset contents were changed.
