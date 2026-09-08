# Shadow-volume corner and plane records

Target: EN v1.0 (`GSAE01`), game compiler GC/1.3.

The shadow renderer's bounding geometry now uses native `Vec3f` arrays,
`TrackQueryBounds`, and `ShadowVolumePlane` records. Its existing allocation,
arithmetic order, unused arguments, and calls remain intact.

`buildShadowVolumeBox` writes eight XYZ corners. Its output and direction
arguments now have vector types, including the two callers in
`shadow_dolphin.c` and `newshadows.c`. The template retains its existing
25-float storage: initialization and the eight-iteration loop establish
only the first 24 values, so the trailing float is not assigned a meaning.

`vecGetRanges` scales and translates each of the eight corners and writes
the established six signed fields of `TrackQueryBounds`. It still compares
floating coordinates against the current integer bounds and truncates on
assignment. Replacing this with a float min/max pass followed by conversion
would require separate evidence; it is not part of the type recovery.

`trackDolphin_buildShadowVolumePlanes` at 0x80061954 writes six plane
records at a 0x14 stride. Each has XYZ normal components at +0/+4/+8 and
distance at +0x0c, with four untouched bytes at +0x10. The source preserves
those bytes as opaque storage; no flag or corner-index meaning is claimed.
The helper computes a normalized cross product, negates the normal, and
sets distance to the negated dot product with a point on the plane.

| Plane | First edge | Second edge | Point used for distance |
| --- | --- | --- | --- |
| 0 | corner 2 - corner 3 | corner 7 - corner 3 | corner 3 |
| 1 | corner 6 - corner 5 | corner 1 - corner 5 | corner 5 |
| 2 | corner 5 - corner 4 | corner 0 - corner 4 | corner 4 |
| 3 | corner 3 - corner 0 | corner 4 - corner 0 | corner 0 |
| 4 | corner 6 - corner 7 | corner 4 - corner 7 | corner 7 |
| 5 | corner 1 - corner 0 | corner 3 - corner 0 | corner 0 |

The renderer's corner buffer at stack +0x48 becomes `Vec3f boxCorners[8]`.
The plane workspace begins at +0xa8; its existing 304-byte extent is retained
as raw storage, with a typed view passed to the plane builder. The six
observed plane writes do not establish an array of 15 planes or explain the
remaining workspace. This extent remains a reconstruction of the stack
layout, not a recovered source allocation contract.

The EN `cullVisibleShadowTriangles` accepts the corners and planes but does
not read either. It tests triangle normals against the shadow direction and
copies accepted vertices. The plane calculation and unused arguments are
retained rather than assuming that this version performs volume clipping.

Validation: all 1,002 source objects remain byte-identical, and the full
objdiff report is unchanged. The corner builder (320 bytes), bounds helper
(392 bytes), six-plane builder (1,156 bytes), culler (308 bytes), and render
coordinator (560 bytes) remain 100% matched. Both the strict retail checksum
and `ninja all_source` pass.
