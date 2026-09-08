# Shared collision records and shadow triangle collection

Target: EN v1.0 (`GSAE01`), game compiler GC/1.3.

`collectShadowTrackTriangles` at 0x80060c14 consumes the same 0x4c-byte
`TrackTriangle` records that `track_dolphin.c` builds and queries. The two
private definitions are consolidated in `track_dolphin.h`, with assertions
for the record size and the accessed coordinate, normal, and flag offsets.
The shared descriptor accessor now returns `TrackBlockDescriptor*`.

The retail collector advances descriptors by 0x18 bytes and reads signed
triangle indices at +4 and +0x1c: each descriptor's range ends at the next
descriptor's `firstTriangle`, including the final sentinel. Input coordinates
are three signed halfwords per axis at +0x10, +0x16, and +0x1c. Each accepted
triangle produces three `Vec3f` values and one 0x14-byte
`TrackShadowTriangle`. Native array indexing replaces the private nine-float
overlay, integer vertex cursor, and separate output-record byte counter.

The collector's coordinate cases follow its descriptor owner:

- A null owner uses the object's local position, with the supplied grid X/Z
  offsets applied to the relative vertex coordinates.
- The object's parent uses its local position without the grid adjustment.
- Another owner supplies the matrix at descriptor +0x0c. Its column-major
  entries are copied into an SDK affine matrix with the object's local
  position subtracted from the translation. Only the vertices appended for
  this descriptor are transformed by `PSMTXMultVecArray`.

The selector chooses flag mask 4 or 8; the input byte retains the retail
signed extension. Normals and flags are copied in all three cases. The
collector does not transform those normals or write the output plane
distance. Both capacity checks remain: 1,200 triangles and 3,600 vertices.
The existing unused count and render-mode arguments do not control capacity.

Native output indexing improves the 1,152-byte collector from 98.50694% to
99.739586%. The remaining 13 diff regions exchange r27 and r31 for the
selected flag and triangle count. Every other function in the full objdiff
report keeps its size and match score. Only `tex_dolphin.o` changes among
1,002 source objects, and only this function's instruction bytes change
within it; named symbol positions and relocation records are unchanged.

`python3 tools/test_shadow_triangle_collection.py` compiles the production
collector and canonical records with a small host fixture at `-O0` and
`-O2`. Five scenarios check fixed expected coordinates, both selectors,
signed flags, empty and fully filtered input, the fixed capacity, and
untouched output fields and buffer tails. The SDK matrix call is modeled
with ordinary affine math; this does not validate GameCube cache behavior
or final shadow-volume rendering. The existing three ground-query tests
also pass using the canonical triangle definition. Both the strict retail
checksum build and `ninja all_source` pass.
