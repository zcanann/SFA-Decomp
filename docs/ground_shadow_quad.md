# Ground-shadow quad storage

Target: EN v1.0 (`GSAE01`), game compiler GC/1.3.

`GroundShadowQuad` in `include/main/ground_shadow.h` owns the model instance's
optional ground-shadow buffer. This is a four-vertex quad, distinct from the
variable-length projected shadow mesh and the track triangle collection.

| Offset | Storage | Evidence |
| --- | --- | --- |
| 0x00 | `Vec3s vertices[4]` | Twelve halfword stores in `buildGroundShadowQuad`; four XYZ submissions in `objDrawGroundShadow`. |
| 0x18 | `u8 status` | Initialized to zero by the model loader; builder writes 1 on success or 0xff on failure. |
| 0x19 | One padding byte | Allocator reserves 0x1a bytes and aligns the buffer to two bytes. No field access recovered. |

The allocation size is independent evidence for the complete record:
`modelLoad_calcSizes` adds 0x1a for load flag 0x8000 (retail instruction at
0x80025ac0). `modelLoad_layoutBuffers` aligns the cursor and stores it at
`ObjModel` +0x54, then clears buffer +0x18 (0x80025ef8–0x80025f08).
The canonical model field is now `GroundShadowQuad* groundShadowQuad`,
and allocation uses `sizeof(GroundShadowQuad)`.

`buildGroundShadowQuad` (0x8006135c, 760 bytes) queries the ground offset and
normal, constructs orthogonal tangent and bitangent vectors, and scales both
by half the model state's shadow scale. It centers the quad at the negated
ground offset, multiplies the coordinates by 256, and stores signed
halfwords. `objDrawGroundShadow` (0x80061654, 768 bytes) submits them using
`GX_VTXFMT6`; `pi_videoinit.c` configures this format's positions as signed
halfwords with eight fractional bits. Its texture coordinates use ten
fractional bits, matching the corner values 0 and 0x400.

Status zero triggers construction. Status 0xff skips drawing; the failure
path leaves vertex storage untouched. The status byte is unsigned, matching
the renderer's byte loads and comparisons. The reconstruction preserves
the existing lazy construction, arithmetic order, and ground-query behavior.

The producer and consumer now use native vertex fields and a named status
field; the builder's local names identify the ground normal, tangent basis,
half size, and fixed-point scale. The drawing declaration lives beside its
record, and the lightmap renderer includes that header directly.

Validation preserves all function instruction bytes, allocated sections,
named symbol positions, and relocation destinations. The shadow object has
13 renamed anonymous relocation references; the other 1,001 source objects
are byte-identical. Every function's size and score in the full objdiff
report is unchanged, including both quad functions at 100%. The strict
retail checksum and `ninja all_source` pass.
