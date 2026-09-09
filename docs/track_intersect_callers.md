# Intersection caller storage

The caller records below use the canonical 0x70-byte `TrackHitResults` contract.
These are source-layout recoveries; their functions already matched retail.

## Pushable (object slot 239)

`pushable_push` at EN 0x801755CC has a 0x1C0-byte frame. All three intersection
calls pass SP+0xFC. Its radii pointer remains in r31 at SP+0x13C; the initial
surface type, query type and hit count are stored at SP+0x14C, +0x150 and +0x168.
The record ends at SP+0x16C, before the conversion temporary at SP+0x170.
The preceding matrix ends at SP+0xFC.

The former 64-byte `hitBuffer` and 48-byte `PushableCollisionProbe` were two
parts of that one record. A single `TrackHitResults` replaces them, preserving
the interior radii pointer. This repairs the source's cross-local access;
the retail function does not overrun its stack record. The entire compiled
object remains byte-identical, including all 18 function bodies and data.
The generated slot path and descriptor ownership are unchanged.

## Camera modes

`camcontrol_traceMove` accepts `TrackHitResults*`. The separate
`CamcontrolTraceWork` was the same record with most fields hidden: `bboxHit`
was `surfaceTypes[0]`, `mode` was `queryTypes[0]`, and `blocked` was `hitMask`.
Camera modes 73, 75 and 77 now use the canonical record too.

In `CameraModeNormal_updateVerticalBounds` (EN 0x801046F4), retail passes
camera+0x34 as the result pointer and camera+0x74 as the radii pointer, writing
surface/query inputs at +0x84/+0x88. `CameraObject.collisionResults` exposes
this storage through the existing prefix union. The result ends at +0xA4,
where the separately used target pointer begins. The old animation-field
accesses misrepresented camera-specific storage; direct record fields emit
the same instructions. Offset assertions live in the camera's owning header.

`camcontrol_traceFromTarget` passes SP+0x14 in its 0x90-byte frame and reads
its mask at SP+0x82. The record ends at SP+0x84, before saves at +0x88/+0x8C.
Its former 111-byte array is now the complete aligned record. The already
112-byte result arrays in target-position and wall-avoidance queries are
also typed. Larger scratch arrays in the other camera queries retain their
storage shapes pending recovery of their surrounding locals.

## Validation

The five affected units retain their exact retail matches. Every function
body, allocated section, named symbol layout and resolved relocation target
is unchanged. Camera mode 66 renumbers anonymous literal symbols; the other
four complete objects retain their original bytes. Formatting is checked
separately for code-generation neutrality. Full `ninja all_source` and strict
retail checksum builds gate publication, each with a 30-second timeout.
