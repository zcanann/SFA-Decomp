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
also typed. The remaining wall-direction search storage is recovered below.

## Validation

The five affected units retain their exact retail matches. Every function
body, allocated section, named symbol layout and resolved relocation target
is unchanged. Camera mode 66 renumbers anonymous literal symbols; the other
four complete objects retain their original bytes. Formatting is checked
separately for code-generation neutrality. Full `ninja all_source` and strict
retail checksum builds gate publication, each with a 30-second timeout.

## Normal-camera update locals (2026-10-06)

`CameraModeNormal_update` now uses two three-element origin vectors and two
`TrackHitResults` locals. Previously it passed the address of a scalar X
coordinate as a vector, relying on MWCC placing the separately declared Y
and Z locals after it. The collision outputs were casts of 116-byte and
112-byte arrays. Neither spelling describes native storage correctly:
the vector accesses cross local-object boundaries, and `TrackHitResults`
grows when its object pointers become 64 bits. Foxhollow's corresponding
camera code independently replaces byte collision buffers with typed records.

Retail EN uses a 0x150-byte frame with these complete records:

| Local | Stack offset | Size |
| --- | ---: | ---: |
| Target time scale | 0x08 | 4 |
| Relative-position outputs, distance/Z/Y/X order | 0x0C..0x18 | 16 |
| Collision-probe origin | 0x1C | 12 |
| Wall-trace origin | 0x28 | 12 |
| Collision-probe results | 0x34 | 0x70 |
| Wall-trace results | 0xA4 | 0x70 |

Ordinary typed locals reproduce every offset without filler arrays. The
one-element target-pointer array is now a pointer, and the four-byte
relative-position scratch array is an ordinary float output.

The same function's apparent animation accesses are collision data:
`lbz` at camera+0xA2 reads `collisionResults.hitMask`, and `lfs` at
camera+0x38 reads `collisionResults.planes[0][1]`. The former accesses used
`offsetof(anim.activeMove)` and `offsetof(anim.next)`, hiding the camera's
different layout. They now use the canonical collision fields. The cached
byte at normal-mode state+0xC5 is renamed from `targetActionFlags` to
`collisionHitMask`; all consumers are in this function.

The complete 19-function TU remains exact in all five retail versions.
EN has 12,592 code bytes and 260 data bytes; its 1,644-byte update function
is unchanged. Comparing the complete EN object before and after shows only
anonymous-name changes in `.strtab`, with identical code, data, symbol
offsets and relocations. Formatting is verified separately by raw object
hash in every version. Compiler profiles and splits are unchanged.

All original DOL hashes are verified. Full-project reports regenerated
without completion overrides retain only the existing TRK vector-carving
and MusyX discarded exception-data report discrepancies. All five
`all_source` builds and strict source-linked retail checksums pass.

`python3 tools/test_camera_update_storage.py` compiles the actual update
body, mode-state definition, and collision record at `-O0` and `-O2` under
ASan/UBSan. Semantic camera/player fixtures and service stubs isolate the
function from the target object ABI. Both player and non-player paths
exercise both trace origins, full native collision-record writes, timer
reset, hit-mask caching, plane-based height locking, and the null-target
return. This is a local storage probe, not a complete native camera test.

## Wall-direction search camera (2026-10-06)

The apparent 75-float `probe` and 136-byte `box` in
`CameraModeNormal_chooseWallAvoidanceDirection` were an incorrect division
of two real locals: a 0x70-byte `TrackHitResults` followed by a 0x144-byte
camera state. Retail EN's 0x300-byte frame establishes their placement:

| Local or field | Stack offset | Size |
| --- | ---: | ---: |
| Target trace origin | 0x18 | 12 |
| Negative-angle path, seven positions | 0x24 | 84 |
| Positive-angle path, seven positions | 0x78 | 84 |
| `TrackHitResults` | 0xCC | 0x70 |
| Temporary `CamcontrolCameraState` | 0x13C | 0x144 |
| Temporary camera's world position | 0x154 | 12 |
| Temporary camera's focus pointer | 0x1E0 | 4 |
| Following conversion temporary | 0x280 | 8 |

The position and focus stores independently land at the camera's +0x18
and +0xA4 offsets. The 0x144-byte record ends at the conversion temporary;
retail `Camera_initialise` separately clears exactly 0x144 bytes of the
live state. The existing `CamcontrolCameraState` definition expresses all
three facts. The old `box` consumed the camera's first 0x18 bytes, while
`probe` consumed its remaining 0x12C bytes. Its `*(int*)&probe[35]` store
was really `probeCamera.focusObj`, not a float-array element or padding.

The search now declares both actual record types and uses the camera's
world-position array. This view shares the existing X/Y/Z fields in their
owning header, with a checked +0x18 offset. The focus pointer is assigned
through `&initialTarget->anim`, preserving native pointer width. Positive
and negative paths each retain their evidenced initial point plus six
candidate points. Their names and trigonometric locals now describe the
direction and value being used; the retail arithmetic is preserved.

An initial typed spelling copied the world-position address through an
extra register. The compiler trace isolated this to the pointer binding;
using the same vector pointer for the candidate stores and trace call
restores the exact instructions. No extra padding, compiler profile change,
or fabricated storage is needed.

All 19 camera functions, 12,592 code bytes, and 260 data bytes match in
all five versions. Full-project reports without completion overrides show
no new discrepancies, and every source build and strict retail checksum
passes. Formatting preserves each version's complete camera object hash.

`python3 tools/test_camera_wall_search.py` compiles the actual search and
record definitions under ASan/UBSan at `-O0` and `-O2`. It checks the
full-width focus pointer through the passed position view, both target
classes, all six search steps, both path directions, tie selection,
segment rejection, full native collision writes, and yaw-offset clamping.
The surrounding camera and trace services are isolated fixtures, as in
the update-local test above.
