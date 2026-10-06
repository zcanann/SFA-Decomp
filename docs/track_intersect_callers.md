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
this storage directly. The result ends at +0xA4,
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
ASan/UBSan. The camera uses its production definition; a semantic player
fixture and service stubs isolate the function from the target object ABI.
Both player and non-player paths
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
| Temporary `CameraObject` | 0x13C | 0x144 |
| Temporary camera's world position | 0x154 | 12 |
| Temporary camera's focus pointer | 0x1E0 | 4 |
| Following conversion temporary | 0x280 | 8 |

The position and focus stores independently land at the camera's +0x18
and +0xA4 offsets. The 0x144-byte record ends at the conversion temporary;
retail `Camera_initialise` separately clears exactly 0x144 bytes of the
live state. The canonical `CameraObject` definition expresses all three
facts. The old `box` consumed the camera's first 0x18 bytes, while
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
The camera uses its production definition. The surrounding player and
trace services are isolated fixtures, as in the update-local test above.

## One canonical camera record (2026-10-06)

Camera control and the mode handlers now share `CameraObject` in
`include/main/camera_object.h`. The former `CamcontrolCameraState` and
`CameraObject` views described the same live and temporary records, but
the latter incorrectly included a complete `ObjAnimComponent`, an
`objectFlags` overlay at +0xB0, and an unconsumed tail through +0x14B.

The live initialization's 0x144-byte clear and normal-camera stack layout
above establish the size. `CameraModeStaffAnim_samplePath` independently
uses a full temporary record with the default camera handlers. The live
storage wrapper retains its separately evidenced four bytes after the
camera; those bytes are not part of `CameraObject`.

A 0x34-byte `CameraTransform` now ends at the parent pointer, before the
camera's collision record. The legacy `anim` member spelling remains in
mode consumers, but its type no longer exposes animation/model fields.
The prior header's claim about `camera.c` reading camera +0xB0 flags was
incorrect: those accesses belong to `GameObject` parents. Camera +0xB0
is the saved local Z coordinate.

| Offset | Canonical field | Evidence |
| --- | --- | --- |
| 0x34 | `collisionResults` | Complete track-query record, including staff mode's +0xA0 hit count |
| 0xA4 | `focusObj` / `focusObject` | Camera control uses the object's animation component; modes use its owner |
| 0xA8 | `prevLocalX/Y/Z` / `savedLocalPos` | Local position snapshot at the end of `Camera_update` |
| 0xB4 | `fovY` | Shared camera-control projection value and mode FOV writes |
| 0xB8 | `prevWorldX/Y/Z` | World position snapshot, also transformed when the parent changes |
| 0xC4 | `focusMoveAverage` | Owner maintains the five-sample movement average used by wall avoidance |
| 0x11C | `overrideTarget` | Combat's target is the same override selected by camera control |

Both focus views are actual pointers, and the staff-camera transform now
uses its parent pointer instead of the animation overlay's integer
address view. Unknown bytes remain opaque. Every mode and sequence-camera
consumer uses the recovered fields; no target ABI offsets change.

The native update and wall-search probes now compile the production
`CameraTransform` and `CameraObject` definitions as well as the collision
and mode-state records. They pass ASan/UBSan at `-O0` and `-O2`, including
cross-view position and full-width focus-pointer checks. This validates
the exercised local paths, not a complete native camera implementation.

Every affected TU remains 100% in all five retail versions. Across the
complete EN source-object baseline, only the sequence object's anonymous
symbol numbering changes: its code, data, symbol offsets, bindings and
relocations are identical. All other object hashes are unchanged.
`clang-format -i` leaves the owner TU and both camera headers byte-identical;
its strict dry run passes, so no separate formatting commit is needed.

All original DOL hashes are verified, and all five `ninja all_source`
builds and strict source-linked retail checksum targets pass. Full-project
objdiff reports regenerated without completion overrides show only the
pre-existing TRK vector-carving and MusyX discarded exception-data
reporting discrepancies. No compiler profiles, splits, or matching
classifications changed.

## Staff-camera path completion and storage (2026-10-06)

`CameraModeStaffAnim_samplePath` formerly declared a byte result but ended
with a bare `return`, even though `CameraModeStaffAnim_update` uses its
result to leave the path-following mode. Retail EN at 0x80106818 calls
`Curve_AdvanceAlongPath`, then copies the sampled X/Z coordinates without
changing r3 before returning. Its caller at 0x8010722C narrows that result
to a byte. The sampler now explicitly saves and returns the integer path
completion result; the caller retains the evidenced narrowing.

Two independent references support this interpretation. Foxhollow's
`game/src/dlls/engine/67/67.c` already returns the curve-advance result.
Dinosaur Planet's `85_attentioncam/attention.c` has the corresponding
`attentioncam_func_112C`, declared `s32`, with the same final call, output
stores and return. The SFA retail instructions remain the matching ground
truth; no reference-project code or names were copied wholesale.

The update's temporary position is a `Vec3f`, replacing an oversized
four-float Z local, two separate coordinates and a pointer-assignment
store. Retail EN's 0x40-byte frame places X/Y/Z at +0x18/+0x1C/+0x20,
above the four relative-position outputs at +0x08..+0x14. The ordinary
vector produces exactly these offsets and instruction order without
padding. `defaultHandler` is now a `CamcontrolDefaultHandlerEntry*`
throughout, so its three callback accesses preserve native pointer width.

The state record now exposes the recovered roles of its fields:

| Offset | Recovered field | Evidence |
| --- | --- | --- |
| 0x004 | `minDistance` | First output of normal mode's `getSettings` |
| 0x008 | `maxDistance` | Second output of `getSettings`; retained despite no later staff-mode read |
| 0x00C | `lowerHeightOffset` | Third output, used for the path endpoint and viewfinder Y offset |
| 0x010 | `targetHeight` | Fifth output, added to target Y and passed to the viewfinder |
| 0x014 / 0x018 | `floorHeight` / `ceilingHeight` | Collision-bound output pointers and their negative/positive sentinels |
| 0x10C | `pathSpeedCurve[4]` | Four values written by `camcontrol_initialise` and consumed by `Curve_EvalHermite` |
| 0x11C | `collisionTime` | Independently incremented by `timeDelta` when either collision flag is set |

The old fifth `initialiseCurve` element was the collision timer, not a
Hermite coefficient. Dinosaur Planet likewise places a scalar after a
four-float curve. SFA's retail exit threshold remains zero; the older
reference's ten-frame threshold is different behavior and is not imported.
All fields remain within the existing allocation-backed 0x1C0-byte state.

`python3 tools/test_staff_camera.py` compiles the actual sampler/update
bodies and production camera, curve, state, interface and handler records
with native pointers. ASan/UBSan runs at `-O0` and `-O2` cover return
propagation, zero-length and clamped path progress, minimum speed,
endpoint updates, completion exits, both collision sources, previous
collision time, full collision-record writes, parent-frame changes and
the no-path exit. Player and curve/trace services are isolated fixtures;
this is a local contract test, not a complete native camera simulation.

The complete ten-function TU remains 100% in all five retail versions:
5,272 code bytes and 112 data bytes. Across the EN source-object baseline,
only this TU's anonymous symbol names change. Each region retains exact
code, data, symbol offsets and relocations; formatting preserves every
source-object hash in each version.

All five full-source builds and strict source-linked retail checksums
pass against verified original DOLs. Full-project reports without
completion overrides retain only the established TRK vector-carving and
MusyX discarded exception-data discrepancies. Compiler profiles, split
boundaries, descriptor order and matching classifications are unchanged.

## Normal-camera vertical-bound contract (2026-10-06)

`CameraModeNormal_updateVerticalBounds` now keeps the focus as a
`GameObject*`, removing its round trip through a 32-bit `int`. Retail EN
loads camera +0xA4 into r29 at 0x80104718 and passes that pointer directly
to broadphase, intersection and height queries. Foxhollow independently
removes the integer cast. The source fix preserves the entire retail
object while making those calls valid with native 64-bit pointers.

The height producer and both selection loops establish the bound roles:
`TrackGroundHit.height` is the plane's Y coordinate, and its +0x08 field
is `normalY`. The first output receives upward-facing floor heights; the
second receives downward-facing ceiling heights. The camera's +0x12C and
+0x130 fields store the selected ceiling and floor normal-Y components,
respectively. The former `boundHitZLower/Upper` names incorrectly described
coordinates and reversed the physical roles. They are now
`ceilingNormalY` and `floorNormalY`, with assertions beside the canonical
camera definition. The normal-mode state, callback declarations and
call sites consistently use `floorHeight` and `ceilingHeight`.

The selection rules remain exactly as the retail instructions specify:

- Negative normal Y qualifies as a ceiling when height is strictly greater
  than camera Y minus ten; positive normal Y qualifies as a floor when
  height is strictly less than camera Y plus ten.
- Each pass chooses the smallest absolute vertical distance, retaining the
  first candidate on equal distance. The tolerance intentionally permits
  a ceiling below the camera or a floor above it.
- With no qualifying hit, outputs remain -100000/+100000 and the cached
  normal fields retain their previous values. Normal-mode wall avoidance
  clears the same two fields at its existing reset site.
- `flags & 1` performs the collision sweep; `flags & 2` performs the height query.
  World-to-local synchronization runs even when neither query is requested.

Dinosaur Planet's `camnormal_func_1A58` independently has the same two-pass
floor/ceiling shape and output order, but uses normal thresholds of
+/-0.707 and a different collision setup. SFA's zero thresholds and sweep
parameters are preserved. Foxhollow's separate collision scratch record
also is not imported: SFA's complete camera-owned result record is already
represented directly.

`python3 tools/test_camera_vertical_bounds.py` compiles the actual helper
and production camera, collision, bounds and height-hit records with native
pointers. ASan/UBSan at `-O0` and `-O2` cover all four flag combinations,
full-width focus propagation, complete collision-record writes, corrected
sweep endpoints, the low-byte collision flag, parent conversion, empty
results, both normal signs, strict tolerance boundaries and ties. The
collision services are controlled fixtures. The existing update, wall
search and staff-camera native tests also pass with the renamed fields.

All 19 functions, 12,592 code bytes and 260 data bytes in the normal-camera
TU remain exact across all five versions. The complete object is byte-for-byte
unchanged in each version, as are all EN source-object hashes. Formatting
also preserves every source-object hash in all five builds. Full-project
reports without completion overrides show no new discrepancies; only the
documented TRK vector-carving and MusyX exception-data reporting cases
remain. Every full-source build and strict source-linked retail checksum
passes against its verified original DOL.
