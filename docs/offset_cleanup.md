# Offset-arithmetic cleanup

Game code should reach fields through the struct that owns them. The sites
below still form an address as `base + offsetof(...)` or `base + *_OFFSET`
and need further cleanup.

## `offsetof` arithmetic

- `src/main/objprint_dolphin.c` `objRenderShadowModel` and
  `modelDoRenderInstrs`: vertex buffer selected through
  `offsetof(ObjModel, vtxBuf)` (four sites).
- `src/main/model.c` `modelAnimUpdateChannels`: per-bone matrix slot written
  through `offsetof(ModelBone, idx)`.
- `src/main/pi_pathsearch.c` `pathSearchNodeMatchesTarget`: walk group read
  through `offsetof(RomCurveDef, linkWalkGroups)`.
- `src/main/pi_pathsearch.c` `pathSearchExpandNode`: link id read through a
  byte walker plus `offsetof(RomCurveDef, linkIds)`.
- `src/main/objanim.c` `ObjAnim_SampleRootCurvePhase` and
  `ObjAnim_AdvanceCurrentMove`: four header-to-axis cursor advances now use
  `offsetof(ObjAnimRootCurve, axisData)`. Direct member access changes codegen;
  the variable-length record types and presence fields are recovered.

## `*_OFFSET` macros

- `src/main/objlib.c` `ObjLink_DetachChild`: child slots reached through
  `OBJLINK_CHILD_LIST_OFFSET` on integer walkers.
- `src/main/objhits.c` `ObjHits_AddContactObject`: transform state and its
  contact list reached through `OBJHITBOX_TRANSFORM_STATE_OFFSET`,
  `OBJHITBOX_STATE_CONTACT_OBJECTS_OFFSET` and
  `OBJHITBOX_STATE_CONTACT_OBJECT_COUNT_OFFSET`.

The cached move offset sites are recovered: `ObjAnimCachedMove` contains the
joint-matrix-slot table prefix and the named `moveData` member. State cache
pointers and their loader path now use this type; see
[animation frame layouts](model_animation_frame_layout.md#cached-move-records-2026-09-07).

## Camera storage recovery, 2026-10-06

`camera.c` no longer casts the inverse-object matrix array to a fabricated
`CameraMatrixStorage` spanning `0x1700` bytes. Object transforms, view updates
and initialization use their actual globals; cameras are indexed as camera
records, so the code also works when a native pointer enlarges `Camera`.
Foxhollow's direct-reference conversion corroborates this storage problem.

The old 34-element object matrix array and 64-float world matrix also included
independent scratch and projection matrices. Retail calls establish these
64-byte destinations:

| EN address | Recovered role |
| --- | --- |
| `80337090` | 30 inverse object matrices |
| `80337810` | 30 object matrices |
| `80337FD0` | Parent-chain transform scratch matrix |
| `80338050` | Initial perspective copy |
| `80338090` | World transform matrix |
| `80338110` | Initial perspective matrix |

The paired array count is corroborated by Dinosaur Planet's `gObjectMatrices`
and `gInverseObjectMatrices`, both of length 30, and its allocator's explicit
30-slot overflow diagnostic. Its `camBuildObjectMatrix` uses the separate
`gAuxMtx` for the same parent-chain multiplication. Four intervening 64-byte
retail BSS spans remain opaque; no matrix meaning is assigned merely from
their widths. All five symbol configs preserve the established addresses.
The retail unchecked slot counter and four-entry ancestor stack are unchanged.

The separate fullscreen viewport overrun remains documented beside its function.
Its accesses now use an explicit byte cursor, preserving the retail reads past
the four-entry viewport table without widening the table. Object bytes and
relocations are unchanged by that spelling.

The existing common GC/1.3 deferred/no-auto-inline profile emits the native
BSS pool without cross-object arithmetic. The whole TU remains intact, with
functions ordered to preserve retail emission. There are no section directives,
new retention rules, per-function flags or compiler-version exceptions.

Dinosaur Planet also supplies two useful source-level clues. `camReset` takes
integer positions and angles in degrees; `180 * 182` explains retail's initial
`0x7FF8` yaw. A private reset helper recovers those arguments and the matching
field initialization. Its `camResetFarPlane` requests 10000 units over 60 frames.
Restoring that API reproduces the otherwise unexplained 10000-unit literal
before initialization's 200-unit literal. MWCC emits its 40-byte body, which
the ordinary retail link discards, while retaining the shared constant. The
previous named one-element constant arrays are removed.

The stripped reset API is a reconstruction supported by the predecessor and
the exact retail pool, not a recovered SFA symbol name or direct proof of the
discarded function's original spelling. A green code-only report was
insufficient here: direct global references initially moved those constants,
and the final DOL comparison detected their changed addresses.

All five hash-verified versions retain 58 matching live functions, 8,472 code
bytes and 6,580 data bytes. Every other existing source object's raw hash is
unchanged; all five `all_source` and strict checksum builds pass. Full objdiff
inventories with completion annotations removed retain only the existing DTK
exception-vector and MusyX discarded exception-data report artifacts.

`python3 tools/test_camera_storage_native.py` compiles the changed production
functions and reset helpers with the canonical camera record. It runs 199
storage scenarios at `-O0` and `-O2` under ASan and UBSan, with independent
global redzones and 64-bit pointers. Cases cover all valid matrix slots,
parent chains through depth four, every camera, pause/shake combinations and
initialization. SDK adapters check the actual matrix destinations and captured
transform values. Negative controls reject the old camera-pool base, fixed
96-byte camera stride, scratch-array overrun, perspective-array overrun and
incorrect inverse-view destination.
