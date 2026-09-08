# Offset-arithmetic cleanup

Game code should reach fields through the struct that owns them. The sites
below still form an address as `base + offsetof(...)` or `base + *_OFFSET`
and need further cleanup.

## `offsetof` arithmetic

- `src/main/camera.c` `Camera_InitState`: `camera` built from `storage` plus
  `offsetof(CameraMatrixStorage, cameras)`.
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
