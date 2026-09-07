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

## `*_OFFSET` macros

- `src/main/objlib.c` `ObjLink_DetachChild`: child slots reached through
  `OBJLINK_CHILD_LIST_OFFSET` on integer walkers.
- `src/main/objhits.c` `ObjHits_AddContactObject`: transform state and its
  contact list reached through `OBJHITBOX_TRANSFORM_STATE_OFFSET`,
  `OBJHITBOX_STATE_CONTACT_OBJECTS_OFFSET` and
  `OBJHITBOX_STATE_CONTACT_OBJECT_COUNT_OFFSET`.
- `src/main/objanim.c` `ObjAnim_SetBlendMove`, `Object_ObjAnimSetMove`,
  `ObjAnim_SampleRootCurvePhase`, `ObjAnim_AdvanceCurrentMove` and
  `ObjAnim_SetCurrentMove`: cached move data reached through
  `OBJANIM_CACHED_MOVE_DATA_OFFSET` (seven sites), and root curve axis data
  reached through `OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET` or a bare `+= 3`
  (four sites).
- `include/main/objanim_internal.h` `ObjAnim_GetMoveData` and
  `ObjAnim_GetBlendMoveData`: same cached move offset.
- `src/main/model.c` `ObjModel_SampleJointTransform`, `modelAnimResetState`
  and `modelAnimUpdateChannels`: cached move data reached through
  `OBJANIM_CACHED_MOVE_DATA_OFFSET` or a bare `+ 0x80`.

The cached move sites share one layout: a 0x80-byte joint matrix slot row
followed by `ObjAnimMoveData`. A struct for that record would let
`moveCache`, `blendMoveCache` and `cachedMoves` in `ObjAnimState` be typed.
