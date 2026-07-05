#ifndef MAIN_DLL_CHECKPOINT4_H_
#define MAIN_DLL_CHECKPOINT4_H_

#include "global.h"
#include "main/object_descriptor.h"
#include "main/objanim_internal.h"

#define CHECKPOINT4_DLL_ID 0x00E8
#define CHECKPOINT4_CLASS_ID 0x0005
#define CHECKPOINT4_DEF_ID 0x0492
#define CHECKPOINT4_OBJECT_DEF_BYTES 0xA0
#define CHECKPOINT4_PLACEMENT_BYTES 0x40
#define CHECKPOINT4_EXTRA_STATE_BYTES 0x40

#define CHECKPOINT4_OBJECT_TYPE_ID 0x10
#define CHECKPOINT4_RANDOM_HEADING_COUNT 4
#define CHECKPOINT4_RANDOM_HEADING_MAX 0xF0
#define CHECKPOINT4_OBJECT_FLAGS_ENABLED 0xA000

typedef struct Checkpoint4MatrixBuildTransform {
  s16 rotX;
  s16 rotY;
  s16 rotZ;
  u16 pad06;
  f32 scale;
  f32 x;
  f32 y;
  f32 z;
} Checkpoint4MatrixBuildTransform;

typedef struct Checkpoint4Placement {
  u8 pad00[0x28];
  s8 checkpointIndex;
  u8 rotX;
  u8 radius;
  u8 pad2B[CHECKPOINT4_PLACEMENT_BYTES - 0x2B];
} Checkpoint4Placement;

typedef struct Checkpoint4State {
  u8 pad00[0x10];
  f32 planeNormalX;
  f32 planeNormalY;
  f32 planeNormalZ;
  f32 planeDistance;
  f32 triggerRadius;
  u8 pad24[0x34 - 0x24];
  s16 randomHeadings[CHECKPOINT4_RANDOM_HEADING_COUNT];
  u8 pad3C[CHECKPOINT4_EXTRA_STATE_BYTES - 0x3C];
} Checkpoint4State;

typedef struct Checkpoint4Object {
  ObjAnimComponent objAnim;
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  Checkpoint4State *state;
  u8 padBC[0xF4 - 0xBC];
  s32 checkpointIndex;
} Checkpoint4Object;

STATIC_ASSERT(sizeof(Checkpoint4Placement) == CHECKPOINT4_PLACEMENT_BYTES);
STATIC_ASSERT(offsetof(Checkpoint4Placement, checkpointIndex) == 0x28);
STATIC_ASSERT(offsetof(Checkpoint4Placement, rotX) == 0x29);
STATIC_ASSERT(offsetof(Checkpoint4Placement, radius) == 0x2A);

STATIC_ASSERT(sizeof(Checkpoint4State) == CHECKPOINT4_EXTRA_STATE_BYTES);
STATIC_ASSERT(offsetof(Checkpoint4State, planeNormalX) == 0x10);
STATIC_ASSERT(offsetof(Checkpoint4State, planeDistance) == 0x1C);
STATIC_ASSERT(offsetof(Checkpoint4State, triggerRadius) == 0x20);
STATIC_ASSERT(offsetof(Checkpoint4State, randomHeadings) == 0x34);

STATIC_ASSERT(offsetof(Checkpoint4Object, objAnim) == 0x00);
STATIC_ASSERT(offsetof(Checkpoint4Object, objectFlags) == 0xB0);
STATIC_ASSERT(offsetof(Checkpoint4Object, state) == 0xB8);
STATIC_ASSERT(offsetof(Checkpoint4Object, checkpointIndex) == 0xF4);

extern ObjectDescriptor11WithPadding gCheckpoint4ObjDescriptor;

void setMatrixFromObjectPos(f32 *matrix, void *obj);
void Matrix_TransformPoint(f32 *matrix, f64 x, f64 y, f64 z, f32 *outX, f32 *outY, f32 *outZ);

void checkpoint4_setScale(void);
int checkpoint4_getExtraSize(void);
int checkpoint4_getObjectTypeId(void);
void checkpoint4_free(void);
void checkpoint4_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void checkpoint4_hitDetect(void);
void checkpoint4_update(void);
void checkpoint4_init(Checkpoint4Object *checkpoint, Checkpoint4Placement *placement);
void checkpoint4_release(void);
void checkpoint4_initialise(void);

#endif /* MAIN_DLL_CHECKPOINT4_H_ */
