#ifndef MAIN_DLL_DLL_0235_DFPTARGETBLOCK_H_
#define MAIN_DLL_DLL_0235_DFPTARGETBLOCK_H_

#include "main/dll/door.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct DfpTargetBlockPoint {
  f32 x;
  f32 y;
  f32 z;
} DfpTargetBlockPoint;

/*
 * Placement/def record the map loader hands to dfptargetblock_init. Embeds the
 * common ObjPlacement head, then the block's class-specific SFX gamebit ids
 * (def+0x1E / def+0x20) read in dfptargetblock_init.
 */
typedef struct DfpTargetBlockPlacement {
  ObjPlacement base;       /* 0x00: common placement head */
  u8 pad18[0x1E - 0x18];   /* 0x18 */
  s16 completionSfxId;     /* 0x1E */
  s16 stateSfxId;          /* 0x20 */
} DfpTargetBlockPlacement;

STATIC_ASSERT(offsetof(DfpTargetBlockPlacement, completionSfxId) == 0x1E);
STATIC_ASSERT(offsetof(DfpTargetBlockPlacement, stateSfxId) == 0x20);

struct DfpTargetBlockState {
  void *pathState;
  DfpTargetBlockPoint floorPoints[8];
  s16 stateSfxId;
  s16 completionSfxId;
  s8 floorPointCount;
  u8 mode;
  u8 stateSfxReady;
  u8 completionSfxReady;
};

typedef enum DfpTargetBlockMode {
  DFPTARGETBLOCK_MODE_RAISING = 0,
  DFPTARGETBLOCK_MODE_ACTIVE = 1,
  DFPTARGETBLOCK_MODE_RESETTING = 2,
  DFPTARGETBLOCK_MODE_LOWERING = 3,
  DFPTARGETBLOCK_MODE_SETTLED = 4,
} DfpTargetBlockMode;

#define DFPTARGETBLOCK_HOME_OBJECT_TYPE     0x04E0
#define DFPTARGETBLOCK_HIT_TYPE_PUSH        0x0E
#define DFPTARGETBLOCK_IMPACT_SFX           0x044D
#define DFPTARGETBLOCK_LOOP_SFX             0x03BD
#define DFPTARGETBLOCK_RESET_SFX            0x01D3
#define DFPTARGETBLOCK_RESET_PARTICLE_ID    0x05F5
#define DFPTARGETBLOCK_RESET_PARTICLE_MODE  0x200001
#define DFPTARGETBLOCK_RESET_PARTICLE_COUNT 0x14

STATIC_ASSERT(offsetof(DfpTargetBlockState, floorPoints) == 0x04);
STATIC_ASSERT(offsetof(DfpTargetBlockState, stateSfxId) == 0x64);
STATIC_ASSERT(offsetof(DfpTargetBlockState, completionSfxId) == 0x66);
STATIC_ASSERT(offsetof(DfpTargetBlockState, floorPointCount) == 0x68);
STATIC_ASSERT(offsetof(DfpTargetBlockState, mode) == 0x69);
STATIC_ASSERT(sizeof(DfpTargetBlockState) == 0x6C);

void dfptargetblock_update(DfpTargetBlockObject *obj);
void dfptargetblock_resolveCollisionPoints(DfpTargetBlockObject* obj,
                                           DfpTargetBlockCollisionPoints* collisionPoints);
void dfptargetblock_init(DfpTargetBlockObject *obj, DfpTargetBlockPlacement* placement);
int dfptargetblock_getExtraSize(void);
int dfptargetblock_getObjectTypeId(void);
void dfptargetblock_free(DfpTargetBlockObject* obj);
void dfptargetblock_render(DfpTargetBlockObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dfptargetblock_hitDetect(DfpTargetBlockObject* obj);
void dfptargetblock_release(void);
void dfptargetblock_initialise(void);
extern ObjectDescriptor10WithPadding gDfptargetblockObjDescriptor;

#endif /* MAIN_DLL_DLL_0235_DFPTARGETBLOCK_H_ */
