#ifndef MAIN_DLL_ZBOMB_H_
#define MAIN_DLL_ZBOMB_H_

#include "ghidra_import.h"
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

typedef struct DfpTargetBlockState {
  void *pathState;
  DfpTargetBlockPoint floorPoints[8];
  s16 stateSfxId;
  s16 completionSfxId;
  s8 floorPointCount;
  u8 mode;
  u8 stateSfxReady;
  u8 completionSfxReady;
} DfpTargetBlockState;

typedef enum DfpTargetBlockMode {
  DFPTARGETBLOCK_MODE_RAISING = 0,
  DFPTARGETBLOCK_MODE_ACTIVE = 1,
  DFPTARGETBLOCK_MODE_RESETTING = 2,
  DFPTARGETBLOCK_MODE_LOWERING = 3,
  DFPTARGETBLOCK_MODE_SETTLED = 4,
} DfpTargetBlockMode;

void dfptargetblock_update(DfpTargetBlockObject *obj);
void dfptargetblock_init(DfpTargetBlockObject *obj,int params);
void dfptargetblock_release(void);
void dfptargetblock_initialise(void);
extern ObjectDescriptor10WithPadding gDfptargetblockObjDescriptor;

#endif /* MAIN_DLL_ZBOMB_H_ */
