#ifndef MAIN_DLL_ZBOMB_H_
#define MAIN_DLL_ZBOMB_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

typedef struct DfpTargetBlockPoint {
  f32 x;
  f32 y;
  f32 z;
} DfpTargetBlockPoint;

typedef struct DfpTargetBlockState {
  u32 controlId;
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

void dfptargetblock_update(int obj);
void dfptargetblock_init(int obj,int params);
void dfptargetblock_release(void);
void dfptargetblock_initialise(void);
extern ObjectDescriptor10WithPadding gDfptargetblockObjDescriptor;

#endif /* MAIN_DLL_ZBOMB_H_ */
