#ifndef MAIN_DLL_DOOR_H_
#define MAIN_DLL_DOOR_H_

#include "ghidra_import.h"

typedef struct DfpTargetBlockObject {
  u8 pad00[0x0C];
  f32 x;
  f32 y;
  f32 z;
  u8 pad18[0x0C];
  f32 velX;
  f32 velY;
  f32 velZ;
} DfpTargetBlockObject;

typedef struct DfpTargetBlockCollisionPoints {
  u8 pointData[0x64];
  u8 pad64[0x68 - 0x64];
  s8 count;
} DfpTargetBlockCollisionPoints;

void dfptargetblock_resolveCollisionPoints(DfpTargetBlockObject *obj,
                                           DfpTargetBlockCollisionPoints *collisionPoints);
int dfptargetblock_getExtraSize(void);
int dfptargetblock_func08(void);
void dfptargetblock_free(void);
void dfptargetblock_render(int obj);

#endif /* MAIN_DLL_DOOR_H_ */
