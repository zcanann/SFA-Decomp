#ifndef MAIN_DLL_DOOR_H_
#define MAIN_DLL_DOOR_H_

#include "ghidra_import.h"

typedef struct DfpTargetBlockAudioState DfpTargetBlockAudioState;

typedef struct DfpTargetBlockHome {
  u8 pad00[0x08];
  f32 x;
  f32 y;
  f32 z;
} DfpTargetBlockHome;

typedef struct DfpTargetBlockObject {
  u8 pad00[0x0C];
  f32 x;
  f32 y;
  f32 z;
  u8 pad18[0x0C];
  f32 velX;
  f32 velY;
  f32 velZ;
  u8 pad30[0x46 - 0x30];
  s16 objectType;
  u8 pad48[0x4C - 0x48];
  DfpTargetBlockHome *home;
  u8 pad50[0x80 - 0x50];
  f32 prevX;
  f32 prevY;
  f32 prevZ;
  u8 pad8C[0xAC - 0x8C];
  s8 mapId;
  u8 padAD[0xB8 - 0xAD];
  DfpTargetBlockAudioState *state;
} DfpTargetBlockObject;

typedef struct DfpTargetBlockCollisionPoints {
  u8 pointData[0x64];
  u8 pad64[0x68 - 0x64];
  s8 count;
} DfpTargetBlockCollisionPoints;

void dfptargetblock_resolveCollisionPoints(DfpTargetBlockObject *obj,
                                           DfpTargetBlockCollisionPoints *collisionPoints);
int dfptargetblock_getExtraSize(void);
int dfptargetblock_getObjectTypeId(void);
void dfptargetblock_free(void);
void dfptargetblock_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

#endif /* MAIN_DLL_DOOR_H_ */
