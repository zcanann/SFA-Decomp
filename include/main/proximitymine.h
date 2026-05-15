#ifndef MAIN_PROXIMITYMINE_H_
#define MAIN_PROXIMITYMINE_H_

#include "ghidra_import.h"

typedef struct ProximityMineEffect {
  u8 unk0[0x4c];
  u8 visible;
  u8 unk4D[0x2f8 - 0x4d];
  u8 active;
} ProximityMineEffect;

typedef struct ProximityMineState {
  void *targetObj;
  ProximityMineEffect *effectHandle;
  f32 triggerDistance;
  f32 verticalStep;
  u8 unk10[4];
  u8 renderTimer[4];
  u8 launchTimer[4];
  u8 resetTimer[4];
  u8 bounceTimer[4];
  u8 initTimer[4];
  u8 lifespanTimer[4];
  s8 mode;
  u8 unk2D;
  u8 flashMode;
  u8 unk2F;
  u8 effectVisible;
  u8 unk31[3];
} ProximityMineState;

typedef struct ProximityMineCollider {
  u8 unk0[0x50];
  void *hitObj;
  u8 unk54[0x59];
  s8 hitFlag;
} ProximityMineCollider;

typedef struct ProximityMineObject {
  s16 angle;
  u8 unk02[6];
  f32 height;
  f32 posX;
  f32 posY;
  f32 posZ;
  u8 unk18[0xc];
  f32 velocityX;
  f32 velocityY;
  f32 velocityZ;
  u8 unk30[0x16];
  s16 objId;
  u8 unk48[0xc];
  ProximityMineCollider *collider;
  u8 unk58[0x60];
  ProximityMineState *state;
  u8 unkBC[8];
  void *pendingTarget;
} ProximityMineObject;

typedef struct ProximityMineDef {
  u8 unk0[0x18];
  s8 angleSeed;
  s8 mode;
  s16 parameter;
} ProximityMineDef;

#endif /* MAIN_PROXIMITYMINE_H_ */
