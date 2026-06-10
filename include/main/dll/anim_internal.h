#ifndef MAIN_DLL_ANIM_INTERNAL_H_
#define MAIN_DLL_ANIM_INTERNAL_H_

#include "global.h"

typedef struct AnimBehaviorConfig {
  u8 pad00[0x08];
  float targetPosX;
  float targetPosY;
  float targetPosZ;
  u8 pad14[0x19 - 0x14];
  u8 forceRadiusByte;
  u8 speedScaleByte;
  u8 facingAngleByte;
  s16 primaryConditionId;
  s16 secondaryConditionId;
  u8 pad20[0x24 - 0x20];
  s16 readyConditionId;
  u8 behaviorMode;
  u8 pad27[0x2C - 0x27];
  s16 activationEventId;
} AnimBehaviorConfig;

typedef struct AnimBehaviorEventPayload {
  s16 queuedConditionId;
  s16 queuedConditionValue;
  float queuedConditionScale;
} AnimBehaviorEventPayload;

typedef struct AnimBehaviorState {
  u8 pad00[0x10C];
  float reboundVelocityX;
  float reboundVelocityY;
  float reboundVelocityZ;
  u8 state;
  u8 behaviorFlags;
  u8 pad11A[0x11C - 0x11A];
  AnimBehaviorEventPayload queuedEvent;
} AnimBehaviorState;

typedef struct AnimBehaviorObject {
  u8 pad00[0x4C];
  AnimBehaviorConfig *config;
  u8 pad50[0xAC - 0x50];
  s8 mapEventSlot;
  u8 padAD[0xAF - 0xAD];
  u8 statusFlags;
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  AnimBehaviorState *runtimeState;
} AnimBehaviorObject;

STATIC_ASSERT(offsetof(AnimBehaviorConfig, forceRadiusByte) == 0x19);
STATIC_ASSERT(offsetof(AnimBehaviorConfig, speedScaleByte) == 0x1A);
STATIC_ASSERT(offsetof(AnimBehaviorConfig, facingAngleByte) == 0x1B);
STATIC_ASSERT(offsetof(AnimBehaviorConfig, primaryConditionId) == 0x1C);
STATIC_ASSERT(offsetof(AnimBehaviorConfig, secondaryConditionId) == 0x1E);
STATIC_ASSERT(offsetof(AnimBehaviorConfig, readyConditionId) == 0x24);
STATIC_ASSERT(offsetof(AnimBehaviorConfig, behaviorMode) == 0x26);
STATIC_ASSERT(offsetof(AnimBehaviorConfig, activationEventId) == 0x2C);

STATIC_ASSERT(offsetof(AnimBehaviorState, reboundVelocityX) == 0x10C);
STATIC_ASSERT(offsetof(AnimBehaviorState, reboundVelocityY) == 0x110);
STATIC_ASSERT(offsetof(AnimBehaviorState, reboundVelocityZ) == 0x114);
STATIC_ASSERT(offsetof(AnimBehaviorState, state) == 0x118);
STATIC_ASSERT(offsetof(AnimBehaviorState, behaviorFlags) == 0x119);
STATIC_ASSERT(offsetof(AnimBehaviorState, queuedEvent) == 0x11C);

STATIC_ASSERT(offsetof(AnimBehaviorObject, config) == 0x4C);
STATIC_ASSERT(offsetof(AnimBehaviorObject, mapEventSlot) == 0xAC);
STATIC_ASSERT(offsetof(AnimBehaviorObject, statusFlags) == 0xAF);
STATIC_ASSERT(offsetof(AnimBehaviorObject, objectFlags) == 0xB0);
STATIC_ASSERT(offsetof(AnimBehaviorObject, runtimeState) == 0xB8);

#endif /* MAIN_DLL_ANIM_INTERNAL_H_ */
