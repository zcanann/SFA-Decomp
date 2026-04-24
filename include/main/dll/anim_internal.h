#ifndef MAIN_DLL_ANIM_INTERNAL_H_
#define MAIN_DLL_ANIM_INTERNAL_H_

#include "ghidra_import.h"

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
  s8 modeIndex;
  u8 padAD[0xAF - 0xAD];
  u8 statusFlags;
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  AnimBehaviorState *runtimeState;
} AnimBehaviorObject;

#endif /* MAIN_DLL_ANIM_INTERNAL_H_ */
