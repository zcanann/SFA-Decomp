#ifndef MAIN_DLL_SH_SHTHORNTAIL_INTERNAL_H_
#define MAIN_DLL_SH_SHTHORNTAIL_INTERNAL_H_

#include "global.h"
#include "ghidra_import.h"
#include "dolphin/mtx.h"

typedef struct SHthorntailConfig {
  u8 pad00[0x08];
  Vec homePos;
  s32 configToken;
  u8 controlMode;
  u8 initialFacingByte;
  u8 impactSfxVariant;
  u8 leashRadiusByte;
  u16 initScale;
} SHthorntailConfig;

typedef struct SHthorntailRuntime {
  u8 pad00[0x04];
  float dustEffectTimer;
  u8 pad08[0xD4 - 0x08];
  u8 dustEffectFlags;
  u8 padD5[0x611 - 0xD5];
  u8 movementControlFlags;
  u8 pad612[0x624 - 0x612];
  s8 behaviorState;
  u8 behaviorFlags;
  u8 locomotionMode;
  u8 tailSwingState;
  float tailSwingTimer;
  u8 *impactSfxTable;
  float idleTimer;
  float comboTimer;
  float effectTimer;
  s16 storedFacingAngle;
  s8 comboRepeatCount;
  u8 freezeFrameCounter;
  u8 hitReactState;
  u8 pad641[0x644 - 0x641];
  u8 moveScratch[0x89F - 0x644];
  u8 activeMoveValid;
  u8 pad8A0[0x8AC - 0x8A0];
  u8 hitReactScratch[0x8B0 - 0x8AC];
  u8 collisionShapeState[0x8E0 - 0x8B0];
  Vec renderPathPoints[4];
  float proximityAlertState;
} SHthorntailRuntime;

typedef struct SHthorntailObject {
  u8 pad00[0x18];
  Vec pos;
  u8 pad24[0x46 - 0x24];
  s16 objType;
  u8 pad48[0x4C - 0x48];
  SHthorntailConfig *config;
  u8 pad50[0xAC - 0x50];
  s8 animObjId;
  u8 padAD[0xAF - 0xAD];
  u8 statusFlags;
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  SHthorntailRuntime *runtime;
} SHthorntailObject;

typedef struct SHthorntailAnimationInterface {
  u8 pad00[0x24];
  int (*isTailSwingQueued)(int);
} SHthorntailAnimationInterface;

typedef struct SHthorntailEventInterface {
  u8 pad00[0x44];
  void (*triggerEvent)(int,int);
  u8 pad48[0x50 - 0x48];
  void (*setAnimEvent)(int,int,int);
} SHthorntailEventInterface;

#define SHTHORNTAIL_FLAG_MOVE_COMPLETE 0x01
#define SHTHORNTAIL_FLAG_IMPACT_PENDING 0x02
#define SHTHORNTAIL_FLAG_LEVELCONTROL_READY 0x08
#define SHTHORNTAIL_FLAG_FREEZE_MOTION 0x10
#define SHTHORNTAIL_OBJECT_STATUS_08 0x08
#define SHTHORNTAIL_STATE_IDLE 0x00
#define SHTHORNTAIL_STATE_IDLE_COUNTDOWN 0x01
#define SHTHORNTAIL_STATE_MOVE_2 0x02
#define SHTHORNTAIL_STATE_MOVE_3 0x03
#define SHTHORNTAIL_STATE_MOVE_4 0x04
#define SHTHORNTAIL_STATE_MOVE_5 0x05
#define SHTHORNTAIL_STATE_TURN_HOME 0x06
#define SHTHORNTAIL_STATE_CLOSE_ATTACK 0x07
#define SHTHORNTAIL_STATE_CLOSE_ATTACK_WAIT 0x08
#define SHTHORNTAIL_STATE_CLOSE_ATTACK_REPEAT 0x09
#define SHTHORNTAIL_STATE_CLOSE_ATTACK_RECOVER 0x0A
#define SHTHORNTAIL_STATE_TAIL_SWING_READY 0x0B
#define SHTHORNTAIL_STATE_TAIL_SWING 0x0C
#define SHTHORNTAIL_STATE_TAIL_SWING_RECOVER 0x0D
#define SHTHORNTAIL_STATE_EVENT_PAUSE 0x0E
#define SHTHORNTAIL_STATE_ROOT_MODE2_EVENT 0x0F
#define SHTHORNTAIL_STATE_ROOT_MODE3_WAIT 0x10
#define SHTHORNTAIL_TAIL_SWING_READY 0x00
#define SHTHORNTAIL_TAIL_SWING_WINDUP 0x01
#define SHTHORNTAIL_TAIL_SWING_ACTIVE 0x02
#define SHTHORNTAIL_TAIL_SWING_STATE_COUNT 0x03
#define SHTHORNTAIL_LOCOMOTION_DEFAULT 0
#define SHTHORNTAIL_LOCOMOTION_1 1
#define SHTHORNTAIL_LOCOMOTION_2 2
#define SHTHORNTAIL_LOCOMOTION_3 3
#define SHTHORNTAIL_LOCOMOTION_4 4
#define SHTHORNTAIL_LOCOMOTION_5 5
#define SHTHORNTAIL_LOCOMOTION_6 6
#define SHTHORNTAIL_LOCOMOTION_7 7
#define SHTHORNTAIL_LOCOMOTION_8 8
#define SHTHORNTAIL_CONTROL_MODE_LEVEL_0 0
#define SHTHORNTAIL_CONTROL_MODE_LEVEL_1 1
#define SHTHORNTAIL_CONTROL_MODE_ROOT_2 2
#define SHTHORNTAIL_CONTROL_MODE_ROOT_3 3
#define SHTHORNTAIL_RENDER_PATH_POINT_COUNT 4
#define SHTHORNTAIL_CONFIG_TOKEN_NONE -1
#define SHTHORNTAIL_EXTRA_STATE_BYTES 0x914

extern s32 gSHthorntailActiveConfigToken;
extern u8 gSHthorntailLevelControlMode1ImpactSfxTable;
extern u8 gSHthorntailLevelControlMode0DefaultImpactSfxTable[];
extern u8 gSHthorntailLevelControlMode0Locomotion6ImpactSfxTable;
extern u8 gSHthorntailRootControlMode2DefaultImpactSfxTable;
extern u8 gSHthorntailRootControlMode2Locomotion8ImpactSfxTable[];
extern u8 gSHthorntailRootControlMode3Locomotion1ImpactSfxTable;
extern u8 gSHthorntailRootControlMode3LocomotionDefaultImpactSfxTable;
extern u8 gSHthorntailRootControlMode3Locomotion2ImpactSfxTable;
extern u8 gSHthorntailRootControlMode3Locomotion2AltImpactSfxTable[];
extern u8 gSHthorntailRootControlMode3Locomotion3ImpactSfxTable;
extern u8 gSHthorntailRootControlMode3Locomotion4ImpactSfxTable;
extern u8 gSHthorntailRootControlMode3Locomotion5IdleImpactSfxTable;
extern u8 gSHthorntailRootControlMode3Locomotion5EventImpactSfxTable;
extern u8 gSHthorntailRootControlMode3Locomotion5PlayerImpactSfxTable;
extern u8 gSHthorntailRootControlMode3Locomotion6ImpactSfxTable;
extern u8 gSHthorntailRootControlMode3Locomotion7ImpactSfxTable;
extern u8 gSHthorntailRootControlMode3Locomotion8ImpactSfxTable;

STATIC_ASSERT(sizeof(SHthorntailRuntime) == SHTHORNTAIL_EXTRA_STATE_BYTES);

static inline s16 SHthorntail_GetLinkedGameBit(SHthorntailConfig *config) {
  return *(s16 *)&config->controlMode;
}

void SHthorntail_updateTailSwing(uint objectId,SHthorntailRuntime *runtime);
uint SHthorntail_chooseNextState(SHthorntailObject *obj,SHthorntailRuntime *runtime,
                                 SHthorntailConfig *config);

#endif /* MAIN_DLL_SH_SHTHORNTAIL_INTERNAL_H_ */
