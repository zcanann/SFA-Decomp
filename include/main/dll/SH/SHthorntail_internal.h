#ifndef MAIN_DLL_SH_SHTHORNTAIL_INTERNAL_H_
#define MAIN_DLL_SH_SHTHORNTAIL_INTERNAL_H_

#include "global.h"
#include "ghidra_import.h"
#include "dolphin/mtx.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"
#include "main/sky_interface.h"

typedef struct SHthorntailConfig {
  u8 pad00[0x04];
  f32 baseScale;
  Vec homePos;
  s32 configToken;
  u8 controlMode;
  u8 initialFacingByte;
  u8 impactSfxVariant;
  u8 leashRadiusByte;
  u16 initScale;
} SHthorntailConfig;

#define SHTHORNTAIL_LINKED_CONFIG_GROUP_COUNT 6
#define SHTHORNTAIL_LINKED_CONFIG_COUNT 3
#define SHTHORNTAIL_HIT_REACT_ENTRY_COUNT 25
#define SHTHORNTAIL_STATE_MOVE_ID_COUNT 18
#define SHTHORNTAIL_STATE_STEP_SCALE_COUNT 17
#define SHTHORNTAIL_STATE_FLAG_BYTES 0x14
#define SHTHORNTAIL_STATE_TRIGGER0_SFX_COUNT 18
#define SHTHORNTAIL_STATE_TRIGGER7_SFX_BYTES 0x14
#define SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES 0x0C

typedef struct SHthorntailLinkedConfigRow {
  s32 configToken;
  s32 linkedConfigTokens[SHTHORNTAIL_LINKED_CONFIG_COUNT];
} SHthorntailLinkedConfigRow;

typedef struct SHthorntailDataTables {
  SHthorntailLinkedConfigRow linkedConfigRows[SHTHORNTAIL_LINKED_CONFIG_GROUP_COUNT];
  u8 pathHeaders[0x30];
  u8 pathControlData[0x10];
  ObjHitReactEntry normalHitReactEntries[SHTHORNTAIL_HIT_REACT_ENTRY_COUNT];
  ObjHitReactEntry heavyHitReactEntries[SHTHORNTAIL_HIT_REACT_ENTRY_COUNT];
  s16 stateMoveIds[SHTHORNTAIL_STATE_MOVE_ID_COUNT];
  f32 stateMoveStepScales[SHTHORNTAIL_STATE_STEP_SCALE_COUNT];
  u8 stateFlags[SHTHORNTAIL_STATE_FLAG_BYTES];
  u16 stateTrigger0Sfx[SHTHORNTAIL_STATE_TRIGGER0_SFX_COUNT];
  u8 stateTrigger7Sfx[SHTHORNTAIL_STATE_TRIGGER7_SFX_BYTES];
  u8 levelMode0DefaultImpactSfxTable[0x10];
  u8 levelMode0Locomotion1ImpactSfxVariants[SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES];
  u8 levelMode0Locomotion2ClearImpactSfxVariants[SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES];
  u8 levelMode0Locomotion2SetImpactSfxVariants[SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES];
  u8 levelMode0Locomotion3ClearImpactSfxVariants[SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES];
  u8 levelMode0Locomotion3SetImpactSfxVariants[SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES];
  u8 levelMode0Locomotion5ClearImpactSfxVariants[SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES];
  u8 levelMode0Locomotion8ImpactSfxVariants[SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES];
} SHthorntailDataTables;

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
  u8 moveScratch[0x7DC - 0x644];
  s16 moveControlPitch;
  s16 moveControlRoll;
  u8 moveScratchTail[0x89F - 0x7E0];
  u8 activeMoveValid;
  u8 pad8A0[0x8AC - 0x8A0];
  u8 hitReactScratch[0x8B0 - 0x8AC];
  u8 collisionShapeState[0x8E0 - 0x8B0];
  Vec renderPathPoints[4];
  float proximityAlertState;
} SHthorntailRuntime;

typedef struct SHthorntailObject {
  union {
    ObjAnimComponent anim;
    struct {
      s16 facingAngle;
      s16 pitch;
      s16 roll;
      u8 pad06[0x08 - 0x06];
      f32 modelScale;
      Vec modelPos;
      Vec pos;
      f32 velocityX;
      f32 velocityY;
      u8 pad2C[0x46 - 0x2C];
      s16 objType;
      u8 pad48[0x4C - 0x48];
      SHthorntailConfig *config;
      u8 pad50[0xA0 - 0x50];
      s16 currentMove;
      u8 padA2[0xA8 - 0xA2];
      f32 cullRadius;
      s8 animObjId;
      u8 padAD[0xAF - 0xAD];
      u8 statusFlags;
    };
  };
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  SHthorntailRuntime *runtime;
  void *animEventCallback;
} SHthorntailObject;

STATIC_ASSERT(offsetof(SHthorntailObject, anim) == 0x00);
STATIC_ASSERT(offsetof(SHthorntailObject, facingAngle) == offsetof(ObjAnimComponent, rotX));
STATIC_ASSERT(offsetof(SHthorntailObject, modelScale) == offsetof(ObjAnimComponent, rootMotionScale));
STATIC_ASSERT(offsetof(SHthorntailObject, modelPos) == offsetof(ObjAnimComponent, localPosX));
STATIC_ASSERT(offsetof(SHthorntailObject, pos) == offsetof(ObjAnimComponent, worldPosX));
STATIC_ASSERT(offsetof(SHthorntailObject, objType) == offsetof(ObjAnimComponent, seqId));
STATIC_ASSERT(offsetof(SHthorntailObject, config) == offsetof(ObjAnimComponent, placementData));
STATIC_ASSERT(offsetof(SHthorntailObject, currentMove) == offsetof(ObjAnimComponent, currentMove));
STATIC_ASSERT(offsetof(SHthorntailObject, cullRadius) == offsetof(ObjAnimComponent, hitboxScale));
STATIC_ASSERT(offsetof(SHthorntailObject, animObjId) == offsetof(ObjAnimComponent, mapEventSlot));
STATIC_ASSERT(offsetof(SHthorntailObject, statusFlags) == offsetof(ObjAnimComponent, resetHitboxFlags));
STATIC_ASSERT(offsetof(SHthorntailObject, objectFlags) == 0xB0);
STATIC_ASSERT(offsetof(SHthorntailObject, runtime) == 0xB8);
STATIC_ASSERT(offsetof(SHthorntailObject, animEventCallback) == 0xBC);
STATIC_ASSERT(offsetof(SHthorntailConfig, baseScale) == 0x04);
STATIC_ASSERT(offsetof(SHthorntailConfig, homePos) == 0x08);
STATIC_ASSERT(offsetof(SHthorntailConfig, configToken) == 0x14);

typedef struct SHthorntailEventInterface {
  u8 pad00[0x44];
  void (*triggerEvent)(int,int);
  u8 pad48[0x4C - 0x48];
  int (*getAnimEvent)(int,int);
  void (*setAnimEvent)(int,int,int);
} SHthorntailEventInterface;

typedef struct SHthorntailPathControlInterface {
  u8 pad00[0x04];
  void (*initControl)(int control,int mode,int flags,int loopMode);
  u8 pad08[0x0C - 0x08];
  void (*attachPathData)(int control,int channel,u8 *headers,u8 *pathData,u32 *events);
  void (*advanceControl)(SHthorntailObject *obj,u8 *control,f32 deltaTime);
  void (*applyControl)(SHthorntailObject *obj,u8 *control);
  void (*finishControl)(SHthorntailObject *obj,u8 *control,f32 deltaTime);
  u8 pad1C[0x20 - 0x1C];
  void (*bindObject)(SHthorntailObject *obj,int control);
} SHthorntailPathControlInterface;

#define SHTHORNTAIL_FLAG_MOVE_COMPLETE 0x01
#define SHTHORNTAIL_FLAG_IMPACT_PENDING 0x02
#define SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING 0x04
#define SHTHORNTAIL_FLAG_LEVELCONTROL_READY 0x08
#define SHTHORNTAIL_FLAG_FREEZE_MOTION 0x10
#define SHTHORNTAIL_OBJECT_STATUS_FREEZE_FRAME 0x08
#define SHTHORNTAIL_OBJECT_STATUS_ACTIVE 0x10
#define SHTHORNTAIL_OBJECT_STATUS_08 SHTHORNTAIL_OBJECT_STATUS_FREEZE_FRAME
#define SHTHORNTAIL_DUST_FLAG_BURST_READY 0x02
#define SHTHORNTAIL_DUST_FLAG_ACTIVE 0x04
#define SHTHORNTAIL_STATE_FLAG_STATUS_ACTIVE 0x01
#define SHTHORNTAIL_STATE_FLAG_HEAVY_HIT_REACT 0x02
#define SHTHORNTAIL_STATE_FLAG_DISABLE_MOVE_CONTROL 0x04
#define SHTHORNTAIL_STATE_FLAG_APPLY_ROOT_MOTION 0x08
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
#define SHTHORNTAIL_ALERT_VOLUME_ID 0x410
#define SHTHORNTAIL_EVENT_RESUME_VOLUME_ID 0x409
#define SHTHORNTAIL_TAIL_SWING_WINDUP_VOLUME_ID 0xA9
#define SHTHORNTAIL_TAIL_SWING_ACTIVE_VOLUME_ID 0xA8
#define SHTHORNTAIL_CLOSE_ATTACK_WAIT_MIN 500
#define SHTHORNTAIL_CLOSE_ATTACK_WAIT_MAX 800
#define SHTHORNTAIL_CLOSE_ATTACK_REPEAT_MIN 1
#define SHTHORNTAIL_CLOSE_ATTACK_REPEAT_MAX 3
#define SHTHORNTAIL_IDLE_WAIT_MIN 1000
#define SHTHORNTAIL_IDLE_WAIT_MAX 2000
#define SHTHORNTAIL_INVALID_STATE_PANIC_LINE 0x6CD
#define SHTHORNTAIL_ROOT_MODE3_LOCOMOTION2_GAMEBIT 0x0C2
#define SHTHORNTAIL_ROOT_MODE3_LOCOMOTION3_GAMEBIT 0x193
#define SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_GATE_GAMEBIT 0x23C
#define SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_EVENT_GAMEBIT 0x5BD
#define SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_PLAYER_GAMEBIT 0x23D
#define SHTHORNTAIL_ROOT_MODE3_LOCOMOTION6_GAMEBIT 0x13F
#define SHTHORNTAIL_ROOT_MODE3_LOCOMOTION7_GAMEBIT 0x199
#define SHTHORNTAIL_ROOT_MODE3_TRIGGER_EVENT 0x1D
#define SHTHORNTAIL_ROOT_MODE3_TRIGGER_ARG 3
#define SHTHORNTAIL_ROOT_MODE2_TRIGGER_SELECTOR_GAMEBIT 0x1A0
#define SHTHORNTAIL_ROOT_MODE2_TRIGGER_ANIM_EVENT 3
#define SHTHORNTAIL_PATH_CONTROL_MODE 3
#define SHTHORNTAIL_PATH_CONTROL_FLAGS 0xA3
#define SHTHORNTAIL_PATH_CHANNEL 4

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

void SHthorntail_updateTailSwing(u32 objectId,SHthorntailRuntime *runtime);
u32 SHthorntail_chooseNextState(SHthorntailObject *obj,SHthorntailRuntime *runtime,
                                 SHthorntailConfig *config);

#endif /* MAIN_DLL_SH_SHTHORNTAIL_INTERNAL_H_ */
