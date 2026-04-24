#ifndef MAIN_DLL_SH_SHTHORNTAIL_INTERNAL_H_
#define MAIN_DLL_SH_SHTHORNTAIL_INTERNAL_H_

#include "ghidra_import.h"
#include "dolphin/mtx.h"

typedef struct SHthorntailConfig {
  u8 pad00[0x08];
  Vec homePos;
  s32 configToken;
  u8 controlMode;
  u8 pad19[0x1B - 0x19];
  u8 leashRadiusByte;
} SHthorntailConfig;

typedef struct SHthorntailRuntime {
  u8 pad00[0x611];
  u8 movementControlFlags;
  u8 pad612[0x624 - 0x612];
  u8 behaviorState;
  u8 behaviorFlags;
  u8 locomotionMode;
  u8 tailSwingState;
  float tailSwingTimer;
  u8 *impactSfxIds;
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
  u8 collisionShapeState[0x8E0 - 0x8AC];
  Vec renderPathPoints[4];
  float proximityAlertState;
} SHthorntailRuntime;

typedef struct SHthorntailObject {
  u8 pad00[0x4C];
  SHthorntailConfig *config;
  u8 pad50[0xB8 - 0x50];
  SHthorntailRuntime *runtime;
} SHthorntailObject;

#define SHTHORNTAIL_FLAG_MOVE_COMPLETE 0x01
#define SHTHORNTAIL_FLAG_IMPACT_PENDING 0x02
#define SHTHORNTAIL_FLAG_LEVELCONTROL_READY 0x08
#define SHTHORNTAIL_FLAG_FREEZE_MOTION 0x10
#define SHTHORNTAIL_RENDER_PATH_POINT_COUNT 4

extern s32 gSHthorntailActiveConfigToken;

void SHthorntail_updateTailSwing(uint objectId,SHthorntailRuntime *runtime);
uint SHthorntail_chooseNextState(short *obj,SHthorntailRuntime *runtime,SHthorntailConfig *config);

#endif /* MAIN_DLL_SH_SHTHORNTAIL_INTERNAL_H_ */
