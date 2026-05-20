#ifndef MAIN_DLL_FRUIT_H_
#define MAIN_DLL_FRUIT_H_

#include "ghidra_import.h"

typedef union DfpTargetBlockControlId {
  u32 value;
  struct {
    u16 unused0;
    s16 triggerSfxId;
  } audio;
} DfpTargetBlockControlId;

typedef struct DfpTargetBlockAudioState {
  DfpTargetBlockControlId control;
  s16 specialSfxStopTimer;
  u8 effectEmitterActive;
  u8 unused7;
  u8 stopRequested;
  u8 unk09[0x5B];
  s16 stateSfxId;
  s16 completionSfxId;
  s8 floorPointCount;
  u8 mode;
  u8 stateSfxReady;
  u8 completionSfxReady;
} DfpTargetBlockAudioState;

typedef enum DfpTargetBlockAudioMode {
  DFPTARGETBLOCK_AUDIO_MODE_RAISING = 0,
  DFPTARGETBLOCK_AUDIO_MODE_ACTIVE = 1,
  DFPTARGETBLOCK_AUDIO_MODE_RESETTING = 2,
  DFPTARGETBLOCK_AUDIO_MODE_LOWERING = 3,
  DFPTARGETBLOCK_AUDIO_MODE_SETTLED = 4,
} DfpTargetBlockAudioMode;

undefined4 dfptargetblock_hitDetect(int param_1,undefined4 param_2,int param_3);
void dfptargetblock_updateAudioState(uint param_1);
void dfptargetblock_updateAudioStateWrapper(uint param_1);
void FUN_802089e8(undefined2 *param_1,int param_2);
void FUN_802089ec(void);
void FUN_80208a0c(void);
void dfptargetblock_resolveCollision(int *param_1,int param_2);
void FUN_80208c28(int param_1);

#endif /* MAIN_DLL_FRUIT_H_ */
