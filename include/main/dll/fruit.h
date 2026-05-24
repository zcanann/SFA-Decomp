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

struct DfpTargetBlockObject;

void dfptargetblock_hitDetect(struct DfpTargetBlockObject *obj);

#endif /* MAIN_DLL_FRUIT_H_ */
