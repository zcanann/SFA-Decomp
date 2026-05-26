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

#define DFPTARGETBLOCK_HOME_OBJECT_TYPE 0x04E0
#define DFPTARGETBLOCK_HIT_TYPE_PUSH 0x0E
#define DFPTARGETBLOCK_IMPACT_SFX 0x044D
#define DFPTARGETBLOCK_LOOP_SFX 0x03BD
#define DFPTARGETBLOCK_RESET_SFX 0x01D3
#define DFPTARGETBLOCK_RESET_PARTICLE_ID 0x05F5
#define DFPTARGETBLOCK_RESET_PARTICLE_MODE 0x200001
#define DFPTARGETBLOCK_RESET_PARTICLE_COUNT 0x14

struct DfpTargetBlockObject;

void dfptargetblock_hitDetect(struct DfpTargetBlockObject *obj);

#endif /* MAIN_DLL_FRUIT_H_ */
