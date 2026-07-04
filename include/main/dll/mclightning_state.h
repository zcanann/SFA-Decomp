#ifndef MAIN_DLL_MCLIGHTNING_STATE_H_
#define MAIN_DLL_MCLIGHTNING_STATE_H_

#include "ghidra_import.h"
#include "global.h"

enum McLightningPhase {
    MCLIGHTNING_PHASE_READ_PARAM_A = 0,
    MCLIGHTNING_PHASE_READ_PARAM_B = 1,
    MCLIGHTNING_PHASE_READ_PARAM_C = 2,
    MCLIGHTNING_PHASE_READ_PARAM_D = 3,
    MCLIGHTNING_PHASE_READ_TARGET = 4,
    MCLIGHTNING_PHASE_ARMED = 5,
    MCLIGHTNING_PHASE_ACTIVE = 6,
    MCLIGHTNING_PHASE_ABORTED = 0xa
};

typedef struct McLightningFlags {
    u8 phase : 4;
    u8 spawnFlags : 4;
} McLightningFlags;

typedef struct McLightningState {
    void *boltHandle;
    f32 boltFrameTimer;
    f32 boltParamA;
    f32 boltParamB;
    f32 hitEffectScale;
    f32 burstEffectChance;
    u8 boltParamC;
    u8 boltParamD;
    u8 targetLinkId;
    McLightningFlags flags;
} McLightningState;

STATIC_ASSERT(sizeof(McLightningState) == 0x1C);
STATIC_ASSERT(offsetof(McLightningState, boltHandle) == 0x00);
STATIC_ASSERT(offsetof(McLightningState, boltFrameTimer) == 0x04);
STATIC_ASSERT(offsetof(McLightningState, boltParamA) == 0x08);
STATIC_ASSERT(offsetof(McLightningState, boltParamB) == 0x0C);
STATIC_ASSERT(offsetof(McLightningState, hitEffectScale) == 0x10);
STATIC_ASSERT(offsetof(McLightningState, burstEffectChance) == 0x14);
STATIC_ASSERT(offsetof(McLightningState, boltParamC) == 0x18);
STATIC_ASSERT(offsetof(McLightningState, boltParamD) == 0x19);
STATIC_ASSERT(offsetof(McLightningState, targetLinkId) == 0x1A);
STATIC_ASSERT(offsetof(McLightningState, flags) == 0x1B);

#endif /* MAIN_DLL_MCLIGHTNING_STATE_H_ */
