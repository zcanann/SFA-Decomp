#ifndef MAIN_DLL_DR_DRLASERTURRET_H_
#define MAIN_DLL_DR_DRLASERTURRET_H_

#include "ghidra_import.h"

#define DR_LASERTURRET_FLAG_ACTION_ACTIVE 0x08
#define DR_LASERTURRET_FLAG_START_SEQUENCE 0x02
#define DR_LASERTURRET_FLAG_CONFIRM_PROMPT 0x10

typedef struct DRLaserTurretState {
    u8 pad000[0x9b0];
    void *stateStack;
    void *linkedTarget;
    f32 bobAmplitude;
    f32 bobBaseY;
    f32 actionTimer;
    u8 pad9c4[0x9c8 - 0x9c4];
    s16 maxCount;
    u16 bobPhase;
    s16 countScale;
    s16 countTarget;
    s16 countValue;
    u8 nudgeCount;
    u8 pad9d3;
    u8 flags;
    u8 digitCount;
    u8 promptState;
} DRLaserTurretState;

int fn_801E6B10(void *obj, void *param2);
int objAnimFn_801e6d08(void *obj, void *param2);
int fn_801E7124(void *obj);
int fn_801E71A4(void *obj, void *param2, int dispatch);
void objCbSet30sTimer_801e75ec(void *obj);

#endif /* MAIN_DLL_DR_DRLASERTURRET_H_ */
