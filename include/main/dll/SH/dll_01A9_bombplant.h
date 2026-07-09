#ifndef MAIN_DLL_SH_SHKILLERMUSHROOM_H_
#define MAIN_DLL_SH_SHKILLERMUSHROOM_H_

#include "ghidra_import.h"
#include "main/dll/SH/SHrocketmushroom.h"

typedef struct BombPlantState {
    /* 0x00 */ f32 growTimer;
    /* 0x04 */ f32 growStartScale;
    /* 0x08 */ f32 growDuration;
    /* 0x0C */ f32 growTargetScale;
    /* 0x10 */ f32 growRate;
    /* 0x14 */ u8 stateIndex;
    /* 0x15 */ u8 flags;
} BombPlantState;

void BombPlantSpore_free(struct GameObject *obj);
void bombplantspore_startDriftBurst(struct GameObject *obj, void *state);
void bombplantspore_updateDrift(struct GameObject *obj, void *state);
int BombPlantSpore_getExtraSize(void);

#endif /* MAIN_DLL_SH_SHKILLERMUSHROOM_H_ */
