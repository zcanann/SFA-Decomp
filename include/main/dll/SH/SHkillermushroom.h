#ifndef MAIN_DLL_SH_SHKILLERMUSHROOM_H_
#define MAIN_DLL_SH_SHKILLERMUSHROOM_H_

#include "ghidra_import.h"

typedef struct BombPlantSporeState {
    /* 0x000 */ f32 fadeValue;
    /* 0x004 */ f32 fadeFrom;
    /* 0x008 */ f32 fadeTime;
    /* 0x00C */ f32 fadeTarget;
    /* 0x010 */ f32 fadeRate;
    /* 0x014 */ u8 stateIndex;
    /* 0x015 */ u8 flags;
    /* 0x016 */ u8 pad016[0x270 - 0x016];
    /* 0x270 */ void *light;
    /* 0x274 */ u8 pad274[0x278 - 0x274];
    /* 0x278 */ f32 driftRadius;
    /* 0x27C */ f32 driftRadiusRate;
    /* 0x280 */ f32 driftRadiusTarget;
    /* 0x284 */ f32 unk284;
    /* 0x288 */ f32 driftSin;
    /* 0x28C */ f32 driftCos;
    /* 0x290 */ f32 burstSin;
    /* 0x294 */ f32 burstCos;
    /* 0x298 */ f32 unk298;
    /* 0x29C */ f32 unk29c;
    /* 0x2A0 */ f32 unk2a0;
    /* 0x2A4 */ u8 pad2a4[0x2a8 - 0x2a4];
    /* 0x2A8 */ s16 driftAngle;
    /* 0x2AA */ s16 burstAngle;
    /* 0x2AC */ s16 driftAngleStep;
    /* 0x2AE */ u8 pad2ae[0x2b4 - 0x2ae];
} BombPlantSporeState;

void bombplantspore_free(void *obj);
void bombplantspore_startDriftBurst(void *obj, void *state);
void bombplantspore_updateDrift(void *obj, void *state);
int bombplantspore_getExtraSize(void);

#endif /* MAIN_DLL_SH_SHKILLERMUSHROOM_H_ */
