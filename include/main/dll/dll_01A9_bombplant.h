#ifndef MAIN_DLL_DLL_01A9_BOMBPLANT_H_
#define MAIN_DLL_DLL_01A9_BOMBPLANT_H_

#include "main/game_object.h"

typedef struct BombPlantState
{
    /* 0x00 */ f32 growTimer;
    /* 0x04 */ f32 growStartScale;
    /* 0x08 */ f32 growDuration;
    /* 0x0C */ f32 growTargetScale;
    /* 0x10 */ f32 growRate;
    /* 0x14 */ u8 stateIndex;
    /* 0x15 */ u8 flags;
} BombPlantState;

void bombplant_throwSpore(int* obj, int* p2);

#endif /* MAIN_DLL_DLL_01A9_BOMBPLANT_H_ */
