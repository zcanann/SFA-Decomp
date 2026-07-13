#ifndef MAIN_DLL_DLL_01AA_BOMBPLANTSPORE_H_
#define MAIN_DLL_DLL_01AA_BOMBPLANTSPORE_H_

#include "main/game_object.h"

typedef struct BombPlantSporeState
{
    /* 0x000 */ u16 damageType;
    /* 0x002 */ u8 pad02[0x08 - 0x02];
    /* 0x008 */ u8 pathState[0x270 - 0x08];
    /* 0x270 */ void* light;
    /* 0x274 */ f32 fuseTimer;
    /* 0x278 */ f32 driftAmplitude;
    /* 0x27C */ f32 driftSpeed;
    /* 0x280 */ f32 randomPhase;
    /* 0x284 */ f32 driftTimer;
    /* 0x288 */ f32 driftBaseX;
    /* 0x28C */ f32 driftBaseZ;
    /* 0x290 */ f32 driftSin;
    /* 0x294 */ f32 driftCos;
    /* 0x298 */ f32 spinTimer;
    /* 0x29C */ f32 driftSpeedTarget;
    /* 0x2A0 */ f32 spinChangeTimer;
    /* 0x2A4 */ f32 detonateTimer;
    /* 0x2A8 */ s16 currentSpinAngle;
    /* 0x2AA */ s16 burstDriftAngle;
    /* 0x2AC */ s16 spinAngle;
    /* 0x2AE */ s16 yawStep;
    /* 0x2B0 */ u8 stateFlags;
} BombPlantSporeState;

STATIC_ASSERT(offsetof(BombPlantSporeState, pathState) == 0x08);
STATIC_ASSERT(offsetof(BombPlantSporeState, light) == 0x270);
STATIC_ASSERT(offsetof(BombPlantSporeState, fuseTimer) == 0x274);
STATIC_ASSERT(offsetof(BombPlantSporeState, randomPhase) == 0x280);
STATIC_ASSERT(offsetof(BombPlantSporeState, driftSpeedTarget) == 0x29C);
STATIC_ASSERT(offsetof(BombPlantSporeState, detonateTimer) == 0x2A4);
STATIC_ASSERT(offsetof(BombPlantSporeState, spinAngle) == 0x2AC);
STATIC_ASSERT(offsetof(BombPlantSporeState, yawStep) == 0x2AE);
STATIC_ASSERT(offsetof(BombPlantSporeState, stateFlags) == 0x2B0);

void BombPlantSpore_init(GameObject* obj, void* param2);
void BombPlantSpore_update(GameObject* obj);
void BombPlantSpore_free(GameObject* obj);
int BombPlantSpore_getExtraSize(void);

#endif /* MAIN_DLL_DLL_01AA_BOMBPLANTSPORE_H_ */
