#ifndef MAIN_DLL_DLL_0124_DEATHGAS_H_
#define MAIN_DLL_DLL_0124_DEATHGAS_H_

#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct DeathGasSetup
{
    ObjPlacement base;
    u8 drainRate;
    u8 fillRate;
    s16 activeGameBit;
} DeathGasSetup;

typedef struct DeathGasState
{
    f32 airRemaining;
    f32 damageTimer;
    f32 effectRadius;
    u8 fogOn : 1;
    u8 draining : 1;
    u8 noFog : 1;
    u8 pad0C : 5;
    u8 pad0D[3];
} DeathGasState;

STATIC_ASSERT(sizeof(DeathGasSetup) == 0x1c);
STATIC_ASSERT(offsetof(DeathGasSetup, drainRate) == 0x18);
STATIC_ASSERT(offsetof(DeathGasSetup, fillRate) == 0x19);
STATIC_ASSERT(offsetof(DeathGasSetup, activeGameBit) == 0x1a);
STATIC_ASSERT(sizeof(DeathGasState) == 0x10);
STATIC_ASSERT(offsetof(DeathGasState, airRemaining) == 0x0);
STATIC_ASSERT(offsetof(DeathGasState, damageTimer) == 0x4);
STATIC_ASSERT(offsetof(DeathGasState, effectRadius) == 0x8);

int DeathGas_getExtraSize(void);
void DeathGas_free(GameObject* obj);
void DeathGas_update(GameObject* obj);
void DeathGas_init(GameObject* obj);

#endif /* MAIN_DLL_DLL_0124_DEATHGAS_H_ */
