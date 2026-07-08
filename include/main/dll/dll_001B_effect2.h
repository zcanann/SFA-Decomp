#ifndef MAIN_DLL_DLL_001B_EFFECT2_H_
#define MAIN_DLL_DLL_001B_EFFECT2_H_

#include "main/effect_interfaces.h"

/* Per-config velocity-range band count (emit[6]/sub[6]/col[6] parallel tables). */
#define EFFECT2_VELOCITY_RANGE_COUNT 6

typedef struct EmitterCfg
{
    f32 vel[7][3];
    f32 lifetimeRange[3];
    f32 textureId;
    int emit[EFFECT2_VELOCITY_RANGE_COUNT];
    int sub[EFFECT2_VELOCITY_RANGE_COUNT];
    u16 col[EFFECT2_VELOCITY_RANGE_COUNT];
    u8 alphaMin;
    u8 alphaMax;
    u8 pad[2];
} EmitterCfg;

void Effect2_func03_nop(void);
void Effect2_release(void);
void Effect2_initialise(void);
void Effect2_func05(void);
int Effect2_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                   s16* extraArgs);

#endif /* MAIN_DLL_DLL_001B_EFFECT2_H_ */
