#ifndef MAIN_DLL_DLL_001F_EFFECT6_H_
#define MAIN_DLL_DLL_001F_EFFECT6_H_

#include "main/effect_interfaces.h"

void Effect6_func03_nop(void);
void Effect6_release(void);
void Effect6_initialise(void);
int Effect6_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                   u16* extraArgs);
void Effect6_func05(void);

#endif /* MAIN_DLL_DLL_001F_EFFECT6_H_ */
