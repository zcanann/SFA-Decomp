#ifndef MAIN_DLL_DLL_0022_EFFECT9_H_
#define MAIN_DLL_DLL_0022_EFFECT9_H_

#include "types.h"
#include "main/effect_interfaces.h"

void Effect9_func03_nop(void);
void Effect9_release(void);
void Effect9_initialise(void);
int Effect9_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                   s16* extraArgs);
void Effect9_func05(void);

#endif /* MAIN_DLL_DLL_0022_EFFECT9_H_ */
