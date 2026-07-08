#ifndef MAIN_DLL_DLL_0021_EFFECT8_H_
#define MAIN_DLL_DLL_0021_EFFECT8_H_

#include "types.h"
#include "main/effect_interfaces.h"

void Effect8_func03_nop(void);
void Effect8_release(void);
void Effect8_initialise(void);
void Effect8_func05(void);
int Effect8_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                   s16* extraArgs);

#endif /* MAIN_DLL_DLL_0021_EFFECT8_H_ */
