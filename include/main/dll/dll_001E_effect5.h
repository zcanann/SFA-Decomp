#ifndef MAIN_DLL_DLL_001E_EFFECT5_H_
#define MAIN_DLL_DLL_001E_EFFECT5_H_

#include "main/dll/partfx_interface.h"

void Effect5_func03_nop(void);
void Effect5_release(void);
void Effect5_initialise(void);
int Effect5_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                   s16* extraArgs);
void Effect5_func05(void);

#endif /* MAIN_DLL_DLL_001E_EFFECT5_H_ */
