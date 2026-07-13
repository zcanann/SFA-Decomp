#ifndef MAIN_DLL_DLL_0020_EFFECT7_H_
#define MAIN_DLL_DLL_0020_EFFECT7_H_

#include "main/dll/partfx_interface.h"

void Effect7_func03_nop(void);
void Effect7_release(void);
void Effect7_initialise(void);
void Effect7_func05(void);
int Effect7_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                   s16* extraArgs);

#endif /* MAIN_DLL_DLL_0020_EFFECT7_H_ */
