#ifndef MAIN_DLL_DLL_001C_EFFECT3_H_
#define MAIN_DLL_DLL_001C_EFFECT3_H_

#include "main/dll/partfx_interface.h"

void Effect3_func05_nop(void);
void Effect3_func03_nop(void);
void Effect3_release(void);
void Effect3_initialise(void);
int Effect3_func04(s16* sourceObj, int effectId, PartFxSpawnParams* spawnParamsIn, u32 spawnFlags, u8 modelId,
                   f32* extraArgs);

#endif /* MAIN_DLL_DLL_001C_EFFECT3_H_ */
