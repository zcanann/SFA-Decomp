#ifndef MAIN_DLL_DLL_002D_EFFECT20_H_
#define MAIN_DLL_DLL_002D_EFFECT20_H_

#include "main/dll/partfx_interface.h"
#include "global.h"

int Effect20_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                    f32* extraArgs);
void Effect20_func05(void);
void Effect20_func03_nop(void);
void Effect20_release(void);
void Effect20_initialise(void);

#endif /* MAIN_DLL_DLL_002D_EFFECT20_H_ */
