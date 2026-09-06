#ifndef MAIN_DLL_DLL_0029_EFFECT16_H_
#define MAIN_DLL_DLL_0029_EFFECT16_H_

#include "main/dll/partfx_interface.h"

int Effect16_spawnObject(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                         s16* extraArgs);
void Effect16_updateFrameState(void);
void Effect16_func03_nop(void);
void Effect16_release(void);
void Effect16_initialise(void);

#endif /* MAIN_DLL_DLL_0029_EFFECT16_H_ */
