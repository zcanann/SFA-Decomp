#ifndef MAIN_DLL_DLL_001A_EFFECT1_H_
#define MAIN_DLL_DLL_001A_EFFECT1_H_

#include "main/dll/partfx_interface.h"
#include "types.h"

void Effect1_func03_nop(void);
void Effect1_release(void);
void Effect1_initialise(void);
void Effect1_updateFrameState(void);
int Effect1_spawnObject(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                        s16* extraArgs);

#endif /* MAIN_DLL_DLL_001A_EFFECT1_H_ */
