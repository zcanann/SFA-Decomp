#ifndef MAIN_DLL_DLL_001D_EFFECT4_H_
#define MAIN_DLL_DLL_001D_EFFECT4_H_

#include "main/dll/partfx_interface.h"

void Effect4_func03_nop(void);
void Effect4_release(void);
void Effect4_initialise(void);
void Effect4_updateFrameState(void);
int Effect4_spawnObject(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                        s16* extraArgs);

#endif /* MAIN_DLL_DLL_001D_EFFECT4_H_ */
