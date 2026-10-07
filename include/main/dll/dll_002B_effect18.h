#ifndef MAIN_DLL_DLL_002B_EFFECT18_H_
#define MAIN_DLL_DLL_002B_EFFECT18_H_

#include "game/objects/object_fwd.h"

#include "main/dll/partfx_interface.h"

int Effect18_spawnEffect(GameObject* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                         s8 sourceParam, void* extraArgs);
void Effect18_updateFrameState(void);
void Effect18_func03_nop(void);
void Effect18_release(void);
void Effect18_initialise(void);

#endif /* MAIN_DLL_DLL_002B_EFFECT18_H_ */
