#ifndef MAIN_DLL_DLL_0029_EFFECT16_H_
#define MAIN_DLL_DLL_0029_EFFECT16_H_

#include "game/objects/object_fwd.h"

#include "main/dll/partfx_interface.h"

int Effect16_spawnEffect(GameObject* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                         s8 sourceParam, s16* extraArgs);
void Effect16_updateFrameState(void);
void Effect16_func03_nop(void);
void Effect16_release(void);
void Effect16_initialise(void);

#endif /* MAIN_DLL_DLL_0029_EFFECT16_H_ */
