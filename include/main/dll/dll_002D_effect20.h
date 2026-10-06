#ifndef MAIN_DLL_DLL_002D_EFFECT20_H_
#define MAIN_DLL_DLL_002D_EFFECT20_H_

#include "game/objects/object_fwd.h"

#include "main/dll/partfx_interface.h"
#include "global.h"

int Effect20_spawnEffect(GameObject* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, s8 sourceParam,
                         f32* extraArgs);
void Effect20_updateFrameState(void);
void Effect20_func03_nop(void);
void Effect20_release(void);
void Effect20_initialise(void);

#endif /* MAIN_DLL_DLL_002D_EFFECT20_H_ */
