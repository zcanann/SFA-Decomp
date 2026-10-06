#ifndef MAIN_DLL_DLL_0028_EFFECT15_H_
#define MAIN_DLL_DLL_0028_EFFECT15_H_

#include "game/objects/object_fwd.h"

#include "main/dll/partfx_interface.h"

int Effect15_spawnEffect(GameObject* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, s8 sourceParam,
                         f32* extraArgs);
void Effect15_func05_nop(void);
void Effect15_func03_nop(void);
void Effect15_release(void);
void Effect15_initialise(void);

#endif /* MAIN_DLL_DLL_0028_EFFECT15_H_ */
