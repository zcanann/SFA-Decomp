#ifndef MAIN_DLL_DLL_002C_EFFECT19_H_
#define MAIN_DLL_DLL_002C_EFFECT19_H_

#include "game/objects/object_fwd.h"

#include "main/dll/partfx_interface.h"

int Effect19_spawnEffect(GameObject* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                         s8 sourceParam, f32* extraArgs);
void Effect19_updateFrameState(void);
void Effect19_func03_nop(void);
void Effect19_release(void);
void Effect19_initialise(void);

#endif /* MAIN_DLL_DLL_002C_EFFECT19_H_ */
