#ifndef MAIN_DLL_DLL_0022_EFFECT9_H_
#define MAIN_DLL_DLL_0022_EFFECT9_H_

#include "game/objects/object_fwd.h"

#include "main/dll/partfx_interface.h"
#include "types.h"

void Effect9_func03_nop(void);
void Effect9_release(void);
void Effect9_initialise(void);
int Effect9_spawnEffect(GameObject* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                        s8 sourceParam, s16* extraArgs);
void Effect9_updateFrameState(void);

#endif /* MAIN_DLL_DLL_0022_EFFECT9_H_ */
