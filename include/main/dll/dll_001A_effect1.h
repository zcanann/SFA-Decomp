#ifndef MAIN_DLL_DLL_001A_EFFECT1_H_
#define MAIN_DLL_DLL_001A_EFFECT1_H_

#include "game/objects/object_fwd.h"

#include "main/dll/partfx_interface.h"
#include "types.h"

void Effect1_func03_nop(void);
void Effect1_release(void);
void Effect1_initialise(void);
void Effect1_updateFrameState(void);
int Effect1_spawnEffect(GameObject* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                        s8 sourceParam, s16* extraArgs);

#endif /* MAIN_DLL_DLL_001A_EFFECT1_H_ */
