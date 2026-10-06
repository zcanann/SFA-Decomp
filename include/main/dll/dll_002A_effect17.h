#ifndef MAIN_DLL_DLL_002A_EFFECT17_H_
#define MAIN_DLL_DLL_002A_EFFECT17_H_

#include "game/objects/object_fwd.h"

#include "main/dll/partfx_interface.h"

int Effect17_spawnEffect(GameObject* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                         s8 sourceParam, s16* extraArgs);
void Effect17_updateFrameState(void);
void Effect17_func03_nop(void);
void Effect17_release(void);
void Effect17_initialise(void);

#endif /* MAIN_DLL_DLL_002A_EFFECT17_H_ */
