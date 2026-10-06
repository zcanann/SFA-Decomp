#ifndef MAIN_DLL_DLL_0020_EFFECT7_H_
#define MAIN_DLL_DLL_0020_EFFECT7_H_

#include "game/objects/object_fwd.h"

#include "main/dll/partfx_interface.h"

void Effect7_func03_nop(void);
void Effect7_release(void);
void Effect7_initialise(void);
void Effect7_updateFrameState(void);
int Effect7_spawnEffect(GameObject* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                        s8 sourceParam, s16* extraArgs);

#endif /* MAIN_DLL_DLL_0020_EFFECT7_H_ */
