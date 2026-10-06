#ifndef MAIN_DLL_DLL_0021_EFFECT8_H_
#define MAIN_DLL_DLL_0021_EFFECT8_H_

#include "game/objects/object_fwd.h"

#include "main/dll/partfx_interface.h"
#include "types.h"

void Effect8_func03_nop(void);
void Effect8_release(void);
void Effect8_initialise(void);
void Effect8_updateFrameState(void);
int Effect8_spawnEffect(GameObject* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, s8 sourceParam,
                        s16* extraArgs);

#endif /* MAIN_DLL_DLL_0021_EFFECT8_H_ */
