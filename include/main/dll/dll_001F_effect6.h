#ifndef MAIN_DLL_DLL_001F_EFFECT6_H_
#define MAIN_DLL_DLL_001F_EFFECT6_H_

#include "game/objects/object_fwd.h"

#include "main/dll/partfx_interface.h"

void Effect6_func03_nop(void);
void Effect6_release(void);
void Effect6_initialise(void);
int Effect6_spawnEffect(GameObject* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, s8 sourceParam,
                        u16* extraArgs);
void Effect6_updateFrameState(void);

#endif /* MAIN_DLL_DLL_001F_EFFECT6_H_ */
