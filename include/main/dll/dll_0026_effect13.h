#ifndef MAIN_DLL_DLL_0026_EFFECT13_H_
#define MAIN_DLL_DLL_0026_EFFECT13_H_

#include "game/objects/object_fwd.h"

#include "main/dll/partfx_interface.h"
#include "types.h"

int Effect13_spawnEffect(GameObject* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                         s8 sourceParam);
void Effect13_func05_nop(void);
void Effect13_func03_nop(void);
void Effect13_release(void);
void Effect13_initialise(void);

#endif /* MAIN_DLL_DLL_0026_EFFECT13_H_ */
