#ifndef MAIN_DLL_DLL_0027_EFFECT14_H_
#define MAIN_DLL_DLL_0027_EFFECT14_H_

#include "game/objects/object_fwd.h"

#include "types.h"
#include "game/objects/object.h"
#include "main/dll/partfx_interface.h"

int Effect14_spawnEffect(GameObject* obj, int id, PartFxSpawnParams* src, u32 flags, s8 sourceParam, u16* extraArgs);
void Effect14_func05_nop(void);
void Effect14_func03_nop(void);
void Effect14_release(void);
void Effect14_initialise(void);

#endif /* MAIN_DLL_DLL_0027_EFFECT14_H_ */
