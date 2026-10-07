#ifndef MAIN_DLL_DLL_0024_EFFECT11_H_
#define MAIN_DLL_DLL_0024_EFFECT11_H_

#include "game/objects/object_fwd.h"

#include "types.h"
#include "main/dll/partfx_interface.h"

int Effect11_spawnEffect(GameObject* obj, int id, PartFxSpawnParams* src, u32 flags, s8 sourceParam);
void Effect11_func05_nop(void);
void Effect11_func03_nop(void);
void Effect11_release(void);
void Effect11_initialise(void);

#endif /* MAIN_DLL_DLL_0024_EFFECT11_H_ */
