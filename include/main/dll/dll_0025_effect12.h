#ifndef MAIN_DLL_DLL_0025_EFFECT12_H_
#define MAIN_DLL_DLL_0025_EFFECT12_H_

#include "game/objects/object_fwd.h"

#include "types.h"
#include "game/objects/object.h"
#include "main/dll/partfx_interface.h"

int Effect12_spawnEffect(GameObject* obj, int id, PartFxSpawnParams* src, u32 flags, s8 sourceParam, f32* auxParam);
void Effect12_func05_nop(void);
void Effect12_func03_nop(void);
void Effect12_release(void);
void Effect12_initialise(void);

#endif /* MAIN_DLL_DLL_0025_EFFECT12_H_ */
