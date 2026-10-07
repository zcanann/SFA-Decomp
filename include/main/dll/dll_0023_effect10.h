#ifndef MAIN_DLL_DLL_0023_EFFECT10_H_
#define MAIN_DLL_DLL_0023_EFFECT10_H_

#include "game/objects/object_fwd.h"

#include "types.h"
#include "main/dll/partfx_interface.h"

int Effect10_spawnEffect(GameObject* obj, int id, PartFxSpawnParams* src, u32 flags, s8 sourceParam, f32* p6);
void Effect10_updateFrameState(void);
void Effect10_func03_nop(void);
void Effect10_release(void);
void Effect10_initialise(void);

#endif /* MAIN_DLL_DLL_0023_EFFECT10_H_ */
