#ifndef MAIN_DLL_DR_DRCLOUDCAGE_H_
#define MAIN_DLL_DR_DRCLOUDCAGE_H_

#include "main/game_object.h"
#include "ghidra_import.h"

void fn_801E9C00(GameObject* obj, int state);
void drcloudcage_updateEngineFx(GameObject* obj, void* state, f32 distanceScale, int intensity, u8* unused,
                                u8 channelFlags);
f32 fn_801EA678(GameObject* obj, int state);

#endif /* MAIN_DLL_DR_DRCLOUDCAGE_H_ */
