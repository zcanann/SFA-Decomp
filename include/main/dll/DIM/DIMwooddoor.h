#ifndef MAIN_DLL_DIM_DIMWOODDOOR_H_
#define MAIN_DLL_DIM_DIMWOODDOOR_H_

#include "ghidra_import.h"
#include "main/game_object.h"

void DIMwooddoor_spawnShard(int obj, u8 variant);
void DIMwooddoor_updateShardAim(GameObject* obj, f32 targetX, f32 targetY, f32 targetZ);

#endif /* MAIN_DLL_DIM_DIMWOODDOOR_H_ */
