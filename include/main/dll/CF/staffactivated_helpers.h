#ifndef MAIN_DLL_CF_STAFFACTIVATED_HELPERS_H_
#define MAIN_DLL_CF_STAFFACTIVATED_HELPERS_H_

#include "main/game_object.h"
#include "global.h"
#include "main/dll/CF/dll_163.h"

void staffactivated_updateLiftHeight(GameObject* obj, StaffActivatedState* state);
u32 cfPrisonGuard_getPullRateMode(GameObject* obj);
void cfPrisonGuard_setGameBitMirror(GameObject* obj, u8 flag);
int cfPrisonGuard_isGameBitMirrorSet(GameObject* obj);
void FUN_80189cc4(int obj, StaffActivatedState* state);
void FUN_80189e0c(u32 obj, StaffActivatedState* state);
void staffactivated_spawnMapEventDebris(GameObject* obj);
void FUN_8018a060(int obj, char enabled);
u8 FUN_8018a0d0(int obj);

#endif /* MAIN_DLL_CF_STAFFACTIVATED_HELPERS_H_ */
