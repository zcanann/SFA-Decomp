#ifndef MAIN_DLL_CF_CFPRISONGUARD_H_
#define MAIN_DLL_CF_CFPRISONGUARD_H_

#include "global.h"
#include "main/dll/CF/dll_163.h"

void staffactivated_updateLiftHeight(int obj, StaffActivatedState *state);
void FUN_80189cc4(int obj, StaffActivatedState *state);
void FUN_80189e0c(uint obj, StaffActivatedState *state);
void staffactivated_spawnMapEventDebris(int obj);
void FUN_8018a060(int obj, char enabled);
byte FUN_8018a0d0(int obj);

#endif /* MAIN_DLL_CF_CFPRISONGUARD_H_ */
