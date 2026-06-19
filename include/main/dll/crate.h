#ifndef MAIN_DLL_CRATE_H_
#define MAIN_DLL_CRATE_H_

#include "ghidra_import.h"
#include "main/dll/sfxplayer.h"
#include "main/objanim_update.h"

u32 sfxplayer_updateState(int obj, u32 unused, ObjAnimUpdateState *animUpdate);
void FUN_802081e0(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,int param_10);

#endif /* MAIN_DLL_CRATE_H_ */
