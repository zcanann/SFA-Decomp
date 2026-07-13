#ifndef MAIN_DLL_SAVEGAME_H_
#define MAIN_DLL_SAVEGAME_H_

#include "ghidra_import.h"
#include "main/dll/savegame_load_api.h"
#include "main/dll/savegame_object_api.h"

void dll_91_func03(int param_1,int param_2,int param_3,u32 param_4);
void SaveGame_setCamActionNo(s16 actionNo);
s32 SaveGame_getCamActionNo(void);

void saveGame_save();
void* saveGameGetEnvState(void);

#endif /* MAIN_DLL_SAVEGAME_H_ */
