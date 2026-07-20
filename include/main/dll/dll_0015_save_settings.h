#ifndef MAIN_DLL_DLL_0015_SAVE_SETTINGS_H_
#define MAIN_DLL_DLL_0015_SAVE_SETTINGS_H_

#include "global.h"
#include "main/dll/savedata_struct.h"

void saveFileStruct_unlockCheat(u8 idx);
int saveFileStruct_isCheatActive(u8 idx);
int isCheatUnlocked(u8 idx);
void saveFileStruct_resetVolumes(void);
SaveData* getSaveFileStruct(void);
void loadSaveSettings(void);

#endif /* MAIN_DLL_DLL_0015_SAVE_SETTINGS_H_ */
