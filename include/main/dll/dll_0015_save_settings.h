#ifndef MAIN_DLL_DLL_0015_SAVE_SETTINGS_H_
#define MAIN_DLL_DLL_0015_SAVE_SETTINGS_H_

#include "global.h"

void saveFileStruct_unlockCheat(u8 idx);
int saveFileStruct_isCheatActive(u8 idx);
int isCheatUnlocked(u8 idx);
void saveFileStruct_resetVolumes(void);
void* getSaveFileStruct(void);
void loadSaveSettings(void);

#endif /* MAIN_DLL_DLL_0015_SAVE_SETTINGS_H_ */
