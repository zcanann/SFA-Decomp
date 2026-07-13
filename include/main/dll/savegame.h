#ifndef MAIN_DLL_SAVEGAME_H_
#define MAIN_DLL_SAVEGAME_H_

#include "ghidra_import.h"
#include "main/dll/savegame_load_api.h"
#include "main/dll/savegame_object_api.h"

void SaveGame_setCamActionNo(s16 actionNo);
s32 SaveGame_getCamActionNo(void);
f32 SaveGame_getPlayTime(void);
void clearSaveGameLoadingFlag(void);
char* getSaveFileName(void);
int saveFn_800e8508(void);
void gplaySaveGame(int param);
void titleDoLoadSave(void);
void saveGame_save(void);
int trySaveGame(int slot);
int insertHighScore(u8 slot, u8 flag, u32 score, u8* initials);
int gplayNewGame(char* name, int slot);
void SaveGame_gplaySetObjGroupStatus(int idx, int shift, int value);
s8 SaveGame_findTransientMapBit(int mapId, int bit);
void SaveGame_updateTransientMapBits(void);
int saveSelect_getInfo(void* out);
s32 isSaveGameLoading(void);
void setSaveGameLoadingFlag(void);
void updateSavedHealth(void);

void* saveGameGetEnvState(void);

#endif /* MAIN_DLL_SAVEGAME_H_ */
