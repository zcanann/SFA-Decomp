#ifndef MAIN_DLL_DLL_0017_SAVEGAME_API_H_
#define MAIN_DLL_DLL_0017_SAVEGAME_API_H_

#include "main/dll/savedata_struct.h"
#include "main/mapEventTypes.h"
#include "main/dll/savegame_state.h"

/* SaveData describes this persisted byte buffer: the settings block followed by
 * the five high-score tables. */
extern u8 saveData[SAVE_DATA_SIZE];

void mapClearBit(int idx, int bit);
void* getHighScoreEntry(u8 fileIdx, u8 rank);
int saveGame_restoreObjectPosToRomList(void* object);

void SaveGame_initialise(void);
void SaveGame_release(void);
void SaveGame_func08_nop(void);
void SaveGame_gplaySavePoint(f32* pos, s16 angle, int flags, int mapLayer);
void SaveGame_gplayGotoSavegame(void);
void SaveGame_gplayRestartPoint(f32* pos, s16 angle, int b691, int flag);
void SaveGame_gplayGotoRestartPoint(void);
void SaveGame_gplayClearRestartPoint(void);
s32 SaveGame_gplayGetRestartGameNotCleared(void);
void* SaveGame_getState(void);
u8 SaveGame_getCurChar(void);
void SaveGame_setCharacter(u8 c);
void* SaveGame_getPlayerStats(void);
void* SaveGame_getCurCharPos(void);
TrickyStats* SaveGame_getTrickyStats(void);
void SaveGame_gplayAddTime(int id, f32 time);
int SaveGame_gplayDidTimeExpire(int id);
f32 SaveGame_gplayGetTimeRemaining(int id);
void SaveGame_updateTimes(void);
void SaveGame_setMapActLut(int val, int idx);
void SaveGame_gplaySetAct(int idx, int act);
u8 SaveGame_getMapAct(int idx);
int SaveGame_gplayGetObjGroupStatus(int idx, int shift);
u16 SaveGame_getMapObjGroupBit(int idx);
void SaveGame_mapUpdateObjGroups(int idx);
u32 SaveGame_mapGetObjGroups(int idx);
void SaveGame_resetObjGroups(int idx);

#endif /* MAIN_DLL_DLL_0017_SAVEGAME_API_H_ */
