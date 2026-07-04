#ifndef MAIN_DLL_GAMEPLAY_H_
#define MAIN_DLL_GAMEPLAY_H_

#include "ghidra_import.h"

void saveFileStruct_unlockCheat(u32 param_1);
u32 isCheatUnlocked(u32 param_1);
void saveFileStruct_resetVolumes(void);
u8 * getSaveFileStruct(void);
void saveGame_unsaveObjectPos(u8 *obj);
void loadSaveSettings(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                      u64 param_5,u64 param_6,u64 param_7,
                      u64 param_8);
u8 * FUN_800e82d8(void);
u32 FUN_800e82e0(int param_1);
u32 FUN_800e83c8(int param_1);
void FUN_800e842c(int param_1);
void FUN_800e8630(int param_1);
void FUN_800e8794(u16 param_1);
int FUN_800e87a0(void);
u32 * FUN_800e87a8(void);
int saveFn_800e8508(void);
void gplaySaveGame(int param);
void titleDoLoadSave(void);
void saveGame_save(void);
int trySaveGame(int slot);
int insertHighScore(u8 slot, u8 flag, u32 score, u8 *initials);
int gplayNewGame(char *name, int slot);
void SaveGame_gplaySetObjGroupStatus(int idx, int shift, int value);
s8 SaveGame_findTransientMapBit(int mapId, int bit);
void SaveGame_updateTransientMapBits(void);
int saveSelect_getInfo(void *out);
void FUN_800e8b48(void);
void FUN_800e8b54(void);
u32 FUN_800e8b6c(void);
u8 FUN_800e8b98(void);
int FUN_800e8ba4(u64 param_1,double param_2,u64 param_3,u64 param_4,
                u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                u8 param_9);
u8 * FUN_800e8d50(u32 param_1,u32 param_2);
int FUN_800e8d6c(u32 param_1,u8 param_2,u32 param_3,u8 *param_4);
u8 * FUN_800e8f50(void);
void FUN_800e8f58(u64 param_1,double param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_800e9298(u64 param_1,double param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_800e95e8(u32 param_1,u32 param_2,int param_3);
void FUN_800e99f8(void);
int FUN_800e9b14(int param_1,u32 param_2);
void FUN_800e9c00(u32 param_1,int param_2);
void FUN_800e9c3c(u32 param_1);
u32 FUN_800e9ca4(u32 param_1,u32 param_2);
u8 FUN_800e9d1c(u32 param_1);
void FUN_800e9da0(u32 param_1,u32 param_2);
void FUN_800e9e54(void);
double FUN_800e9e74(void);
void FUN_800e9e9c(void);
void FUN_800ea000(void);
void FUN_800ea034(void);
void FUN_800ea1cc(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u8 param_11,int param_12);
void FUN_800ea3e8(void);
void FUN_800ea590(u32 *param_1,u16 param_2,u32 param_3,u8 param_4);
void FUN_800ea698(void);
void FUN_800ea6c4(void);
void FUN_800ea7bc(int param_1);
u16 FUN_800ea83c(void);
void FUN_800ea858(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
u32
FUN_800ea8c8(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8);
u8 FUN_800ea9ac(void);
void FUN_800ea9b8(void);
void FUN_800eab50(void);
void FUN_800eac54(void);
void FUN_800eac94(void);
void FUN_800eacd8(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_800eaeb8(int param_1);
void FUN_800eaf2c(int param_1,int param_2);
void FUN_800eaf90(int param_1);
int FUN_800eafb4(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                u32 param_9);
void FUN_800eb410(int param_1,int param_2);
void FUN_800eb464(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800eb4d0(u32 param_1,u32 param_2,int param_3,u32 param_4,u32 param_5,
                 int *param_6);
void FUN_800eb6f8(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 *param_14,u32 param_15,u32 param_16);
void FUN_800ec43c(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ec4a8(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ec514(u32 param_1,u8 param_2,u32 param_3,u32 param_4);
void FUN_800eca00(int param_1,u16 param_2,int param_3,u32 param_4);
void FUN_800eca64(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ecb04(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ecb7c(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ecbf8(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ecd94(int param_1,int param_2,int param_3,u32 param_4);
void FUN_800ece08(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ece84(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ecef0(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ecf5c(int param_1,u16 param_2,int param_3,u32 param_4);
void FUN_800ecfc0(int param_1,u16 param_2,int param_3,u32 param_4);
void FUN_800ed024(short *param_1,int param_2,int param_3,u32 param_4,u32 param_5,
                 u32 *param_6);
void FUN_800ed228(int param_1,int param_2,int param_3,u32 param_4);
void FUN_800ed2f0(int param_1,u16 param_2,int param_3,u32 param_4);
void FUN_800ed354(int param_1,u16 param_2,int param_3,u32 param_4);
void FUN_800ed3b8(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ed424(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ed490(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ed4fc(int param_1,u16 param_2,int param_3,u32 param_4);
void FUN_800ed560(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ed5e4(int param_1,int param_2,int param_3,u32 param_4);
void FUN_800ed68c(int param_1,int param_2,int param_3,u32 param_4);
void FUN_800ed880(int param_1,u16 param_2,int param_3,u32 param_4);
void FUN_800ed8e4(int param_1,u16 param_2,int param_3,u32 param_4);
void FUN_800ed948(int param_1,u16 param_2,short *param_3,u32 param_4);
void FUN_800ed9ac(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ee000(u32 param_1,u32 param_2,int param_3,u32 param_4);
void FUN_800ee10c(u32 param_1,u32 param_2,int param_3,u32 param_4);

#endif /* MAIN_DLL_GAMEPLAY_H_ */
