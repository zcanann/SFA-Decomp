#ifndef MAIN_GAMEPLAY_RUNTIME_H_
#define MAIN_GAMEPLAY_RUNTIME_H_

#include "global.h"

u32 GameBit_Get(int eventId);
void GameBit_Set(int eventId, int value);
void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
void loadUiDll(int index);
void defragMemory(int mode);
int loadMapAndParent(int mapId);
int lockLevel(int mapDir, int locked);
int mapUnload(int mapDir, int flags);
int mapGetDirIdx(int mapId);
void warpToMap(int mapId, int transition);
void objRenderFn_8003b8f4(double scale);
void unlockLevel(int mapId, int flags, int unlocked);
void envFxActFn_800887f8(u8 value);
void streamFn_8000a380(int mask, int mode, int time);

#endif /* MAIN_GAMEPLAY_RUNTIME_H_ */
