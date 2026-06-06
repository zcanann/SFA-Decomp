#ifndef MAIN_GAMEPLAY_RUNTIME_H_
#define MAIN_GAMEPLAY_RUNTIME_H_

#include "global.h"

u32 GameBit_Get(int eventId);
void GameBit_Set(int eventId, int value);
void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
int Sfx_PlayFromObjectLimited(void *obj, int sfxId, int maxCount);
void loadUiDll(int index);
void defragMemory(int mode);
int loadMapAndParent(int mapId);
int lockLevel(int mapDir, int locked);
int mapUnload(int mapDir, int flags);
int mapGetDirIdx(int mapId);
void warpToMap(int mapId, int transition);
void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
void unlockLevel(int mapId, int flags, int unlocked);
void envFxActFn_800887f8(u8 value);
void streamFn_8000a380(int mask, int mode, int time);
int randomGetRange(int min, int max);
void mm_free(u32 handle);
void *Obj_GetPlayerObject(void);

#endif /* MAIN_GAMEPLAY_RUNTIME_H_ */
