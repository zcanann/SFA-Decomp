#ifndef MAIN_GAMEPLAY_RUNTIME_H_
#define MAIN_GAMEPLAY_RUNTIME_H_

#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "global.h"

void objRenderFn_80041018(int obj);
void loadUiDll(int index);
void defragMemory(int mode);
int loadMapAndParent(int mapId);
int lockLevel(int mapDir, int locked);
int mapUnload(int mapDir, int flags);
int mapGetDirIdx(int mapId);
void warpToMap(int mapId, int transition);
void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
void unlockLevel(int mapId, int flags, int unlocked);
void envFxActFn_800887f8(u8 value);
void getEnvfxActImmediately(void *obj, void *target, int effectId, int flags);
void setMotionBlur(int mode, f32 amount);
void streamFn_8000a380(int mask, int mode, int time);
void storeZeroToFloatParam(void *timer);
void s16toFloat(void *timer, int duration);
int timerCountDown(void *timer);
int randomGetRange(int min, int max);
void mm_free(void *ptr);
void *Obj_GetPlayerObject(void);
void *getTrickyObject(void);

#endif /* MAIN_GAMEPLAY_RUNTIME_H_ */
