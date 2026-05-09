#ifndef MAIN_DLL_DIM_DIMBOSS_H_
#define MAIN_DLL_DIM_DIMBOSS_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

typedef struct DIMbossEffect {
  u8 pad00[0x4C];
  u8 visible;
  u8 pad4D[0x2F8 - 0x4D];
  u8 active;
} DIMbossEffect;

typedef struct DIMbossTopState {
  DIMbossEffect *effect;
  u8 pad004[0xA4 - 0x04];
  f32 launchLift;
  u8 pad0A8[0xAC - 0xA8];
  f32 introSinkHeight;
  s32 defeatTimer;
  u8 stompDustDelay;
  u8 pad0B5;
  u8 steamSfxPending;
} DIMbossTopState;

typedef struct DIMbossRuntime {
  u8 pad000[0x274];
  s16 scale;
  u8 pad276[0x2D0 - 0x276];
  undefined4 targetModel;
  u8 pad2D4[0x354 - 0x2D4];
  u8 animMode;
  u8 pad355[0x35C - 0x355];
  u8 moveScratch[0x3F4 - 0x35C];
  s16 activeMoveId;
  s16 eventGameBit;
  u8 pad3F8[0x400 - 0x3F8];
  u16 stateFlags;
  s16 phase;
  u8 pad404;
  u8 hitReactMode;
  u8 pad406[0x40C - 0x406];
  DIMbossTopState *topState;
} DIMbossRuntime;

typedef struct DIMbossConfig {
  u8 pad00[0x08];
  f32 spawnX;
  f32 spawnY;
  f32 spawnZ;
  u8 pad14[0x2E - 0x14];
  s8 animObjId;
} DIMbossConfig;

typedef struct DIMbossObject {
  u8 pad00[0x08];
  f32 baseScale;
  f32 posX;
  f32 posY;
  f32 posZ;
  u8 pad18[0x30 - 0x18];
  undefined4 facingAngle;
  u8 pad34[0x4C - 0x34];
  DIMbossConfig *config;
  u8 pad50[0xA8 - 0x50];
  f32 modelScale;
  u8 padAC[0xAF - 0xAC];
  u8 objectFlags;
  u8 padB0[0xB8 - 0xB0];
  DIMbossRuntime *runtime;
  u8 padBC[0xC8 - 0xBC];
  void *childObject;
  u8 padCC[0xF4 - 0xCC];
  int renderPause;
  int updateInitialized;
} DIMbossObject;

void DIMboss_updateState(DIMbossObject *param_1,undefined4 param_2,ObjAnimUpdateState *animUpdate);
void dimboss_func11(void);
int DIMboss_setScale(DIMbossObject *obj);
int DIMboss_getExtraSize(void);
int dimboss_func08(void);
void DIMboss_free(DIMbossObject *obj);
void DIMboss_render(DIMbossObject *obj,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                    undefined4 param_5,char shouldRender);
void DIMboss_hitDetect(DIMbossObject *obj);
void dimboss_update2(DIMbossObject *obj);
void DIMboss_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                    undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                    ushort *param_9);
void dimboss_release(void);
void dimboss_initialise(void);

#endif /* MAIN_DLL_DIM_DIMBOSS_H_ */
