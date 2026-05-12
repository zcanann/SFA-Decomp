#ifndef MAIN_DLL_DIM_DIMBOSS_H_
#define MAIN_DLL_DIM_DIMBOSS_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

#define DIMBOSS_RUNTIME_SIZE 0x4C8
#define DIMBOSS_OBJECT_TYPE_ID 0x49

#define DIMBOSS_EVENT_FREE_DIMBOSS_ASSETS 0x15
#define DIMBOSS_EVENT_LOAD_DIMTOP_ASSETS 0x16

#define DIMBOSS_MAP_DIR 0x1C
#define DIMBOSS_GUT_MAP_DIR 0x1B
#define DIMTOP_MAP_DIR 0x13

#define DIMBOSS_MAP_UNLOAD_MASK 0x3FF
#define DIMBOSS_GUT_MAP_UNLOAD_MASK 0x20000000
#define DIMTOP_BOOT_DATA_FILE 0x20
#define DIMTOP_INTRO_DATA_FILE 0x21
#define DIMTOP_PLATFORM_DATA_FILE 0x23
#define DIMTOP_LIFT_DATA_FILE 0x24
#define DIMTOP_SCENE_DATA_FILE 0x30
#define DIMTOP_STEAM_DATA_FILE 0x2F
#define DIMTOP_BOSS_DATA_FILE_A 0x2B
#define DIMTOP_BOSS_DATA_FILE_B 0x2A
#define DIMTOP_EFFECT_DATA_FILE_A 0x26
#define DIMTOP_EFFECT_DATA_FILE_B 0x25
#define DIMTOP_ROOM_DATA_FILE_A 0x1A
#define DIMTOP_ROOM_DATA_FILE_B 0x1B
#define DIMTOP_AUDIO_DATA_FILE_A 0x0E
#define DIMTOP_AUDIO_DATA_FILE_B 0x0D

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
  f32 idleLift;
  f32 introSinkHeight;
  s32 defeatTimer;
  u8 stompDustDelay;
  u8 pad0B5;
  u8 steamSfxPending;
} DIMbossTopState;

typedef struct DIMbossRuntime {
  u8 pad000[0x270];
  s16 field270;
  u8 pad272[0x274 - 0x272];
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
  u8 pad50[0xA2 - 0x50];
  s16 activeModelId;
  u8 padA4[0xA8 - 0xA4];
  f32 modelScale;
  u8 padAC[0xAF - 0xAC];
  u8 objectFlags;
  u8 padB0[0xB8 - 0xB0];
  DIMbossRuntime *runtime;
  void (*updateState)(struct DIMbossObject *obj,undefined4 param_2,ObjAnimUpdateState *animUpdate);
  u8 padC0[0xC8 - 0xC0];
  void *childObject;
  u8 padCC[0xE4 - 0xCC];
  u8 updateMode;
  u8 padE5[0xF4 - 0xE5];
  int renderPause;
  int updateInitialized;
} DIMbossObject;

void DIMboss_updateState(DIMbossObject *obj,undefined4 param_2,ObjAnimUpdateState *animUpdate);
void dimboss_func11(void);
int DIMboss_setScale(DIMbossObject *obj);
int DIMboss_getExtraSize(void);
int dimboss_func08(void);
void DIMboss_free(DIMbossObject *obj);
void DIMboss_render(DIMbossObject *obj,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                    undefined4 param_5,char shouldRender);
void DIMboss_hitDetect(DIMbossObject *obj);
void dimboss_update2(DIMbossObject *obj);
void DIMboss_update(DIMbossObject *obj,undefined4 param_2,int param_3);
void dimboss_release(void);
void dimboss_initialise(void);

#endif /* MAIN_DLL_DIM_DIMBOSS_H_ */
