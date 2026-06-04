#ifndef MAIN_DLL_DIM_DIMBOSS_H_
#define MAIN_DLL_DIM_DIMBOSS_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

#define DIMBOSS_RUNTIME_SIZE 0x4C8
#define DIMBOSS_OBJECT_TYPE_ID 0x49

#define DIMBOSS_EVENT_CLEAR_RENDER_ATTACHMENT 0x01
#define DIMBOSS_EVENT_LAUNCH_LIFT 0x02
#define DIMBOSS_EVENT_SET_SEQUENCE_FLAGS_40004 0x06
#define DIMBOSS_EVENT_SET_SEQUENCE_FLAG_0002 0x07
#define DIMBOSS_EVENT_QUEUE_STEAM_SFX 0x08
#define DIMBOSS_EVENT_SET_SEQUENCE_FLAG_0040 0x09
#define DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_0040 0x0A
#define DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_0080 0x0C
#define DIMBOSS_EVENT_SET_SEQUENCE_FLAG_0100 0x0D
#define DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_0100 0x0E
#define DIMBOSS_EVENT_SET_SEQUENCE_FLAGS_2001 0x0F
#define DIMBOSS_EVENT_SET_SEQUENCE_FLAGS_8021 0x10
#define DIMBOSS_EVENT_FREE_DIMBOSS_ASSETS 0x15
#define DIMBOSS_EVENT_LOAD_DIMTOP_ASSETS 0x16
#define DIMBOSS_EVENT_TRIGGER_DEFEAT_FLAGS 0x11
#define DIMBOSS_EVENT_SPAWN_DIMBOSS_OBJECT 0x12
#define DIMBOSS_EVENT_ENABLE_DIMBOSS_MAP_AREA 0x13
#define DIMBOSS_EVENT_DISABLE_DIMBOSS_MAP_AREA 0x14
#define DIMBOSS_EVENT_SET_SEQUENCE_FLAG_80000 0x17
#define DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_80000 0x18

#define DIMBOSS_PHASE_START 0
#define DIMBOSS_PHASE_LAUNCH_LIFT 1
#define DIMBOSS_PHASE_GAMEBIT_COUNT_MET 2
#define DIMBOSS_PHASE_NO_RENDER 3
#define DIMBOSS_PHASE_RENDER_PAUSE 4

#define DIMBOSS_STATE_FLAG_START_MOVE 0x02
#define DIMBOSS_STATE_FLAG_TARGET_TRICKY 0x04
#define DIMBOSS_DEFEAT_TIMER_START 10

#define DIMBOSS_GAMEBIT_DEFEAT_STATE_A 0x123
#define DIMBOSS_GAMEBIT_DEFEAT_STATE_B 0x17
#define DIMBOSS_GAMEBIT_INTRO_SEEN 0x1DF
#define DIMBOSS_GAMEBIT_TONSIL_HIT_COUNT 0x20C
#define DIMBOSS_GAMEBIT_SPIT_ACTIVE 0x20E
#define DIMBOSS_GAMEBIT_RENDER_PAUSE 0x210
#define DIMBOSS_GAMEBIT_LIGHTFOOT_SNOWBALL_GATE 0x9E
#define DIMBOSS_GAMEBIT_TRICKY_BOSS_MODE 0x4E4
#define DIMBOSS_GAMEBIT_SHRINE_MUSIC_LOCK 0xCBB
#define DIMBOSS_GAMEBIT_BOSS_ACTIVE 0xEFD
#define DIMBOSS_GAMEBIT_DIM2_PROJECTILE_DONE 0xDA5

#define DIMBOSS_MUSIC_LIFT_RUMBLE 0x27
#define DIMBOSS_MUSIC_BOSS_THEME 0x36
#define DIMBOSS_MUSIC_STEAM_LOOP 0xEE
#define DIMBOSS_MUSIC_DIM2_PROJECTILE 0xD7
#define DIMBOSS_MUSIC_DIM2_PROJECTILE_ALT 0xE0

#define DIMBOSS_SEQUENCE_FLAG_0001 0x00000001
#define DIMBOSS_SEQUENCE_FLAG_0002 0x00000002
#define DIMBOSS_SEQUENCE_FLAG_0004 0x00000004
#define DIMBOSS_SEQUENCE_FLAG_0020 0x00000020
#define DIMBOSS_SEQUENCE_FLAG_0040 0x00000040
#define DIMBOSS_SEQUENCE_FLAG_0080 0x00000080
#define DIMBOSS_SEQUENCE_FLAG_0100 0x00000100
#define DIMBOSS_SEQUENCE_FLAG_2000 0x00002000
#define DIMBOSS_SEQUENCE_FLAG_8000 0x00008000
#define DIMBOSS_SEQUENCE_FLAG_40000 0x00040000
#define DIMBOSS_SEQUENCE_FLAG_80000 0x00080000
#define DIMBOSS_SEQUENCE_FLAGS_40004 \
  (DIMBOSS_SEQUENCE_FLAG_40000 | DIMBOSS_SEQUENCE_FLAG_0004)
#define DIMBOSS_SEQUENCE_FLAGS_2001 \
  (DIMBOSS_SEQUENCE_FLAG_2000 | DIMBOSS_SEQUENCE_FLAG_0001)
#define DIMBOSS_SEQUENCE_FLAGS_8021 \
  (DIMBOSS_SEQUENCE_FLAG_8000 | DIMBOSS_SEQUENCE_FLAG_0020 | DIMBOSS_SEQUENCE_FLAG_0001)

#define DIMBOSS_MAP_DIR 0x1C
#define DIMBOSS_GUT_MAP_DIR 0x1B
#define DIMTOP_MAP_DIR 0x13

#define DIMBOSS_MAP_UNLOAD_MASK 0x3FF
#define DIMBOSS_GUT_MAP_UNLOAD_MASK 0x20000000
#define DIMTOP_LOAD_PENDING_FLAGS_MASK 0xFFEFFFFF
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
#define DIMBOSS_HIT_EFFECT_ID 0x5A
#define DIMBOSS_HIT_EFFECT_RESOURCE_COUNT 1

#define DIMBOSS_ANIM_CONTROLLER_OFFSET 0x6C
#define DIMBOSS_ANIM_CONTROLLER_SIZE 0x624
#define DIMBOSS_ANIM_CONTROLLER_FLAGS_OFFSET 0x611
#define DIMBOSS_ANIM_TABLE_OFFSET 0x690
#define DIMBOSS_ANIM_TABLE_COUNT 6
#define DIMBOSS_HITDETECT_ANIM_TABLE_OFFSET 0x6A8
#define DIMBOSS_HITDETECT_ANIM_TABLE_COUNT 12

typedef struct DIMbossEffect {
  u8 pad00[0x4C];
  u8 visible;
  u8 pad4D[0x2F8 - 0x4D];
  u8 active;
} DIMbossEffect;

typedef union DIMbossSteamFlags {
  u8 raw;
  struct {
    u8 sfxPending : 1;
    u8 rest : 7;
  } bits;
} DIMbossSteamFlags;

typedef struct DIMbossTopState {
  DIMbossEffect *effect;
  u8 pad004[0xA4 - 0x04];
  f32 launchLift;
  f32 idleLift;
  f32 introSinkHeight;
  s32 defeatTimer;
  u8 stompDustDelay;
  u8 pad0B5;
  DIMbossSteamFlags steamFlags;
} DIMbossTopState;

typedef struct DIMbossAnimScratch {
  u8 pad000[DIMBOSS_ANIM_CONTROLLER_OFFSET];
  u8 animController[DIMBOSS_ANIM_CONTROLLER_SIZE];
  void (*animTable[DIMBOSS_ANIM_TABLE_COUNT])(void);
  void (*hitDetectAnimTable[DIMBOSS_HITDETECT_ANIM_TABLE_COUNT])(void);
} DIMbossAnimScratch;

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
  u8 pad410[DIMBOSS_RUNTIME_SIZE - 0x410];
} DIMbossRuntime;

typedef struct DIMbossConfig {
  u8 pad00[0x08];
  f32 spawnX;
  f32 spawnY;
  f32 spawnZ;
  u8 pad14[0x2C - 0x14];
  s16 eventId;
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
  u8 padB0[0xB4 - 0xB0];
  s16 animStateId;
  u8 padB6[0xB8 - 0xB6];
  DIMbossRuntime *runtime;
  int (*updateState)(struct DIMbossObject *obj,undefined4 param_2,
                     ObjAnimUpdateState *animUpdate);
  u8 padC0[0xC8 - 0xC0];
  void *childObject;
  u8 padCC[0xE4 - 0xCC];
  u8 updateMode;
  u8 padE5[0xF4 - 0xE5];
  int renderPause;
  int updateInitialized;
} DIMbossObject;

STATIC_ASSERT(sizeof(DIMbossEffect) == 0x2F9);
STATIC_ASSERT(offsetof(DIMbossEffect, visible) == 0x4C);
STATIC_ASSERT(offsetof(DIMbossEffect, active) == 0x2F8);

STATIC_ASSERT(sizeof(DIMbossTopState) == 0xB8);
STATIC_ASSERT(offsetof(DIMbossTopState, effect) == 0x00);
STATIC_ASSERT(offsetof(DIMbossTopState, launchLift) == 0xA4);
STATIC_ASSERT(offsetof(DIMbossTopState, idleLift) == 0xA8);
STATIC_ASSERT(offsetof(DIMbossTopState, introSinkHeight) == 0xAC);
STATIC_ASSERT(offsetof(DIMbossTopState, defeatTimer) == 0xB0);
STATIC_ASSERT(offsetof(DIMbossTopState, stompDustDelay) == 0xB4);
STATIC_ASSERT(offsetof(DIMbossTopState, steamFlags) == 0xB6);

STATIC_ASSERT(sizeof(DIMbossAnimScratch) == 0x6D8);
STATIC_ASSERT(offsetof(DIMbossAnimScratch, animController) == DIMBOSS_ANIM_CONTROLLER_OFFSET);
STATIC_ASSERT(offsetof(DIMbossAnimScratch, animTable) == DIMBOSS_ANIM_TABLE_OFFSET);
STATIC_ASSERT(offsetof(DIMbossAnimScratch, hitDetectAnimTable) ==
              DIMBOSS_HITDETECT_ANIM_TABLE_OFFSET);

STATIC_ASSERT(sizeof(DIMbossRuntime) == DIMBOSS_RUNTIME_SIZE);
STATIC_ASSERT(offsetof(DIMbossRuntime, field270) == 0x270);
STATIC_ASSERT(offsetof(DIMbossRuntime, scale) == 0x274);
STATIC_ASSERT(offsetof(DIMbossRuntime, targetModel) == 0x2D0);
STATIC_ASSERT(offsetof(DIMbossRuntime, animMode) == 0x354);
STATIC_ASSERT(offsetof(DIMbossRuntime, moveScratch) == 0x35C);
STATIC_ASSERT(offsetof(DIMbossRuntime, activeMoveId) == 0x3F4);
STATIC_ASSERT(offsetof(DIMbossRuntime, eventGameBit) == 0x3F6);
STATIC_ASSERT(offsetof(DIMbossRuntime, stateFlags) == 0x400);
STATIC_ASSERT(offsetof(DIMbossRuntime, phase) == 0x402);
STATIC_ASSERT(offsetof(DIMbossRuntime, hitReactMode) == 0x405);
STATIC_ASSERT(offsetof(DIMbossRuntime, topState) == 0x40C);

STATIC_ASSERT(sizeof(DIMbossConfig) == 0x30);
STATIC_ASSERT(offsetof(DIMbossConfig, spawnX) == 0x08);
STATIC_ASSERT(offsetof(DIMbossConfig, spawnY) == 0x0C);
STATIC_ASSERT(offsetof(DIMbossConfig, spawnZ) == 0x10);
STATIC_ASSERT(offsetof(DIMbossConfig, eventId) == 0x2C);
STATIC_ASSERT(offsetof(DIMbossConfig, animObjId) == 0x2E);

STATIC_ASSERT(offsetof(DIMbossObject, baseScale) == 0x08);
STATIC_ASSERT(offsetof(DIMbossObject, posX) == 0x0C);
STATIC_ASSERT(offsetof(DIMbossObject, facingAngle) == 0x30);
STATIC_ASSERT(offsetof(DIMbossObject, config) == 0x4C);
STATIC_ASSERT(offsetof(DIMbossObject, activeModelId) == 0xA2);
STATIC_ASSERT(offsetof(DIMbossObject, modelScale) == 0xA8);
STATIC_ASSERT(offsetof(DIMbossObject, objectFlags) == 0xAF);
STATIC_ASSERT(offsetof(DIMbossObject, animStateId) == 0xB4);
STATIC_ASSERT(offsetof(DIMbossObject, runtime) == 0xB8);
STATIC_ASSERT(offsetof(DIMbossObject, updateState) == 0xBC);
STATIC_ASSERT(offsetof(DIMbossObject, childObject) == 0xC8);
STATIC_ASSERT(offsetof(DIMbossObject, updateMode) == 0xE4);
STATIC_ASSERT(offsetof(DIMbossObject, renderPause) == 0xF4);
STATIC_ASSERT(offsetof(DIMbossObject, updateInitialized) == 0xF8);

int DIMboss_updateState(DIMbossObject *obj,undefined4 param_2,ObjAnimUpdateState *animUpdate);
void DIMboss_func0B(void);
int DIMboss_setScale(DIMbossObject *obj);
int DIMboss_getExtraSize(void);
int DIMboss_getObjectTypeId(void);
void DIMboss_free(DIMbossObject *obj);
void DIMboss_render(DIMbossObject *obj,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                    undefined4 param_5,char shouldRender);
void DIMboss_hitDetect(DIMbossObject *obj);
void DIMboss_update(DIMbossObject *obj);
void DIMboss_init(DIMbossObject *obj,undefined4 param_2,int param_3);
void DIMboss_release(void);
void DIMboss_initialise(void);
void DIMboss_initialiseAnimTables(void);
extern ObjectDescriptor12 gDIM_BossObjDescriptor;

#endif /* MAIN_DLL_DIM_DIMBOSS_H_ */
