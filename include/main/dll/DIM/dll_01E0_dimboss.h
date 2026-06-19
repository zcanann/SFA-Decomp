#ifndef MAIN_DLL_DIM_DIMBOSS_H_
#define MAIN_DLL_DIM_DIMBOSS_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_internal.h"
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

#define DIMBOSS_OBJECT_FLAG_HIDDEN 0x08
#define DIMBOSS_OBJECT_FLAG_ACTIVE 0x80

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
#define DIMBOSS_SEQUENCE_FLAG_TONSIL_GUARD_ACTIVE 0x00000008
#define DIMBOSS_SEQUENCE_FLAG_BREATH_BURST 0x00000010
#define DIMBOSS_SEQUENCE_FLAG_0020 0x00000020
#define DIMBOSS_SEQUENCE_FLAG_0040 0x00000040
#define DIMBOSS_SEQUENCE_FLAG_0080 0x00000080
#define DIMBOSS_SEQUENCE_FLAG_0100 0x00000100
#define DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_7 0x00000200
#define DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_8 0x00000400
#define DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_9 0x00000800
#define DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_10 0x00001000
#define DIMBOSS_SEQUENCE_FLAG_2000 0x00002000
#define DIMBOSS_SEQUENCE_FLAG_ARENA_DUST_BURST 0x00004000
#define DIMBOSS_SEQUENCE_FLAG_8000 0x00008000
#define DIMBOSS_SEQUENCE_FLAG_CAPTURE_BLUE_WHITE_VELOCITY 0x00010000
#define DIMBOSS_SEQUENCE_FLAG_SPAWN_BLUE_WHITE_EFFECT 0x00020000
#define DIMBOSS_SEQUENCE_FLAG_40000 0x00040000
#define DIMBOSS_SEQUENCE_FLAG_80000 0x00080000
#define DIMBOSS_SEQUENCE_FLAGS_ICICLE_DUST_POINTS \
  (DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_7 | DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_8 | \
   DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_9 | DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_10)
#define DIMBOSS_SEQUENCE_FLAGS_ICICLE_DUST_AND_BREATH \
  (DIMBOSS_SEQUENCE_FLAGS_ICICLE_DUST_POINTS | DIMBOSS_SEQUENCE_FLAG_BREATH_BURST)
#define DIMBOSS_SEQUENCE_FLAGS_TONSIL_IMPACT \
  (DIMBOSS_SEQUENCE_FLAG_0020 | DIMBOSS_SEQUENCE_FLAG_8000)
#define DIMBOSS_SEQUENCE_FLAGS_LIFT_IMPACT_AND_RUMBLE \
  (DIMBOSS_SEQUENCE_FLAG_40000 | DIMBOSS_SEQUENCE_FLAG_0004)
#define DIMBOSS_SEQUENCE_FLAGS_ICICLE_HIT_EFFECTS \
  (DIMBOSS_SEQUENCE_FLAG_CAPTURE_BLUE_WHITE_VELOCITY | DIMBOSS_SEQUENCE_FLAG_0100 | \
   DIMBOSS_SEQUENCE_FLAG_0080 | DIMBOSS_SEQUENCE_FLAG_0040)
#define DIMBOSS_SEQUENCE_FLAGS_40004 \
  (DIMBOSS_SEQUENCE_FLAG_40000 | DIMBOSS_SEQUENCE_FLAG_0004)
#define DIMBOSS_SEQUENCE_FLAGS_2001 \
  (DIMBOSS_SEQUENCE_FLAG_2000 | DIMBOSS_SEQUENCE_FLAG_0001)
#define DIMBOSS_SEQUENCE_FLAGS_8021 \
  (DIMBOSS_SEQUENCE_FLAG_8000 | DIMBOSS_SEQUENCE_FLAG_0020 | DIMBOSS_SEQUENCE_FLAG_0001)
#define DIMBOSS_SEQUENCE_FLAGS_PERSIST_AFTER_EFFECT_UPDATE \
  (DIMBOSS_SEQUENCE_FLAG_80000 | DIMBOSS_SEQUENCE_FLAG_SPAWN_BLUE_WHITE_EFFECT | \
   DIMBOSS_SEQUENCE_FLAGS_ICICLE_DUST_POINTS | DIMBOSS_SEQUENCE_FLAG_0100 | \
   DIMBOSS_SEQUENCE_FLAG_0080 | DIMBOSS_SEQUENCE_FLAG_0040 | DIMBOSS_SEQUENCE_FLAG_0020 | \
   DIMBOSS_SEQUENCE_FLAG_BREATH_BURST)

#define DIMBOSS_MAP_DIR 0x1C
#define DIMBOSS_GUT_MAP_DIR 0x1B
#define DIMTOP_MAP_DIR 0x13
#define DIMBOSS_MAP_AREA_LIFT 0
#define DIMBOSS_MAP_AREA_BOSS 2
#define DIMBOSS_MAP_AREA_INTRO_GATE 5

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
  u8 enabled;
  u8 pad4D[0x2F8 - 0x4D];
  u8 glowType;
  u8 glowAlpha;
  s8 glowAlphaStep;
} DIMbossEffect;

typedef union DIMbossSteamFlags {
  u8 raw;
  struct {
    u8 sfxPending : 1;
    u8 rest : 7;
  } bits;
} DIMbossSteamFlags;

typedef struct DIMbossEffectMarker {
  u16 rotX;
  u16 rotY;
  u16 rotZ;
  u16 pad06;
  f32 scale;
  f32 x;
  f32 y;
  f32 z;
} DIMbossEffectMarker;

typedef struct DIMbossTopState {
  DIMbossEffect *effect;
  DIMbossEffectMarker blueWhiteEffectSource;
  DIMbossEffectMarker breathBurstSource;
  DIMbossEffectMarker tonsilDustSource;
  DIMbossEffectMarker liftGlowSource;
  f32 breathBurstMtx[12];
  f32 blueWhiteVelocity[3];
  u8 pad0A0[0xA4 - 0xA0];
  f32 launchLift;
  f32 idleLift;
  f32 introSinkHeight;
  s32 defeatTimer;
  u8 stompDustDelay;
  u8 pad0B5;
  DIMbossSteamFlags steamFlags;
} DIMbossTopState;

typedef struct DIMbossAnimScratch {
  union {
    f32 effectVelocity[3];
    u8 pad000[DIMBOSS_ANIM_CONTROLLER_OFFSET];
  };
  u8 animController[DIMBOSS_ANIM_CONTROLLER_SIZE];
  void (*animTable[DIMBOSS_ANIM_TABLE_COUNT])(void);
  void (*hitDetectAnimTable[DIMBOSS_HITDETECT_ANIM_TABLE_COUNT])(void);
} DIMbossAnimScratch;

typedef struct DIMbossRuntime {
  u8 pad000[0x25F];
  u8 effectActive;
  u8 pad260[0x270 - 0x260];
  s16 field270;
  u8 pad272[0x274 - 0x272];
  s16 scale;
  u8 pad276[0x2D0 - 0x276];
  int targetModel;
  u8 pad2D4[0x314 - 0x2D4];
  s32 sequenceTriggerFlags;
  u8 pad318[0x346 - 0x318];
  u8 hitResult;
  u8 pad347[0x349 - 0x347];
  u8 animFinished;
  u8 pad34A[0x34F - 0x34A];
  s8 hitDamageCount;
  u8 pad350[0x354 - 0x350];
  s8 animMode;
  u8 pad355[0x35C - 0x355];
  u8 moveScratch[0x3E0 - 0x35C];
  u32 savedPendingParentObj;
  u8 pad3E4[0x3F4 - 0x3E4];
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
  union {
    ObjAnimComponent anim;
    struct {
      u8 pad00[0x08];
      f32 baseScale;
      f32 posX;
      f32 posY;
      f32 posZ;
      u8 pad18[0x30 - 0x18];
      void *parentObj;
      u8 pad34[0x4C - 0x34];
      DIMbossConfig *config;
      u8 pad50[0xA2 - 0x50];
      s16 activeModelId;
      u8 padA4[0xA8 - 0xA4];
      f32 modelScale;
      u8 padAC[0xAF - 0xAC];
      u8 objectFlags;
    };
  };
  u8 padB0[0xB4 - 0xB0];
  s16 animStateId;
  u8 padB6[0xB8 - 0xB6];
  DIMbossRuntime *runtime;
  int (*updateState)(struct DIMbossObject *obj,u32 param_2,
                     ObjAnimUpdateState *animUpdate);
  u8 padC0[0xC8 - 0xC0];
  void *childObject;
  u8 padCC[0xE4 - 0xCC];
  u8 updateMode;
  u8 padE5[0xF4 - 0xE5];
  int renderPause;
  int updateInitialized;
} DIMbossObject;

STATIC_ASSERT(sizeof(DIMbossEffect) == 0x2FB);
STATIC_ASSERT(offsetof(DIMbossEffect, enabled) == 0x4C);
STATIC_ASSERT(offsetof(DIMbossEffect, glowType) == 0x2F8);
STATIC_ASSERT(offsetof(DIMbossEffect, glowAlpha) == 0x2F9);
STATIC_ASSERT(offsetof(DIMbossEffect, glowAlphaStep) == 0x2FA);

STATIC_ASSERT(sizeof(DIMbossEffectMarker) == 0x18);
STATIC_ASSERT(offsetof(DIMbossEffectMarker, scale) == 0x08);
STATIC_ASSERT(offsetof(DIMbossEffectMarker, x) == 0x0C);

STATIC_ASSERT(sizeof(DIMbossTopState) == 0xB8);
STATIC_ASSERT(offsetof(DIMbossTopState, effect) == 0x00);
STATIC_ASSERT(offsetof(DIMbossTopState, blueWhiteEffectSource) == 0x04);
STATIC_ASSERT(offsetof(DIMbossTopState, breathBurstSource) == 0x1C);
STATIC_ASSERT(offsetof(DIMbossTopState, tonsilDustSource) == 0x34);
STATIC_ASSERT(offsetof(DIMbossTopState, liftGlowSource) == 0x4C);
STATIC_ASSERT(offsetof(DIMbossTopState, breathBurstMtx) == 0x64);
STATIC_ASSERT(offsetof(DIMbossTopState, blueWhiteVelocity) == 0x94);
STATIC_ASSERT(offsetof(DIMbossTopState, launchLift) == 0xA4);
STATIC_ASSERT(offsetof(DIMbossTopState, idleLift) == 0xA8);
STATIC_ASSERT(offsetof(DIMbossTopState, introSinkHeight) == 0xAC);
STATIC_ASSERT(offsetof(DIMbossTopState, defeatTimer) == 0xB0);
STATIC_ASSERT(offsetof(DIMbossTopState, stompDustDelay) == 0xB4);
STATIC_ASSERT(offsetof(DIMbossTopState, steamFlags) == 0xB6);

STATIC_ASSERT(sizeof(DIMbossAnimScratch) == 0x6D8);
STATIC_ASSERT(offsetof(DIMbossAnimScratch, effectVelocity) == 0x00);
STATIC_ASSERT(offsetof(DIMbossAnimScratch, animController) == DIMBOSS_ANIM_CONTROLLER_OFFSET);
STATIC_ASSERT(offsetof(DIMbossAnimScratch, animTable) == DIMBOSS_ANIM_TABLE_OFFSET);
STATIC_ASSERT(offsetof(DIMbossAnimScratch, hitDetectAnimTable) == DIMBOSS_HITDETECT_ANIM_TABLE_OFFSET);

STATIC_ASSERT(sizeof(DIMbossRuntime) == DIMBOSS_RUNTIME_SIZE);
STATIC_ASSERT(offsetof(DIMbossRuntime, effectActive) == 0x25F);
STATIC_ASSERT(offsetof(DIMbossRuntime, field270) == 0x270);
STATIC_ASSERT(offsetof(DIMbossRuntime, scale) == 0x274);
STATIC_ASSERT(offsetof(DIMbossRuntime, targetModel) == 0x2D0);
STATIC_ASSERT(offsetof(DIMbossRuntime, sequenceTriggerFlags) == 0x314);
STATIC_ASSERT(offsetof(DIMbossRuntime, hitResult) == 0x346);
STATIC_ASSERT(offsetof(DIMbossRuntime, animFinished) == 0x349);
STATIC_ASSERT(offsetof(DIMbossRuntime, hitDamageCount) == 0x34F);
STATIC_ASSERT(offsetof(DIMbossRuntime, animMode) == 0x354);
STATIC_ASSERT(offsetof(DIMbossRuntime, moveScratch) == 0x35C);
STATIC_ASSERT(offsetof(DIMbossRuntime, activeMoveId) == 0x3F4);
STATIC_ASSERT(offsetof(DIMbossRuntime, eventGameBit) == 0x3F6);
STATIC_ASSERT(offsetof(DIMbossRuntime, savedPendingParentObj) == 0x3E0);
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

STATIC_ASSERT(offsetof(DIMbossObject, anim) == 0x00);
STATIC_ASSERT(offsetof(DIMbossObject, baseScale) == 0x08);
STATIC_ASSERT(offsetof(DIMbossObject, baseScale) == offsetof(ObjAnimComponent, rootMotionScale));
STATIC_ASSERT(offsetof(DIMbossObject, posX) == 0x0C);
STATIC_ASSERT(offsetof(DIMbossObject, posX) == offsetof(ObjAnimComponent, localPosX));
STATIC_ASSERT(offsetof(DIMbossObject, parentObj) == offsetof(ObjAnimComponent, parent));
STATIC_ASSERT(offsetof(DIMbossObject, config) == 0x4C);
STATIC_ASSERT(offsetof(DIMbossObject, config) == offsetof(ObjAnimComponent, placementData));
STATIC_ASSERT(offsetof(DIMbossObject, activeModelId) == 0xA2);
STATIC_ASSERT(offsetof(DIMbossObject, activeModelId) == offsetof(ObjAnimComponent, activeMove));
STATIC_ASSERT(offsetof(DIMbossObject, modelScale) == 0xA8);
STATIC_ASSERT(offsetof(DIMbossObject, modelScale) == offsetof(ObjAnimComponent, hitboxScale));
STATIC_ASSERT(offsetof(DIMbossObject, objectFlags) == 0xAF);
STATIC_ASSERT(offsetof(DIMbossObject, objectFlags) == offsetof(ObjAnimComponent, resetHitboxFlags));
STATIC_ASSERT(offsetof(DIMbossObject, animStateId) == 0xB4);
STATIC_ASSERT(offsetof(DIMbossObject, runtime) == 0xB8);
STATIC_ASSERT(offsetof(DIMbossObject, updateState) == 0xBC);
STATIC_ASSERT(offsetof(DIMbossObject, childObject) == 0xC8);
STATIC_ASSERT(offsetof(DIMbossObject, updateMode) == 0xE4);
STATIC_ASSERT(offsetof(DIMbossObject, renderPause) == 0xF4);
STATIC_ASSERT(offsetof(DIMbossObject, updateInitialized) == 0xF8);

int DIMboss_updateState(DIMbossObject *obj,u32 param_2,ObjAnimUpdateState *animUpdate);
void DIMboss_func0B(void);
int DIMboss_setScale(DIMbossObject *obj);
int DIMboss_getExtraSize(void);
int DIMboss_getObjectTypeId(void);
void DIMboss_free(DIMbossObject *obj);
void DIMboss_render(DIMbossObject *obj,u32 param_2,u32 param_3,u32 param_4,
                    u32 param_5,char shouldRender);
void DIMboss_hitDetect(DIMbossObject *obj);
void DIMboss_update(DIMbossObject *obj);
void DIMboss_init(DIMbossObject *obj,u32 param_2,int param_3);
void DIMboss_release(void);
void DIMboss_initialise(void);
void DIMboss_initialiseAnimTables(void);
extern ObjectDescriptor12 gDIM_BossObjDescriptor;

#endif /* MAIN_DLL_DIM_DIMBOSS_H_ */
