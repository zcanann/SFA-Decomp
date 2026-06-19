#ifndef MAIN_DLL_DIM_DIMBOSSTONSIL_H_
#define MAIN_DLL_DIM_DIMBOSSTONSIL_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/objanim_update.h"

#define DIMBOSSTONSIL_OBJECT_TYPE 0x4b
#define DIMBOSSTONSIL_STATE_SIZE 0x410
#define DIMBOSSTONSIL_SCALE_OFFSET 0x274
#define DIMBOSSTONSIL_ACTIVE_OFFSET 0x27a
#define DIMBOSSTONSIL_STUN_READY_OFFSET 0x27b
#define DIMBOSSTONSIL_RECOVERY_TIMER_OFFSET 0x2a0
#define DIMBOSSTONSIL_HIT_RESULT_OFFSET 0x346
#define DIMBOSSTONSIL_ANIM_FINISHED_OFFSET 0x349
#define DIMBOSSTONSIL_HIT_DAMAGE_COUNT_OFFSET 0x34f
#define DIMBOSSTONSIL_HEALTH_PHASE_OFFSET 0x354
#define DIMBOSSTONSIL_HIT_POINTS_LEFT_OFFSET 0x354
#define DIMBOSSTONSIL_ANIM_POINTS_OFFSET 0x35c
#define DIMBOSSTONSIL_SAVED_OBJ_FIELD_C0_OFFSET 0x3e0
#define DIMBOSSTONSIL_ANIM_FRAME_OFFSET 0x3f4
#define DIMBOSSTONSIL_FIELD270_OFFSET 0x270
#define DIMBOSSTONSIL_EVENT_GAMEBIT_OFFSET 0x3f6
#define DIMBOSSTONSIL_STATE_FLAGS_OFFSET 0x400
#define DIMBOSSTONSIL_HIT_REACT_MODE_OFFSET 0x405

#define DIMBOSSTONSIL_ANIM_EVENT_START_STEAM 1
#define DIMBOSSTONSIL_ANIM_EVENT_ENABLE_AREA 2
#define DIMBOSSTONSIL_ANIM_EVENT_DISABLE_AREA 3
#define DIMBOSSTONSIL_ANIM_EVENT_ENABLE_LIGHT 4
#define DIMBOSSTONSIL_ANIM_EVENT_DISABLE_LIGHT 5

#define DIMBOSSTONSIL_MAP_DIR 0x1c
#define DIMBOSSTONSIL_MAP_AREA 1
#define DIMBOSSTONSIL_STEAM_ENVFX 0xd8
#define DIMBOSSTONSIL_STEAM_MUSIC 0xee
#define DIMBOSSTONSIL_RUMBLE_SFX 0x189
#define DIMBOSSTONSIL_STATE_FLAG_START_MOVE 2

typedef struct DIMbosstonsilLight {
  u8 pad00[0x4C];
  u8 visible;
  u8 pad4D[0x2F8 - 0x4D];
  u8 active;
  u8 glowIntensity;
  s8 glowIntensityStep;
} DIMbosstonsilLight;

typedef struct DIMbosstonsilConfig {
  u8 pad00[0x08];
  f32 spawnX;
  f32 spawnY;
  f32 spawnZ;
  u8 pad14[0x2C - 0x14];
  s16 eventId;
  s8 animObjId;
} DIMbosstonsilConfig;

typedef struct DIMbosstonsilState {
  u8 pad000[0x25F];
  u8 effectActive;
  u8 pad260[DIMBOSSTONSIL_FIELD270_OFFSET - 0x260];
  s16 field270;
  u8 pad272[DIMBOSSTONSIL_SCALE_OFFSET - 0x272];
  s16 scale;
  u8 pad276[DIMBOSSTONSIL_ACTIVE_OFFSET - 0x276];
  s8 active;
  s8 stunReady;
  u8 pad27C[DIMBOSSTONSIL_RECOVERY_TIMER_OFFSET - 0x27C];
  f32 recoveryTimer;
  u8 pad2A4[0x2D0 - 0x2A4];
  void *targetObject;
  u8 pad2D4[DIMBOSSTONSIL_HIT_RESULT_OFFSET - 0x2D4];
  s8 hitResult;
  u8 pad347[DIMBOSSTONSIL_ANIM_FINISHED_OFFSET - 0x347];
  s8 animFinished;
  u8 pad34A[DIMBOSSTONSIL_HIT_DAMAGE_COUNT_OFFSET - 0x34A];
  s8 hitDamageCount;
  u8 pad350[DIMBOSSTONSIL_HIT_POINTS_LEFT_OFFSET - 0x350];
  s8 hitPointsLeft;
  u8 pad355[DIMBOSSTONSIL_ANIM_POINTS_OFFSET - 0x355];
  u8 animPoints[DIMBOSSTONSIL_SAVED_OBJ_FIELD_C0_OFFSET - DIMBOSSTONSIL_ANIM_POINTS_OFFSET];
  u32 savedObjFieldC0;
  u8 pad3E4[DIMBOSSTONSIL_ANIM_FRAME_OFFSET - 0x3E4];
  s16 animFrame;
  s16 eventGameBit;
  u8 pad3F8[DIMBOSSTONSIL_STATE_FLAGS_OFFSET - 0x3F8];
  u16 stateFlags;
  u8 pad402[DIMBOSSTONSIL_HIT_REACT_MODE_OFFSET - 0x402];
  u8 hitReactMode;
  u8 pad406[DIMBOSSTONSIL_STATE_SIZE - 0x406];
} DIMbosstonsilState;

STATIC_ASSERT(offsetof(DIMbosstonsilLight, visible) == 0x4C);
STATIC_ASSERT(offsetof(DIMbosstonsilLight, active) == 0x2F8);
STATIC_ASSERT(offsetof(DIMbosstonsilLight, glowIntensity) == 0x2F9);
STATIC_ASSERT(offsetof(DIMbosstonsilLight, glowIntensityStep) == 0x2FA);

STATIC_ASSERT(offsetof(DIMbosstonsilConfig, spawnX) == 0x08);
STATIC_ASSERT(offsetof(DIMbosstonsilConfig, spawnY) == 0x0C);
STATIC_ASSERT(offsetof(DIMbosstonsilConfig, spawnZ) == 0x10);
STATIC_ASSERT(offsetof(DIMbosstonsilConfig, eventId) == 0x2C);
STATIC_ASSERT(offsetof(DIMbosstonsilConfig, animObjId) == 0x2E);

STATIC_ASSERT(sizeof(DIMbosstonsilState) == DIMBOSSTONSIL_STATE_SIZE);
STATIC_ASSERT(offsetof(DIMbosstonsilState, effectActive) == 0x25F);
STATIC_ASSERT(offsetof(DIMbosstonsilState, field270) == DIMBOSSTONSIL_FIELD270_OFFSET);
STATIC_ASSERT(offsetof(DIMbosstonsilState, scale) == DIMBOSSTONSIL_SCALE_OFFSET);
STATIC_ASSERT(offsetof(DIMbosstonsilState, active) == DIMBOSSTONSIL_ACTIVE_OFFSET);
STATIC_ASSERT(offsetof(DIMbosstonsilState, stunReady) == DIMBOSSTONSIL_STUN_READY_OFFSET);
STATIC_ASSERT(offsetof(DIMbosstonsilState, recoveryTimer) == DIMBOSSTONSIL_RECOVERY_TIMER_OFFSET);
STATIC_ASSERT(offsetof(DIMbosstonsilState, targetObject) == 0x2D0);
STATIC_ASSERT(offsetof(DIMbosstonsilState, hitResult) == DIMBOSSTONSIL_HIT_RESULT_OFFSET);
STATIC_ASSERT(offsetof(DIMbosstonsilState, animFinished) == DIMBOSSTONSIL_ANIM_FINISHED_OFFSET);
STATIC_ASSERT(offsetof(DIMbosstonsilState, hitDamageCount) == DIMBOSSTONSIL_HIT_DAMAGE_COUNT_OFFSET);
STATIC_ASSERT(offsetof(DIMbosstonsilState, hitPointsLeft) == DIMBOSSTONSIL_HIT_POINTS_LEFT_OFFSET);
STATIC_ASSERT(offsetof(DIMbosstonsilState, animPoints) == DIMBOSSTONSIL_ANIM_POINTS_OFFSET);
STATIC_ASSERT(offsetof(DIMbosstonsilState, savedObjFieldC0) == DIMBOSSTONSIL_SAVED_OBJ_FIELD_C0_OFFSET);
STATIC_ASSERT(offsetof(DIMbosstonsilState, animFrame) == DIMBOSSTONSIL_ANIM_FRAME_OFFSET);
STATIC_ASSERT(offsetof(DIMbosstonsilState, eventGameBit) == DIMBOSSTONSIL_EVENT_GAMEBIT_OFFSET);
STATIC_ASSERT(offsetof(DIMbosstonsilState, stateFlags) == DIMBOSSTONSIL_STATE_FLAGS_OFFSET);
STATIC_ASSERT(offsetof(DIMbosstonsilState, hitReactMode) == DIMBOSSTONSIL_HIT_REACT_MODE_OFFSET);

extern DIMbosstonsilLight *gDIMbosstonsilLight;
extern s8 gDIMbosstonsilRoutePhase;

int dll_DIM_BossGutSpik_update(void *obj,u32 param_2,ObjAnimUpdateState *animUpdate);
void DIMbosstonsil_func0B(void);
int DIMbosstonsil_setScale(int obj);
int DIMbosstonsil_getExtraSize(void);
int DIMbosstonsil_getObjectTypeId(void);
void DIMbosstonsil_free(void *obj);
void DIMbosstonsil_render(void *obj,u32 p2,u32 p3,u32 p4,u32 p5,
                          char visible);
void DIMbosstonsil_hitDetect(void *obj);
void DIMbosstonsil_update(void *obj);
void DIMbosstonsil_init(int obj,u32 param_2,int isAltVariant);
void DIMbosstonsil_release(void);
void DIMbosstonsil_initialise(void);

#endif /* MAIN_DLL_DIM_DIMBOSSTONSIL_H_ */
