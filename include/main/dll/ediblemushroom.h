#ifndef MAIN_DLL_EDIBLEMUSHROOM_H_
#define MAIN_DLL_EDIBLEMUSHROOM_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/dll/curve_walker.h"
#include "main/objanim_internal.h"

typedef struct EdibleMushroomPlacement {
  u8 pad00[0x18];
  u8 objectTypeParam; /* 0x18: variant selector (switch 4/5) */
  u8 pad19[0x1A - 0x19];
  s16 gameBitId;      /* 0x1a: pickup/spawn GameBit id */
  u8 paramByte;       /* 0x1c: normalized into mapParamScale */
} EdibleMushroomPlacement;

typedef struct EnemyMushroomMapData {
  u8 pad00[0x08];
  f32 posX;
  f32 posY;
  f32 posZ;
  u8 pad14[0x1A - 0x14];
  u16 respawnFrameLimit;
  s16 gameBitId;
  s8 yawParam;
  s8 objectTypeParam;
} EnemyMushroomMapData;

typedef struct EnemyMushroomModelState {
  u8 pad00[0x30];
  u32 flags;
} EnemyMushroomModelState;

typedef struct EnemyMushroomState {
  f32 timer;
  f32 heightTarget;
  f32 riseDuration;
  f32 baseScale;
  f32 riseStep;
  u8 resetToSpawn;
  u8 flags;
  u8 pad16[0x20 - 0x16];
  f32 hitEffectX;
  f32 hitEffectY;
  f32 hitEffectZ;
  f32 hitRadius;
  f32 effectTimer;
  s16 respawnFrameLimit;
  u8 stateId;
  u8 stateFlags;
} EnemyMushroomState;

typedef struct EnemyMushroomObject {
  union {
    ObjAnimComponent anim;
    struct {
      s16 rotX;
      s16 rotY;
      s16 rotZ;
      s16 flags;
      f32 scale;
      f32 posX;
      f32 posY;
      f32 posZ;
      u8 pad18[0x36 - 0x18];
      u8 alpha;
      u8 pad37[0x4C - 0x37];
      EnemyMushroomMapData *mapData;
      u8 pad50[0x64 - 0x50];
      EnemyMushroomModelState *modelState;
      u8 pad68[0xB0 - 0x68];
    };
  };
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  EnemyMushroomState *state;
} EnemyMushroomObject;

/* ediblemushroom extra block (size 0x144 = ediblemushroom_getExtraSize). */
typedef struct EdibleMushroomState {
  RomCurveWalker curve;
  f32 currentTargetDistance;
  f32 previousTargetDistance;
  f32 lungeRootSpeedScale;
  f32 mapParamScale;
  f32 lungeRange;
  f32 retreatRange;
  f32 curveAdvanceStep;
  f32 burrowAttackTimer;
  f32 sporePuffTimer;
  f32 tailSwingFxTimer;
  s16 moveAngle;
  u8 pad132[2];
  s16 collectedGameBitId;
  u8 animState;
  u8 flags;
  u8 pad138;
  u8 seqResetPending;
  u8 pad13A[2];
  s16 pickupMsgBitId;
  s16 pickupMsgValue;
  f32 pickupMsgDelay;
} EdibleMushroomState;

STATIC_ASSERT(offsetof(EnemyMushroomMapData, posX) == 0x08);
STATIC_ASSERT(offsetof(EnemyMushroomMapData, posY) == 0x0C);
STATIC_ASSERT(offsetof(EnemyMushroomMapData, posZ) == 0x10);
STATIC_ASSERT(offsetof(EnemyMushroomMapData, respawnFrameLimit) == 0x1A);
STATIC_ASSERT(offsetof(EnemyMushroomMapData, gameBitId) == 0x1C);
STATIC_ASSERT(offsetof(EnemyMushroomMapData, yawParam) == 0x1E);
STATIC_ASSERT(offsetof(EnemyMushroomMapData, objectTypeParam) == 0x1F);
STATIC_ASSERT(offsetof(EnemyMushroomModelState, flags) == 0x30);
STATIC_ASSERT(offsetof(EnemyMushroomState, timer) == 0x00);
STATIC_ASSERT(offsetof(EnemyMushroomState, heightTarget) == 0x04);
STATIC_ASSERT(offsetof(EnemyMushroomState, riseDuration) == 0x08);
STATIC_ASSERT(offsetof(EnemyMushroomState, baseScale) == 0x0C);
STATIC_ASSERT(offsetof(EnemyMushroomState, riseStep) == 0x10);
STATIC_ASSERT(offsetof(EnemyMushroomState, resetToSpawn) == 0x14);
STATIC_ASSERT(offsetof(EnemyMushroomState, flags) == 0x15);
STATIC_ASSERT(offsetof(EnemyMushroomState, hitEffectX) == 0x20);
STATIC_ASSERT(offsetof(EnemyMushroomState, hitRadius) == 0x2C);
STATIC_ASSERT(offsetof(EnemyMushroomState, effectTimer) == 0x30);
STATIC_ASSERT(offsetof(EnemyMushroomState, respawnFrameLimit) == 0x34);
STATIC_ASSERT(offsetof(EnemyMushroomState, stateId) == 0x36);
STATIC_ASSERT(offsetof(EnemyMushroomState, stateFlags) == 0x37);
STATIC_ASSERT(offsetof(EnemyMushroomObject, anim) == 0x00);
STATIC_ASSERT(offsetof(EnemyMushroomObject, scale) == offsetof(ObjAnimComponent, rootMotionScale));
STATIC_ASSERT(offsetof(EnemyMushroomObject, posX) == offsetof(ObjAnimComponent, localPosX));
STATIC_ASSERT(offsetof(EnemyMushroomObject, alpha) == offsetof(ObjAnimComponent, alpha));
STATIC_ASSERT(offsetof(EnemyMushroomObject, mapData) == offsetof(ObjAnimComponent, placementData));
STATIC_ASSERT(offsetof(EnemyMushroomObject, modelState) == offsetof(ObjAnimComponent, modelState));
STATIC_ASSERT(offsetof(EnemyMushroomObject, objectFlags) == 0xB0);
STATIC_ASSERT(offsetof(EnemyMushroomObject, state) == 0xB8);

STATIC_ASSERT(offsetof(EdibleMushroomState, curve) == 0x000);
STATIC_ASSERT(offsetof(EdibleMushroomState, currentTargetDistance) == 0x108);
STATIC_ASSERT(offsetof(EdibleMushroomState, lungeRootSpeedScale) == 0x110);
STATIC_ASSERT(offsetof(EdibleMushroomState, mapParamScale) == 0x114);
STATIC_ASSERT(offsetof(EdibleMushroomState, lungeRange) == 0x118);
STATIC_ASSERT(offsetof(EdibleMushroomState, retreatRange) == 0x11C);
STATIC_ASSERT(offsetof(EdibleMushroomState, curveAdvanceStep) == 0x120);
STATIC_ASSERT(offsetof(EdibleMushroomState, moveAngle) == 0x130);
STATIC_ASSERT(offsetof(EdibleMushroomState, collectedGameBitId) == 0x134);
STATIC_ASSERT(offsetof(EdibleMushroomState, animState) == 0x136);
STATIC_ASSERT(offsetof(EdibleMushroomState, flags) == 0x137);
STATIC_ASSERT(offsetof(EdibleMushroomState, seqResetPending) == 0x139);
STATIC_ASSERT(offsetof(EdibleMushroomState, pickupMsgBitId) == 0x13C);
STATIC_ASSERT(offsetof(EdibleMushroomState, pickupMsgValue) == 0x13E);
STATIC_ASSERT(offsetof(EdibleMushroomState, pickupMsgDelay) == 0x140);
STATIC_ASSERT(sizeof(EdibleMushroomState) == 0x144);

void ediblemushroom_init(int obj, int aux);
int EdibleMushroom_SeqFn(int *obj);
void enemymushroom_resetToSpawn(EnemyMushroomObject *obj,EnemyMushroomState *state,
                                int enableTimer);
int enemymushroom_getExtraSize(void);
int enemymushroom_getObjectTypeId(EnemyMushroomObject *obj);
void enemymushroom_free(EnemyMushroomObject *obj);
void enemymushroom_hitDetect(void);

#endif /* MAIN_DLL_EDIBLEMUSHROOM_H_ */
