#ifndef MAIN_DLL_DIM2CONVEYOR_H_
#define MAIN_DLL_DIM2CONVEYOR_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"
#include "main/dll/rom_curve_interface.h"

#define NW_MAMMOTH_OBJECT_DEF_ID_WHITE 0x0280
#define NW_MAMMOTH_OBJECT_DEF_ID_HEAVY 0x027D
#define NW_MAMMOTH_OBJECT_DEF_ID_BABY 0x027E
#define NW_MAMMOTH_OBJECT_DEF_ID_GUARD 0x0281
#define NW_MAMMOTH_DLL_ID 0x01A1
#define NW_MAMMOTH_CLASS_ID 0x0026
#define NW_MAMMOTH_OBJECT_DEF_SIZE_WHITE 0x1C0
#define NW_MAMMOTH_OBJECT_DEF_SIZE 0x1A0
#define NW_MAMMOTH_PLACEMENT_SIZE 0x24

#define NW_MAMMOTH_GROUP_ID 0x4d
#define NW_MAMMOTH_PATH_POINT_COUNT 4
#define NW_MAMMOTH_PATH_SETUP_POINT_COUNT 4
#define NW_MAMMOTH_TRIGGER_RANDOM_MIN 1
#define NW_MAMMOTH_CURVE_PARAM 0x19
#define NW_MAMMOTH_SOLID_OBJECT_FLAG 0x0400
#define NW_MAMMOTH_MODEL_COLLISION_FLAG 0x00000004
#define NW_MAMMOTH_PATH_CONTROL_FLAG 0x10
#define NW_MAMMOTH_UI_MESSAGE_ID 0xc8
#define NW_MAMMOTH_UI_MESSAGE_TEXT_ID 0x5d0

typedef struct NwMammothMapData {
  u8 pad00[0x1C];
  s8 modelIndex;
  s8 behaviorMode;
} NwMammothMapData;

typedef struct NwMammothModelState {
  u8 pad00[0x30];
  u32 flags;
} NwMammothModelState;

typedef struct NwMammothPathPoint {
  f32 x;
  f32 y;
  f32 z;
} NwMammothPathPoint;

/* Look-at target fed to the character eye-animation update; lives in the
 * eyeAnimState block at 0x40C. */
typedef struct NwMammothEyeTarget {
  u8 enabled;
  u8 pad01[0x04 - 0x01];
  f32 targetX;
  f32 targetY;
  f32 targetZ;
} NwMammothEyeTarget;

typedef struct NwMammothCurveState {
  u8 pad00[0x68];
  f32 pointX;
  f32 pointY;
  f32 pointZ;
  u8 pad74[0x110 - 0x74];
} NwMammothCurveState;

typedef struct NwMammothState {
  f32 sfxTimer;
  f32 stateTimer;
  f32 airMeterValue;
  f32 spawnPosX;
  f32 spawnPosY;
  f32 spawnPosZ;
  f32 playerDistanceSq;
  f32 partfxTimer;
  u8 pad20[0x24 - 0x20];
  void *trackedObject;
  void *playerObject;
  u8 pad2C[0x48 - 0x2C];
  u8 *triggerList;
  f32 animStepScale;
  f32 hitReactStepScale;
  f32 pathSpeed;
  u8 pad58[0x5C - 0x58];
  NwMammothCurveState curveState;
  u8 pathState[0x3D4 - 0x16C];
  u8 hitReactState;
  u8 pad3D5[0x408 - 0x3D5];
  u8 stateIndex;
  u8 pad409[0x40C - 0x409];
  union {
    u8 eyeAnimState[0x43C - 0x40C];
    NwMammothEyeTarget eyeTarget;
  };
  u8 runtimeFlags;
  u8 pad43D[0x43F - 0x43D];
  s8 uiMessageCount;
  ObjAnimEventList animEvents;
  NwMammothPathPoint pathPoints[NW_MAMMOTH_PATH_POINT_COUNT];
} NwMammothState;

typedef struct NwMammothObject {
  union {
    ObjAnimComponent anim;
    struct {
      s16 rotX;
      u8 pad02[0x0C - 0x02];
      f32 localPosX;
      f32 localPosY;
      f32 localPosZ;
      f32 worldPosX;
      f32 worldPosY;
      f32 worldPosZ;
      u8 pad24[0x4C - 0x24];
      NwMammothMapData *mapData;
      u8 pad50[0x64 - 0x50];
      NwMammothModelState *modelState;
      u8 pad68[0xA0 - 0x68];
      s16 currentMove;
      u8 padA2[0xAF - 0xA2];
      u8 hitboxFlags;
    };
  };
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  NwMammothState *state;
  void *seqCallback;
} NwMammothObject;

typedef struct NwMammothTables {
  ObjHitReactEntry normalHitReactEntry;
  ObjHitReactEntry heavyHitReactEntry;
  u8 pad28[0x68 - 0x28];
  s16 stateMoveIds[0x18];
  f32 stateMoveStepScales[0x17];
  u8 stateFlags[1];
} NwMammothTables;

typedef void (*NwMammothPathInitFn)(void *pathState,int param1,int param2,int param3);
typedef void (*NwMammothPathSetupFn)(void *pathState,int pointCount,u8 *pathDataA,u8 *pathDataB,
                                     u32 *pathParam);
typedef void (*NwMammothPathUpdateFn)(NwMammothObject *obj,void *pathState,f32 delta);
typedef void (*NwMammothPathApplyFn)(NwMammothObject *obj,void *pathState);
typedef void (*NwMammothUiMessageFn)(int messageId,int textId);
typedef struct NwMammothPathControlInterface {
  u8 pad00[0x04];
  NwMammothPathInitFn init;
  u8 pad08[0x0C - 0x08];
  NwMammothPathSetupFn setup;
  NwMammothPathUpdateFn update;
  NwMammothPathApplyFn apply;
  NwMammothPathUpdateFn advance;
  u8 pad1C[0x20 - 0x1C];
  NwMammothPathApplyFn attachObject;
} NwMammothPathControlInterface;

typedef struct NwMammothGameUiInterface {
  u8 pad00[0x58];
  NwMammothUiMessageFn showMessage;
} NwMammothGameUiInterface;

STATIC_ASSERT(offsetof(NwMammothMapData, modelIndex) == 0x1C);
STATIC_ASSERT(offsetof(NwMammothMapData, behaviorMode) == 0x1D);
STATIC_ASSERT(offsetof(NwMammothModelState, flags) == 0x30);
STATIC_ASSERT(sizeof(NwMammothPathPoint) == 0x0C);
STATIC_ASSERT(sizeof(NwMammothCurveState) == 0x110);
STATIC_ASSERT(offsetof(NwMammothCurveState, pointX) == 0x68);
STATIC_ASSERT(offsetof(NwMammothCurveState, pointY) == 0x6C);
STATIC_ASSERT(offsetof(NwMammothCurveState, pointZ) == 0x70);
STATIC_ASSERT(offsetof(NwMammothState, sfxTimer) == 0x00);
STATIC_ASSERT(offsetof(NwMammothState, stateTimer) == 0x04);
STATIC_ASSERT(offsetof(NwMammothState, airMeterValue) == 0x08);
STATIC_ASSERT(offsetof(NwMammothState, spawnPosX) == 0x0C);
STATIC_ASSERT(offsetof(NwMammothState, spawnPosY) == 0x10);
STATIC_ASSERT(offsetof(NwMammothState, spawnPosZ) == 0x14);
STATIC_ASSERT(offsetof(NwMammothState, playerDistanceSq) == 0x18);
STATIC_ASSERT(offsetof(NwMammothState, partfxTimer) == 0x1C);
STATIC_ASSERT(offsetof(NwMammothState, trackedObject) == 0x24);
STATIC_ASSERT(offsetof(NwMammothState, playerObject) == 0x28);
STATIC_ASSERT(offsetof(NwMammothState, triggerList) == 0x48);
STATIC_ASSERT(offsetof(NwMammothState, animStepScale) == 0x4C);
STATIC_ASSERT(offsetof(NwMammothState, hitReactStepScale) == 0x50);
STATIC_ASSERT(offsetof(NwMammothState, pathSpeed) == 0x54);
STATIC_ASSERT(offsetof(NwMammothState, curveState) == 0x5C);
STATIC_ASSERT(offsetof(NwMammothState, pathState) == 0x16C);
STATIC_ASSERT(offsetof(NwMammothState, hitReactState) == 0x3D4);
STATIC_ASSERT(offsetof(NwMammothState, stateIndex) == 0x408);
STATIC_ASSERT(offsetof(NwMammothState, eyeAnimState) == 0x40C);
STATIC_ASSERT(offsetof(NwMammothState, eyeTarget) == 0x40C);
STATIC_ASSERT(offsetof(NwMammothEyeTarget, targetX) == 0x04);
STATIC_ASSERT(offsetof(NwMammothEyeTarget, targetY) == 0x08);
STATIC_ASSERT(offsetof(NwMammothEyeTarget, targetZ) == 0x0C);
STATIC_ASSERT(offsetof(NwMammothState, runtimeFlags) == 0x43C);
STATIC_ASSERT(offsetof(NwMammothState, uiMessageCount) == 0x43F);
STATIC_ASSERT(offsetof(NwMammothState, animEvents) == 0x440);
STATIC_ASSERT(offsetof(NwMammothState, pathPoints) == 0x45C);
STATIC_ASSERT(offsetof(NwMammothObject, anim) == 0x00);
STATIC_ASSERT(offsetof(NwMammothObject, localPosX) == offsetof(ObjAnimComponent, localPosX));
STATIC_ASSERT(offsetof(NwMammothObject, worldPosX) == offsetof(ObjAnimComponent, worldPosX));
STATIC_ASSERT(offsetof(NwMammothObject, mapData) == offsetof(ObjAnimComponent, placementData));
STATIC_ASSERT(offsetof(NwMammothObject, modelState) == offsetof(ObjAnimComponent, modelState));
STATIC_ASSERT(offsetof(NwMammothObject, currentMove) == offsetof(ObjAnimComponent, currentMove));
STATIC_ASSERT(offsetof(NwMammothObject, hitboxFlags) == offsetof(ObjAnimComponent, resetHitboxFlags));
STATIC_ASSERT(offsetof(NwMammothObject, objectFlags) == 0xB0);
STATIC_ASSERT(offsetof(NwMammothObject, state) == 0xB8);
STATIC_ASSERT(offsetof(NwMammothObject, seqCallback) == 0xBC);
STATIC_ASSERT(offsetof(NwMammothTables, stateMoveIds) == 0x68);
STATIC_ASSERT(offsetof(NwMammothTables, stateMoveStepScales) == 0x98);
STATIC_ASSERT(offsetof(NwMammothTables, stateFlags) == 0xF4);
STATIC_ASSERT(offsetof(NwMammothPathControlInterface, init) == 0x04);
STATIC_ASSERT(offsetof(NwMammothPathControlInterface, setup) == 0x0C);
STATIC_ASSERT(offsetof(NwMammothPathControlInterface, update) == 0x10);
STATIC_ASSERT(offsetof(NwMammothPathControlInterface, apply) == 0x14);
STATIC_ASSERT(offsetof(NwMammothPathControlInterface, advance) == 0x18);
STATIC_ASSERT(offsetof(NwMammothPathControlInterface, attachObject) == 0x20);
STATIC_ASSERT(offsetof(NwMammothGameUiInterface, showMessage) == 0x58);
void nw_mammoth_update(NwMammothObject *obj,int param_2);
void nw_mammoth_init(NwMammothObject *obj,NwMammothMapData *mapData,int isReload);
void FUN_801cf0b0(u32 param_1,int param_2);
void FUN_801cf0b4(int param_1);
void FUN_801cf108(int param_1);
void FUN_801cf1a0(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9);
int nw_tricky_getExtraSize(void);

#endif /* MAIN_DLL_DIM2CONVEYOR_H_ */
