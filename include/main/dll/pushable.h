#ifndef MAIN_DLL_PUSHABLE_H_
#define MAIN_DLL_PUSHABLE_H_

#include "global.h"

typedef struct PushablePoint {
  f32 x;
  f32 y;
  f32 z;
} PushablePoint;

typedef struct PushableFlags114 {
  u8 b7 : 1;
  u8 b6 : 1;
  u8 rest : 6;
} PushableFlags114;

/*
 * Per-object extra state for the pushable (push/pull block) family
 * (pushable_getExtraSize == 0x148). Shared by transporter.c,
 * lightning.c (fn_80174438/fn_80174668) and the dll_138.c helpers.
 */
typedef struct PushableState {
  u8 unk00[0x0C];
  f32 cullDistance;
  f32 scale;
  f32 timer_0x14;
  PushablePoint probeLocal[4];
  PushablePoint cornerLocal[4];
  PushablePoint cornerWorld[4];
  u8 padA8[4];
  s16 gameBit;
  s16 gameBit2;
  s32 unk_B0;
  s8 pointCount;
  u8 padB5[3];
  int msgSenderObj;
  void *nearestObj;
  f32 unk_C0;
  f32 unk_C4;
  f32 unk_C8;
  f32 eyeOpenSpeed;
  f32 eyeDriftSpeedX;
  f32 eyeDriftSpeedY;
  f32 eyeOpenAmount;
  f32 eyePosX;
  f32 eyePosY;
  f32 blinkInterval;
  f32 blinkStep;
  f32 blinkPhase;
  f32 unk_F0; /* set via ObjMsg 0x40001 */
  f32 waterDepth;
  f32 prevWaterDepth;
  u8 padFC[4];
  u16 flags;
  u8 cornerIdxPosZ;
  u8 cornerIdxNegZ;
  u8 cornerIdxPosX;
  u8 cornerIdxNegX;
  u8 pad106[2];
  f32 pushAmountX;
  f32 pushAmountZ;
  f32 timer_0x110;
  PushableFlags114 moveFlags;
  s8 pushSfxTimer;
  u8 pad116[2];
  f32 posHistX[5];
  f32 posHistZ[5];
  int yaw;
  u8 requiredHitId;
  u8 savePosDelay;
  u8 savePosEnabled;
  u8 pad147;
} PushableState;

/* PushableState.flags state bits */
#define PUSHABLE_FLAG_RESTORED 0x01   /* restored from saved gameBit / saved-map list */
#define PUSHABLE_FLAG_MOVING_Y 0x02   /* moving vertically this frame (velocityY != 0) */
#define PUSHABLE_FLAG_PUSH_SFX_DUE 0x20 /* push scrape SFX timer elapsed this frame */
#define PUSHABLE_FLAG_INITIALIZED 0x40  /* set at end of pushable_init */
#define PUSHABLE_FLAG_PUSH_LOCKED 0x80  /* push amount frozen (no dx/dz follow) */

/* PushableState.flags push-direction bits (set from dx/dz sign, cleared via ~0xF00) */
#define PUSHABLE_FLAG_PUSH_NEG_X 0x100
#define PUSHABLE_FLAG_PUSH_POS_X 0x200
#define PUSHABLE_FLAG_PUSH_NEG_Z 0x400
#define PUSHABLE_FLAG_PUSH_POS_Z 0x800
#define PUSHABLE_FLAG_PUSH_DIR_MASK 0xF00

STATIC_ASSERT(sizeof(PushableState) == 0x148);
STATIC_ASSERT(offsetof(PushableState, cullDistance) == 0x0C);
STATIC_ASSERT(offsetof(PushableState, probeLocal) == 0x18);
STATIC_ASSERT(offsetof(PushableState, cornerLocal) == 0x48);
STATIC_ASSERT(offsetof(PushableState, cornerWorld) == 0x78);
STATIC_ASSERT(offsetof(PushableState, gameBit) == 0xAC);
STATIC_ASSERT(offsetof(PushableState, pointCount) == 0xB4);
STATIC_ASSERT(offsetof(PushableState, nearestObj) == 0xBC);
STATIC_ASSERT(offsetof(PushableState, eyeOpenAmount) == 0xD8);
STATIC_ASSERT(offsetof(PushableState, waterDepth) == 0xF4);
STATIC_ASSERT(offsetof(PushableState, flags) == 0x100);
STATIC_ASSERT(offsetof(PushableState, pushAmountX) == 0x108);
STATIC_ASSERT(offsetof(PushableState, moveFlags) == 0x114);
STATIC_ASSERT(offsetof(PushableState, posHistX) == 0x118);
STATIC_ASSERT(offsetof(PushableState, posHistZ) == 0x12C);
STATIC_ASSERT(offsetof(PushableState, yaw) == 0x140);
STATIC_ASSERT(offsetof(PushableState, requiredHitId) == 0x144);
STATIC_ASSERT(offsetof(PushableState, savePosEnabled) == 0x146);

#endif /* MAIN_DLL_PUSHABLE_H_ */
