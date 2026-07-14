#ifndef MAIN_DLL_CF_LANTERNFIREFLY_STATE_H_
#define MAIN_DLL_CF_LANTERNFIREFLY_STATE_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/modellight_api.h"

/* LanternFireFly per-object extra state. */
typedef struct LanternFireFlyState {
  ModelLightStruct* light; /* 0x00 */
  f32 controlX[4];  /* 0x04: B-spline control ring (shifted per segment) */
  f32 controlY[4];  /* 0x14 */
  f32 controlZ[4];  /* 0x24 */
  f32 offX;         /* 0x34: next segment offset (vecRotateZXY output) */
  f32 offY;         /* 0x38 */
  f32 offZ;         /* 0x3c */
  f32 splineT;      /* 0x40 */
  f32 speed;        /* 0x44 */
  f32 field48;      /* 0x48 */
  f32 field4C;      /* 0x4c */
  f32 driftRangeZ;  /* 0x50: per-placement Z drift distance (from placement unk1C); caps offZ excursion */
  f32 anchorX;      /* 0x54 */
  f32 anchorY;      /* 0x58 */
  f32 anchorZ;      /* 0x5c */
  s32 timer;        /* 0x60 */
  s16 randAngle;    /* 0x64 */
  s16 randPeriod;   /* 0x66 */
  s16 wanderRange;      /* 0x68: randAngle wander range (windlift fn_801868D0) */
  u8 stateId;       /* 0x6a */
  u8 field6B;       /* 0x6b */
  u8 animFrame;     /* 0x6c */
  u8 pad6D;         /* 0x6d */
  u8 lightSpawned;  /* 0x6e */
  u8 field6F;       /* 0x6f */
  u8 modeFlags;     /* 0x70: bits 6..7 = lantern slot kind */
  u8 pad71[0x74 - 0x71];
} LanternFireFlyState;

typedef struct LanternFireFlySpawnDef {
  u8 pad00[0x08];
  f32 x;
  f32 y;
  f32 z;
} LanternFireFlySpawnDef;

STATIC_ASSERT(sizeof(LanternFireFlyState) == 0x74);
STATIC_ASSERT(offsetof(LanternFireFlyState, controlX) == 0x04);
STATIC_ASSERT(offsetof(LanternFireFlyState, offX) == 0x34);
STATIC_ASSERT(offsetof(LanternFireFlyState, splineT) == 0x40);
STATIC_ASSERT(offsetof(LanternFireFlyState, anchorX) == 0x54);
STATIC_ASSERT(offsetof(LanternFireFlyState, timer) == 0x60);
STATIC_ASSERT(offsetof(LanternFireFlyState, randAngle) == 0x64);
STATIC_ASSERT(offsetof(LanternFireFlyState, stateId) == 0x6A);
STATIC_ASSERT(offsetof(LanternFireFlyState, lightSpawned) == 0x6E);
STATIC_ASSERT(offsetof(LanternFireFlyState, modeFlags) == 0x70);

#endif /* MAIN_DLL_CF_LANTERNFIREFLY_STATE_H_ */
