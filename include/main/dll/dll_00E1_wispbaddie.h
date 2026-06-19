#ifndef MAIN_DLL_SEQOBJ_H_
#define MAIN_DLL_SEQOBJ_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/dll/curve_walker.h"
#include "main/object_descriptor.h"

typedef struct GameObject GameObject;

typedef struct WispBaddieState {
  RomCurveWalker *curve;
  GameObject *playerObj;
  f32 hitRadius;
  f32 maxHitRadius;
  f32 playerDistance;
  f32 curveDistance;
  f32 triggerDistance;
  f32 cryTimer;
  int particleId;
  u8 flags;
  u8 pad25;
  s16 pathWavePhase;
  s16 hoverWavePhase;
  u8 pad2a[2];
} WispBaddieState;

STATIC_ASSERT(offsetof(WispBaddieState, curve) == 0x00);
STATIC_ASSERT(offsetof(WispBaddieState, playerObj) == 0x04);
STATIC_ASSERT(offsetof(WispBaddieState, hitRadius) == 0x08);
STATIC_ASSERT(offsetof(WispBaddieState, maxHitRadius) == 0x0C);
STATIC_ASSERT(offsetof(WispBaddieState, playerDistance) == 0x10);
STATIC_ASSERT(offsetof(WispBaddieState, curveDistance) == 0x14);
STATIC_ASSERT(offsetof(WispBaddieState, triggerDistance) == 0x18);
STATIC_ASSERT(offsetof(WispBaddieState, cryTimer) == 0x1C);
STATIC_ASSERT(offsetof(WispBaddieState, particleId) == 0x20);
STATIC_ASSERT(offsetof(WispBaddieState, flags) == 0x24);
STATIC_ASSERT(offsetof(WispBaddieState, pathWavePhase) == 0x26);
STATIC_ASSERT(offsetof(WispBaddieState, hoverWavePhase) == 0x28);
STATIC_ASSERT(sizeof(WispBaddieState) == 0x2C);

void wispbaddie_update(int obj);
void FUN_8014fd38(int param_1);
void FUN_8014fd80(u32 param_1);
void FUN_8014fd84(u32 param_1,int param_2,int param_3);
void FUN_8014fef8(u32 param_1,int param_2,u32 param_3,int param_4);
void FUN_8014ff20(void);
void FUN_8014ff24(short *param_1,u32 param_2);
void FUN_8014ff4c(u32 param_1,int param_2);
void FUN_8014ffa8(u64 param_1,double param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void wispbaddie_release(void);
void wispbaddie_initialise(void);

extern ObjectDescriptor gWispBaddieObjDescriptor;

#endif /* MAIN_DLL_SEQOBJ_H_ */
