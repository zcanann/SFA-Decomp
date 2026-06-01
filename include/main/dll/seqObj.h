#ifndef MAIN_DLL_SEQOBJ_H_
#define MAIN_DLL_SEQOBJ_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"

typedef struct WispBaddieState {
  int curve;
  int playerObj;
  f32 hitRadius;
  f32 maxHitRadius;
  f32 playerDistance;
  f32 curveDistance;
  f32 triggerDistance;
  f32 cryTimer;
  int particleId;
  u8 flags;
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

void wispbaddie_update(int obj);
void FUN_8014fd38(int param_1);
void FUN_8014fd80(uint param_1);
void FUN_8014fd84(uint param_1,int param_2,int param_3);
void FUN_8014fef8(undefined4 param_1,int param_2,undefined4 param_3,int param_4);
void FUN_8014ff20(void);
void FUN_8014ff24(short *param_1,undefined4 param_2);
void FUN_8014ff4c(undefined4 param_1,int param_2);
void FUN_8014ffa8(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void wispbaddie_release(void);
void wispbaddie_initialise(void);

extern ObjectDescriptor gWispBaddieObjDescriptor;

#endif /* MAIN_DLL_SEQOBJ_H_ */
