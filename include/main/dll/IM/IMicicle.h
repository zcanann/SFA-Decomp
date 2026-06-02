#ifndef MAIN_DLL_IM_IMICICLE_H_
#define MAIN_DLL_IM_IMICICLE_H_

#include "ghidra_import.h"

typedef struct ExplodedObjectMapData {
  u8 pad00[0x18];
  u8 objectTypeTag;
  u8 pad19[0x20 - 0x19];
  s16 triggerEventIds[6];
  u8 pad2C[0x3D - 0x2C];
  s8 scaleByte;
} ExplodedObjectMapData;

typedef struct ExplodedObjectState {
  u8 pad00[0x58];
  s32 elapsedFrames;
  s32 durationFrames;
  u8 pad60[0x69 - 0x60];
  u8 explodePhase;
  u8 pad6A[0x6C - 0x6A];
} ExplodedObjectState;

typedef struct ExplodedObject {
  u8 pad00[0x06];
  s16 flags06;
  f32 modelScale;
  f32 x;
  f32 y;
  f32 z;
  u8 pad18[0x36 - 0x18];
  u8 alpha;
  u8 pad37[0x4C - 0x37];
  ExplodedObjectMapData *mapData;
  u8 pad50[0xAD - 0x50];
  s8 objectTypeTag;
  u8 padAE[0xB8 - 0xAE];
  ExplodedObjectState *state;
} ExplodedObject;

void cfforcefield_update(u8 *obj);
void FUN_801a3ac0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);
void FUN_801a3cc4(undefined2 *param_1,int param_2);
void FUN_801a3ee8(void);
void FUN_801a4290(undefined2 *param_1,int param_2);
void FUN_801a42e8(undefined4 param_1,undefined4 param_2,int param_3);
void FUN_801a44f8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void cfmagicwall_initialise(void);
int cflevelcontrol_getObjectTypeId(void);
void FUN_801a45d0(short *param_1,undefined4 *param_2);
void cflevelcontrol_free(int param_1);
void FUN_801a45f8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801a4620(undefined2 *param_1,int param_2);
void FUN_801a466c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801a4694(ushort *param_1);
undefined4
FUN_801a4810(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            undefined4 param_9,undefined4 param_10,int param_11);
void FUN_801a4924(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801a494c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_801a522c(int param_1);
void FUN_801a5230(undefined4 param_1,undefined4 param_2,int param_3,float *param_4);
void FUN_801a5420(undefined2 *param_1,int param_2,int param_3);

#endif /* MAIN_DLL_IM_IMICICLE_H_ */
