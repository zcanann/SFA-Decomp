#ifndef MAIN_DLL_IM_IMICICLE_H_
#define MAIN_DLL_IM_IMICICLE_H_

#include "ghidra_import.h"

typedef struct ExplodedObjectMapData {
  u8 pad00[0x18];
  u8 objectTypeTag;
  u8 pad19;
  s16 initialAngleX;
  s16 initialAngleY;
  s16 initialAngleZ;
  s16 initialVelocityX;
  s16 initialVelocityY;
  s16 initialVelocityZ;
  s16 accelerationX;
  s16 accelerationY;
  s16 accelerationZ;
  s16 spinX;
  s16 spinY;
  s16 spinZ;
  s16 spinVelocityX;
  s16 spinVelocityY;
  s16 spinVelocityZ;
  s16 lifetimeFrames;
  s16 floorOffset;
  u8 pad3C;
  s8 scaleByte;
} ExplodedObjectMapData;

typedef struct ExplodedObjectState {
  u8 pad00[0x18];
  f32 spinX;
  f32 spinY;
  f32 spinZ;
  f32 spinVelocityX;
  f32 spinVelocityY;
  f32 spinVelocityZ;
  f32 accelerationX;
  f32 accelerationY;
  f32 accelerationZ;
  u8 pad3C[0x54 - 0x3C];
  f32 floorHeight;
  s32 elapsedFrames;
  s32 durationFrames;
  u8 pad60[0x66 - 0x60];
  u8 physicsFlags;
  u8 pad67[0x69 - 0x67];
  u8 explodePhase;
  u8 pad6A[0x6C - 0x6A];
} ExplodedObjectState;

typedef struct ExplodedObject {
  s16 angleX;
  s16 angleY;
  s16 angleZ;
  s16 flags06;
  f32 modelScale;
  f32 x;
  f32 y;
  f32 z;
  u8 pad18[0x24 - 0x18];
  f32 velocityX;
  f32 velocityY;
  f32 velocityZ;
  u8 pad30[0x36 - 0x30];
  u8 alpha;
  u8 pad37[0x4C - 0x37];
  ExplodedObjectMapData *mapData;
  void *modelData;
  u8 pad54[0xAD - 0x54];
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
