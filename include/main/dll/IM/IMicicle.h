#ifndef MAIN_DLL_IM_IMICICLE_H_
#define MAIN_DLL_IM_IMICICLE_H_

#include "ghidra_import.h"
#include "main/objanim_internal.h"
#include "main/objanim_update.h"

typedef struct ExplodedObjectMapData {
  u8 pad00[0x08];
  f32 positionX;
  f32 positionY;
  f32 positionZ;
  u8 pad14[0x18 - 0x14];
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
  f32 localCenterX;
  f32 localCenterY;
  f32 localCenterZ;
  f32 initialLocalCenterX;
  f32 initialLocalCenterY;
  f32 initialLocalCenterZ;
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
  union {
    ObjAnimComponent anim;
    struct {
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
    };
  };
  ExplodedObjectState *state;
} ExplodedObject;

STATIC_ASSERT(offsetof(ExplodedObject, anim) == 0x00);
STATIC_ASSERT(offsetof(ExplodedObject, angleX) == offsetof(ObjAnimComponent, rotX));
STATIC_ASSERT(offsetof(ExplodedObject, modelScale) == offsetof(ObjAnimComponent, rootMotionScale));
STATIC_ASSERT(offsetof(ExplodedObject, x) == offsetof(ObjAnimComponent, localPosX));
STATIC_ASSERT(offsetof(ExplodedObject, velocityX) == offsetof(ObjAnimComponent, velocityX));
STATIC_ASSERT(offsetof(ExplodedObject, alpha) == offsetof(ObjAnimComponent, alpha));
STATIC_ASSERT(offsetof(ExplodedObject, mapData) == offsetof(ObjAnimComponent, placementData));
STATIC_ASSERT(offsetof(ExplodedObject, modelData) == offsetof(ObjAnimComponent, modelInstance));
STATIC_ASSERT(offsetof(ExplodedObject, objectTypeTag) == offsetof(ObjAnimComponent, bankIndex));
STATIC_ASSERT(offsetof(ExplodedObject, state) == 0xB8);

void cfforcefield_free(void);
void cfforcefield_render(void);
void cfforcefield_hitDetect(void);
int cfforcefield_getExtraSize(void);
int cfforcefield_getObjectTypeId(void);
void cfforcefield_update(u8 *obj);
void cfforcefield_init(s16 *obj, void *data);
void cfforcefield_release(void);
void cfforcefield_initialise(void);

int slidingdoor_SeqFn(u8 *obj, int unused, ObjAnimUpdateState *animUpdate);
int slidingdoor_getExtraSize(void);
int slidingdoor_getObjectTypeId(void);
void slidingdoor_free(void);
void slidingdoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void slidingdoor_hitDetect(void);
void slidingdoor_update(u8 *obj);
void slidingdoor_init(u8 *obj, u8 *data);
void slidingdoor_release(void);
void slidingdoor_initialise(void);

void attractor_func0B(u8 *obj, void **out);
int attractor_setScale(int *obj);
int attractor_getExtraSize(void);
int attractor_getObjectTypeId(void);
void attractor_free(int x);
void attractor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void attractor_hitDetect(void);
void attractor_update(void);
void attractor_init(s16 *obj, void *data);
void attractor_release(void);
void attractor_initialise(void);

int cfmagicwall_getExtraSize(void);
int cfmagicwall_getObjectTypeId(void);
void cfmagicwall_free(void);
void cfmagicwall_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void cfmagicwall_hitDetect(void);
void cfmagicwall_update(int obj);
void cfmagicwall_init(s16 *dst, void *src);
void cfmagicwall_release(void);
void cfmagicwall_initialise(void);

int CFLevelControl_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
int cflevelcontrol_getExtraSize(void);
int cflevelcontrol_getObjectTypeId(void);
void cflevelcontrol_free(int param_1);
void cflevelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void cflevelcontrol_hitDetect(void);
void cflevelcontrol_update(int obj);
void cflevelcontrol_init(u8 *obj, u8 *params);
void cflevelcontrol_release(void);
void cflevelcontrol_initialise(void);

void exploded_initDebrisState(ExplodedObject *obj, ExplodedObjectMapData *data,
                              int computeModelCenter, ExplodedObjectState *state);
void exploded_seedDebrisMotion(ExplodedObject *obj, ExplodedObjectState *state,
                               ExplodedObjectMapData *data);
u8 exploded_setScale(int *obj);
int exploded_getExtraSize(void);
u32 exploded_getObjectTypeId(ExplodedObject *obj);
void exploded_free(void);
void exploded_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void exploded_hitDetect(void);
int exploded_stepDebrisPhysics(ExplodedObject *obj, ExplodedObjectState *state);
void exploded_update(int *obj);
void exploded_init(ExplodedObject *obj, ExplodedObjectMapData *data, int extra);
void exploded_release(void);
void exploded_initialise(void);

/* Legacy Ghidra split helpers kept until their callers are restructured. */
void FUN_801a3ac0(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);
void FUN_801a3cc4(u16 *param_1,int param_2);
void FUN_801a3ee8(void);
void FUN_801a4290(u16 *param_1,int param_2);
void FUN_801a42e8(u32 param_1,u32 param_2,ObjAnimUpdateState *animUpdate);
void FUN_801a44f8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801a45d0(short *param_1,u32 *param_2);
void FUN_801a45f8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801a4620(u16 *param_1,int param_2);
void FUN_801a466c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801a4694(u16 *param_1);
u32
FUN_801a4810(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,
            u32 param_9,u32 param_10,ObjAnimUpdateState *animUpdate);
void FUN_801a4924(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801a494c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_801a522c(int param_1);
void FUN_801a5230(u32 param_1,u32 param_2,int param_3,float *param_4);
void FUN_801a5420(u16 *param_1,int param_2,int param_3);

#endif /* MAIN_DLL_IM_IMICICLE_H_ */
