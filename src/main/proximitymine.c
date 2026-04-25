#include "ghidra_import.h"

extern void fn_8001CB3C(void *handle);
extern int fn_8003687C(void *obj,int param_2,int param_3,int param_4);
extern void fn_8003B8F4();
extern int fn_8005B2FC(double x,double y,double z);
extern void fn_800604B4(void *effect);
extern int fn_80080150(void *timer);
extern void fn_8008016C(void *timer);
extern void fn_80080178(void *timer,int duration);

extern f32 lbl_803E6768;
extern f32 lbl_803E6778;

typedef struct ProximityMineState {
  void *targetObj;
  void *effectHandle;
  f32 float8;
  f32 velocityY;
  u8 unk10[4];
  u8 renderTimer[4];
  u8 unk18[4];
  u8 resetTimer[4];
  u8 unk20[0xc];
  u8 mode;
  u8 unk2D[7];
} ProximityMineState;

typedef struct ProximityMineCollider {
  u8 unk0[0x50];
  void *hitObj;
  u8 unk54[0x59];
  s8 hitFlag;
} ProximityMineCollider;

typedef struct ProximityMineObject {
  u8 unk0[0xc];
  f32 posX;
  f32 posY;
  f32 posZ;
  u8 unk18[0xc];
  f32 velocityX;
  f32 velocityY;
  f32 velocityZ;
  u8 unk30[0x24];
  ProximityMineCollider *collider;
  u8 unk58[0x60];
  ProximityMineState *state;
  u8 unkBC[8];
  void *pendingTarget;
} ProximityMineObject;

int proximitymine_getExtraSize(void)
{
  return sizeof(ProximityMineState);
}

int proximitymine_func08(void)
{
  return 0;
}

void proximitymine_free(ProximityMineObject *obj)
{
  ProximityMineState *state;

  state = obj->state;
  if (state->effectHandle != NULL) {
    fn_8001CB3C(&state->effectHandle);
  }
  return;
}

void proximitymine_render(ProximityMineObject *obj,undefined4 param_2,undefined4 param_3,
                          undefined4 param_4,undefined4 param_5)
{
  int sector;
  void *effect;
  ProximityMineState *state;

  state = obj->state;
  if (obj->pendingTarget != NULL) {
    state->targetObj = obj->pendingTarget;
    obj->pendingTarget = NULL;
  }
  if (fn_80080150(state->renderTimer) == 0) {
    sector = fn_8005B2FC((double)obj->posX,(double)obj->posY,(double)obj->posZ);
    if (sector != -1) {
      effect = state->effectHandle;
      if ((effect != NULL) && (*(u8 *)((u8 *)effect + 0x2f8) != 0) &&
          (*(u8 *)((u8 *)effect + 0x4c) != 0)) {
        fn_800604B4(effect);
      }
      fn_8003B8F4((double)lbl_803E6778,obj,param_2,param_3,param_4,param_5);
    }
  }
  return;
}

void proximitymine_hitDetect(ProximityMineObject *obj)
{
  f32 zeroVelocity;
  int hit;
  ProximityMineCollider *collider;
  ProximityMineState *state;

  if (fn_80080150(obj->state->renderTimer) == 0) {
    hit = fn_8003687C(obj,0,0,0);
    collider = obj->collider;
    if ((collider->hitFlag != 0) || (hit != 0) || (collider->hitObj != NULL)) {
      state = obj->state;
      zeroVelocity = lbl_803E6768;
      obj->velocityY = zeroVelocity;
      obj->velocityX = zeroVelocity;
      obj->velocityZ = zeroVelocity;
      state->mode = 0;
      fn_8008016C(state->resetTimer);
      fn_80080178(state->resetTimer,1);
      fn_80080178(state->renderTimer,10);
    }
  }
  return;
}
