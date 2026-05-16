#include "ghidra_import.h"
#include "main/proximitymine.h"

extern void fn_8001CB3C(void *handle);
extern int ObjHits_GetPriorityHit(void *obj,int param_2,int param_3,int param_4);
extern void objRenderFn_8003b8f4(void *obj,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                        undefined4 param_5,double scale);
extern int objPosToMapBlockIdx(double x,double y,double z);
extern void queueGlowRender(void *effect);
extern int fn_80080150(void *timer);
extern void storeZeroToFloatParam(void *timer);
extern void s16toFloat(void *timer,int duration);

extern f32 lbl_803E6768;
extern f32 lbl_803E6778;

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

#pragma scheduling off
#pragma peephole off
void proximitymine_render(ProximityMineObject *obj,undefined4 param_2,undefined4 param_3,
                          undefined4 param_4,undefined4 param_5)
{
  int mapBlock;
  ProximityMineEffect *effect;
  ProximityMineState *state;

  state = obj->state;
  if (obj->pendingTarget != NULL) {
    state->targetObj = obj->pendingTarget;
    obj->pendingTarget = NULL;
  }
  if (fn_80080150(state->renderTimer) == 0) {
    mapBlock = objPosToMapBlockIdx((double)obj->posX,(double)obj->posY,(double)obj->posZ);
    if (mapBlock != -1) {
      effect = state->effectHandle;
      if ((effect != NULL) && (effect->active != 0) && (effect->visible != 0)) {
        queueGlowRender(effect);
      }
      objRenderFn_8003b8f4(obj,param_2,param_3,param_4,param_5,(double)lbl_803E6778);
    }
  }
  return;
}

#pragma peephole off
void proximitymine_hitDetect(ProximityMineObject *obj)
{
  f32 zeroVelocity;
  int hit;
  int hitFlag;
  ProximityMineCollider *collider;
  ProximityMineState *state;

  if (fn_80080150(obj->state->renderTimer) == 0) {
    hit = ObjHits_GetPriorityHit(obj,0,0,0);
    collider = obj->collider;
    hitFlag = collider->hitFlag;
    if ((hitFlag != 0) || (hit != 0) || (collider->hitObj != NULL)) {
      state = obj->state;
      zeroVelocity = lbl_803E6768;
      obj->velocityY = zeroVelocity;
      obj->velocityX = zeroVelocity;
      obj->velocityZ = zeroVelocity;
      state->mode = 0;
      storeZeroToFloatParam(state->resetTimer);
      s16toFloat(state->resetTimer,1);
      s16toFloat(state->renderTimer,10);
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset
