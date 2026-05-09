#include "ghidra_import.h"

extern void Obj_SetActiveModelIndex(void *obj,int modelIndex);
extern void ObjHits_DisableObject(void *obj);
extern void ObjHits_EnableObject(void *obj);
extern void storeZeroToFloatParam(void *timer);
extern void s16toFloat(void *timer,int duration);

extern s32 lbl_803DC230;
extern f32 lbl_803E6774;
extern f64 lbl_803E6790;
extern f32 lbl_803E6798;
extern f32 lbl_803E679C;

typedef struct ProximityMineState {
  void *targetObj;
  void *effectHandle;
  f32 triggerDistance;
  f32 verticalStep;
  u8 unk10[4];
  u8 renderTimer[4];
  u8 launchTimer[4];
  u8 resetTimer[4];
  u8 bounceTimer[4];
  u8 initTimer[4];
  u8 lifespanTimer[4];
  s8 mode;
  u8 unk2D;
  u8 flashMode;
  u8 unk2F;
  u8 effectVisible;
  u8 unk31[3];
} ProximityMineState;

typedef struct ProximityMineObject {
  s16 angle;
  u8 unk2[6];
  f32 height;
  u8 unkC[0x3a];
  s16 objId;
  u8 unk48[0x70];
  ProximityMineState *state;
} ProximityMineObject;

typedef struct ProximityMineDef {
  u8 unk0[0x18];
  s8 angleSeed;
  s8 mode;
  s16 parameter;
} ProximityMineDef;

#pragma scheduling off
#pragma peephole off
void proximitymine_init(ProximityMineObject *obj,ProximityMineDef *def)
{
  s8 mode;
  ProximityMineState *state;

  state = obj->state;
  if (obj->objId == 0x789) {
    def->mode = 2;
  }
  obj->angle = 0;
  ObjHits_DisableObject(obj);
  state->mode = 0;
  storeZeroToFloatParam(state->renderTimer);
  storeZeroToFloatParam(state->resetTimer);
  storeZeroToFloatParam(state->bounceTimer);
  s16toFloat(state->bounceTimer,0x14);
  storeZeroToFloatParam(state->launchTimer);
  storeZeroToFloatParam(state->initTimer);
  s16toFloat(state->initTimer,5);
  obj->angle = def->angleSeed << 8;
  storeZeroToFloatParam(state->lifespanTimer);
  s16toFloat(state->lifespanTimer,(s16)lbl_803DC230);
  state->flashMode = 0;
  state->triggerDistance = lbl_803E6774;
  state->effectVisible = 0;
  mode = def->mode;
  switch (mode) {
  case 0:
    s16toFloat(state->resetTimer,def->parameter);
    state->mode = 2;
    Obj_SetActiveModelIndex(obj,1);
    obj->height *= lbl_803E6798;
    break;
  case 1:
    s16toFloat(state->launchTimer,800);
    s16toFloat(state->resetTimer,800);
    obj->angle = def->parameter;
    state->mode = -1;
    obj->height *= lbl_803E6798;
    break;
  case 2:
    storeZeroToFloatParam(state->lifespanTimer);
    state->mode = 3;
    ObjHits_EnableObject(obj);
    state->triggerDistance = (f32)(s32)def->parameter;
    storeZeroToFloatParam(state->bounceTimer);
    break;
  }
  state->verticalStep =
      (lbl_803E679C * obj->height) / (f32)lbl_803DC230;
  state->targetObj = NULL;
  state->effectHandle = NULL;
  return;
}
#pragma peephole reset
#pragma scheduling reset

void proximitymine_release(void)
{
  return;
}

void proximitymine_initialise(void)
{
  return;
}
