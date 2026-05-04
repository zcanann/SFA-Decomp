#include "ghidra_import.h"

extern void fn_8002B884(void *obj,int enabled);
extern void ObjHits_DisableObject(void *obj);
extern void ObjHits_EnableObject(void *obj);
extern void fn_8008016C(void *timer);
extern void fn_80080178(void *timer,int duration);

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
  fn_8008016C(state->renderTimer);
  fn_8008016C(state->resetTimer);
  fn_8008016C(state->bounceTimer);
  fn_80080178(state->bounceTimer,0x14);
  fn_8008016C(state->launchTimer);
  fn_8008016C(state->initTimer);
  fn_80080178(state->initTimer,5);
  obj->angle = def->angleSeed << 8;
  fn_8008016C(state->lifespanTimer);
  fn_80080178(state->lifespanTimer,(s16)lbl_803DC230);
  state->flashMode = 0;
  state->triggerDistance = lbl_803E6774;
  state->effectVisible = 0;
  mode = def->mode;
  switch (mode) {
  case 0:
    fn_80080178(state->resetTimer,def->parameter);
    state->mode = 2;
    fn_8002B884(obj,1);
    obj->height *= lbl_803E6798;
    break;
  case 1:
    fn_80080178(state->launchTimer,800);
    fn_80080178(state->resetTimer,800);
    obj->angle = def->parameter;
    state->mode = -1;
    obj->height *= lbl_803E6798;
    break;
  case 2:
    fn_8008016C(state->lifespanTimer);
    state->mode = 3;
    ObjHits_EnableObject(obj);
    state->triggerDistance = (f32)(s32)def->parameter;
    fn_8008016C(state->bounceTimer);
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
