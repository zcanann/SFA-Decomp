#include "ghidra_import.h"

extern f32 fn_80021704(void *posA,void *posB);
extern void GameBit_Set(int eventId,int value);
extern int GameBit_Get(int eventId);
extern void *Obj_GetPlayerObject(void);
extern void fn_8002CE88(void *obj);
extern void ObjHits_DisableObject(void *obj);
extern void ObjHits_EnableObject(void *obj);
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern void fn_8003B8F4(void *obj,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                        undefined4 param_5,double scale);
extern int fn_80210BE8(void);

extern s16 lbl_803DC228;
extern undefined4 *lbl_803DCAAC;
extern f32 lbl_803E6750;
extern f32 lbl_803E6754;
extern f32 lbl_803E6758;

typedef struct SpellStoneState {
  u8 state;
} SpellStoneState;

typedef struct SpellStoneDef {
  u8 unk0[0x19];
  s8 eventIndex;
  u8 unk1A[4];
  s16 completeEvent;
  s16 activeEvent;
} SpellStoneDef;

typedef struct SpellStoneObject {
  s16 rotX;
  s16 rotY;
  s16 rotZ;
  s16 flags;
  u8 unk8[4];
  f32 posX;
  f32 posY;
  f32 posZ;
  u8 unk18[0x34];
  SpellStoneDef *def;
  u8 unk50[0x68];
  SpellStoneState *state;
  int (*callback)(void);
  u8 unkC0[4];
  void *followTarget;
} SpellStoneObject;

#pragma peephole off
#pragma scheduling off

int spellstone_getState(SpellStoneObject *obj)
{
  return obj->state->state != 2;
}

int spellstone_setState(SpellStoneObject *obj,int state)
{
  SpellStoneState *extra;
  u8 oldState;

  extra = obj->state;
  oldState = extra->state;
  extra->state = (u8)state;
  if (state == 2) {
    obj->posY += lbl_803E6750;
  }
  return oldState != 1;
}

int spellstone_getExtraSize(void)
{
  return sizeof(SpellStoneState);
}

int spellstone_func08(void)
{
  return 0;
}

void spellstone_free(SpellStoneObject *obj)
{
  ObjGroup_RemoveObject(obj,0x1e);
  return;
}

void spellstone_render(SpellStoneObject *obj,undefined4 param_2,undefined4 param_3,
                       undefined4 param_4,undefined4 param_5,char visible)
{
  SpellStoneState *state;

  state = obj->state;
  if ((visible != 0) && (state->state != 0)) {
    fn_8003B8F4(obj,param_2,param_3,param_4,param_5,(double)lbl_803E6754);
  }
  return;
}

void spellstone_hitDetect(void)
{
  return;
}

void spellstone_update(SpellStoneObject *obj)
{
  u32 eventActive;
  void *playerObj;
  SpellStoneState *state;
  SpellStoneDef *def;

  state = obj->state;
  def = obj->def;
  if (state->state == 2) {
    obj->rotY = 0;
    obj->rotX += 0x100;
    obj->rotZ = 0;
  }
  eventActive = GameBit_Get(def->completeEvent);
  if (eventActive != 0) {
    GameBit_Set(*(&lbl_803DC228 + def->eventIndex),1);
    obj->flags = (s16)(obj->flags | 0x4000);
    fn_8002CE88(obj);
    (*(code *)(*lbl_803DCAAC + 0x44))(0x1d,2);
  }
  else {
    eventActive = GameBit_Get(def->activeEvent);
    if (eventActive != 0) {
      obj->flags = (s16)(obj->flags | 0x4000);
      fn_8002CE88(obj);
    }
    if (state->state == 2) {
      playerObj = Obj_GetPlayerObject();
      if (fn_80021704(&obj->unk18,(u8 *)playerObj + 0x18) < lbl_803E6758) {
        GameBit_Set(def->completeEvent,1);
      }
    }
    if (state->state == 0) {
      ObjHits_DisableObject(obj);
      if (obj->followTarget != NULL) {
        obj->posX = *(f32 *)((u8 *)obj->followTarget + 0xc);
        obj->posY = *(f32 *)((u8 *)obj->followTarget + 0x10);
        obj->posZ = *(f32 *)((u8 *)obj->followTarget + 0x14);
      }
    }
    else {
      ObjHits_EnableObject(obj);
    }
  }
  return;
}

void spellstone_init(SpellStoneObject *obj)
{
  SpellStoneState *state;

  state = obj->state;
  ObjGroup_AddObject(obj,0x1e);
  state->state = 1;
  obj->callback = fn_80210BE8;
  return;
}

void spellstone_release(void)
{
  return;
}

void spellstone_initialise(void)
{
  return;
}

#pragma peephole reset
#pragma scheduling reset
