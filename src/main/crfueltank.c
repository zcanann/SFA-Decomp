#include "ghidra_import.h"
#include "main/crfueltank.h"

extern void *Obj_GetPlayerObject(void);
extern void Sfx_PlayFromObject(void *obj,u16 volumeId);
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern void ObjHits_SetHitVolumeSlot(void *obj,int animObjId,int frame,int flags);
extern void ObjHits_DisableObject(void *obj);
extern void ObjHits_EnableObject(void *obj);
extern int fn_80080150(void *timer);
extern void storeZeroToFloatParam(void *timer);
extern void s16toFloat(void *timer,int duration);
extern int timerCountDown(void *timer);

extern f32 lbl_803E6760;

static inline int crfueltank_animFrame(CrFuelTankDef *def)
{
  return def->idleFrameCount / 10;
}

int crfueltank_getExtraSize(void)
{
  return sizeof(CrFuelTankState);
}

int crfueltank_func08(void)
{
  return 0;
}

void crfueltank_free(void)
{
  return;
}

void crfueltank_render(void)
{
  return;
}

#pragma scheduling off
#pragma peephole off
void crfueltank_hitDetect(CrFuelTankObject *obj)
{
  CrFuelTankDef *def;
  CrFuelTankCollider *collider;
  CrFuelTankHitObj *hitObj;

  collider = obj->collider;
  def = obj->def;
  if ((collider != NULL) && (collider->hitObj != NULL)) {
    hitObj = collider->hitObj;
    if (hitObj->objType == 0x38c) {
      ObjHits_DisableObject(obj);
      Sfx_PlayFromObject(Obj_GetPlayerObject(),0xee);
      obj->fadeTimer = 0xfa;
      obj->triggered = 1;
      if (def->hitEvent != -1) {
        GameBit_Set(def->hitEvent,1);
      }
      obj->posX = hitObj->posX;
      obj->posY = lbl_803E6760 + hitObj->posY;
      obj->posZ = hitObj->posZ;
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void crfueltank_update(CrFuelTankObject *obj)
{
  CrFuelTankDef *def;
  CrFuelTankState *state;

  def = obj->def;
  state = obj->state;
  if (fn_80080150(state->timer) != 0) {
    if (timerCountDown(state->timer) != 0) {
      ObjHits_EnableObject(obj);
      obj->flags = (s16)(obj->flags & ~0x4000);
      obj->fadeTimer = 0xff;
    }
  }
  else {
    if (obj->fadeTimer < 0xff) {
      obj->flags = (s16)(obj->flags | 0x4000);
      s16toFloat(state->timer,0x708);
    }
    else {
      ObjHits_SetHitVolumeSlot(obj,0x1d,crfueltank_animFrame(def),0);
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void crfueltank_init(CrFuelTankObject *obj,CrFuelTankDef *def)
{
  CrFuelTankState *state;

  state = obj->state;
  ObjHits_EnableObject(obj);
  ObjHits_SetHitVolumeSlot(obj,0x1d,crfueltank_animFrame(def),0);
  storeZeroToFloatParam(state->timer);
  if ((def->hitEvent != -1) && (GameBit_Get(def->hitEvent) != 0)) {
    s16toFloat(state->timer,0x708);
    ObjHits_DisableObject(obj);
    obj->flags = (s16)(obj->flags | 0x4000);
    obj->fadeTimer = 0;
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

void crfueltank_release(void)
{
  return;
}

void crfueltank_initialise(void)
{
  return;
}

ObjectDescriptor gCrFuelTankObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)crfueltank_initialise,
    (ObjectDescriptorCallback)crfueltank_release,
    0,
    (ObjectDescriptorCallback)crfueltank_init,
    (ObjectDescriptorCallback)crfueltank_update,
    (ObjectDescriptorCallback)crfueltank_hitDetect,
    (ObjectDescriptorCallback)crfueltank_render,
    (ObjectDescriptorCallback)crfueltank_free,
    (ObjectDescriptorCallback)crfueltank_func08,
    crfueltank_getExtraSize,
};
