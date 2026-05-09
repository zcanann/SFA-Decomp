#include "ghidra_import.h"

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

typedef struct CrFuelTankState {
  u8 unk0[0xc];
  u8 timer[4];
} CrFuelTankState;

typedef struct CrFuelTankDef {
  u8 unk0[0x1a];
  s16 idleFrameCount;
  u8 unk1C[2];
  s16 hitEvent;
} CrFuelTankDef;

typedef struct CrFuelTankCollider {
  u8 unk0[0x50];
  void *hitObj;
} CrFuelTankCollider;

typedef struct CrFuelTankHitObj {
  u8 unk0[0x24];
  f32 posX;
  f32 posY;
  f32 posZ;
  u8 unk30[0x16];
  s16 objType;
} CrFuelTankHitObj;

typedef struct CrFuelTankObject {
  u8 unk0[6];
  s16 flags;
  u8 unk8[0x1c];
  f32 posX;
  f32 posY;
  f32 posZ;
  u8 unk30[6];
  u8 fadeTimer;
  u8 unk37[0x15];
  CrFuelTankDef *def;
  u8 unk50[4];
  CrFuelTankCollider *collider;
  u8 unk58[0x60];
  CrFuelTankState *state;
  u8 unkBC[0x3c];
  int triggered;
} CrFuelTankObject;

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
