#include "ghidra_import.h"

extern void *fn_8002B9EC(void);
extern void fn_8000BB18(void *obj,u16 volumeId);
extern int fn_8001FFB4(int eventId);
extern void fn_800200E8(int eventId,int value);
extern void fn_80035DF4(void *obj,int animObjId,int frame,int flags);
extern void fn_80035F00(void *obj);
extern void fn_80035F20(void *obj);
extern int fn_80080150(void *timer);
extern void fn_8008016C(void *timer);
extern void fn_80080178(void *timer,int duration);
extern int fn_800801A8(void *timer);

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

void crfueltank_hitDetect(CrFuelTankObject *obj)
{
  CrFuelTankDef *def;
  CrFuelTankHitObj *hitObj;

  def = obj->def;
  if ((obj->collider != NULL) && (obj->collider->hitObj != NULL)) {
    hitObj = obj->collider->hitObj;
    if (hitObj->objType == 0x38c) {
      fn_80035F00(obj);
      fn_8000BB18(fn_8002B9EC(),0xee);
      obj->fadeTimer = 0xfa;
      obj->triggered = 1;
      if (def->hitEvent != -1) {
        fn_800200E8(def->hitEvent,1);
      }
      obj->posX = hitObj->posX;
      obj->posY = lbl_803E6760 + hitObj->posY;
      obj->posZ = hitObj->posZ;
    }
  }
  return;
}

void crfueltank_update(CrFuelTankObject *obj)
{
  CrFuelTankDef *def;
  CrFuelTankState *state;

  def = obj->def;
  state = obj->state;
  if (fn_80080150(state->timer) != 0) {
    if (fn_800801A8(state->timer) != 0) {
      fn_80035F20(obj);
      obj->flags = (s16)(obj->flags & 0xbfff);
      obj->fadeTimer = 0xff;
    }
  }
  else {
    if (obj->fadeTimer < 0xff) {
      obj->flags = (s16)(obj->flags | 0x4000);
      fn_80080178(state->timer,0x708);
    }
    else {
      fn_80035DF4(obj,0x1d,crfueltank_animFrame(def),0);
    }
  }
  return;
}

void crfueltank_init(CrFuelTankObject *obj,CrFuelTankDef *def)
{
  CrFuelTankState *state;

  state = obj->state;
  fn_80035F20(obj);
  fn_80035DF4(obj,0x1d,crfueltank_animFrame(def),0);
  fn_8008016C(state->timer);
  if ((def->hitEvent != -1) && (fn_8001FFB4(def->hitEvent) != 0)) {
    fn_80080178(state->timer,0x708);
    fn_80035F00(obj);
    obj->flags = (s16)(obj->flags | 0x4000);
    obj->fadeTimer = 0;
  }
  return;
}

void crfueltank_release(void)
{
  return;
}

void crfueltank_initialise(void)
{
  return;
}
