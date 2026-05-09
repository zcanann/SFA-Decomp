#include "ghidra_import.h"
#include "main/dll/dll_13E.h"

extern f32 timeDelta;
extern f32 lbl_803E369C;
extern f32 lbl_803E36A4;
extern f32 lbl_803E36A8;
extern f32 lbl_803E36AC;
extern u8 *lbl_803DCAA8;

extern u8 *Obj_GetPlayerObject(void);
extern u8 *getTrickyObject(void);
extern int GameBit_Get(int bit);
extern void Obj_FreeObject(u8 *obj);
extern u8 fn_80179A2C(u8 *obj);
extern int buttonGetDisabled(int unused);
extern int ObjTrigger_IsSet(u8 *obj);
extern void ObjHits_DisableObject(u8 *obj);
extern void fn_801793B8(u8 *obj, u8 *state);

/*
 * --INFO--
 *
 * Function: sidekickball_update
 * EN v1.0 Address: 0x801797A4
 * EN v1.0 Size: 648b
 */
void sidekickball_update(u8 *self)
{
  u8 *state;
  u8 *player;
  u8 *other;
  int gotHit;

  state = (u8 *)*(int *)(self + 0xB8);
  self[0xAF] = (u8)(self[0xAF] | 0x8);
  state[0x275] = 0;

  player = Obj_GetPlayerObject();
  other = getTrickyObject();
  if (player == NULL
      || (*(u16 *)(player + 0xB0) & 0x1000) != 0
      || other == NULL
      || (((u32)((*(u16 *)(other + 0xB0) == 0) ? 1U : 0U) | ((*(u16 *)(other + 0xB0) & 0x1000) != 0)) != 0)
      || GameBit_Get(0xD00) != 0) {
    Obj_FreeObject(self);
    return;
  }

  if (state[0x274] == 1 || state[0x274] == 2 || state[0x274] == 3) {
    *(f32 *)(state + 0x26C) = *(f32 *)(state + 0x26C) + timeDelta;
    if (*(f32 *)(state + 0x26C) > lbl_803E36A8) {
      *(f32 *)(state + 0x26C) = lbl_803E369C;
      state[0x274] = 5;
    }
  }

  switch ((s8)state[0x274]) {
  case 0:
    fn_801793B8(self, state);
    break;
  case 1:
    fn_80179A2C(self);
    /* fallthrough */
  case 2:
    self[0xAF] = (u8)(self[0xAF] & 0xF7);
    gotHit = 0;
    if ((buttonGetDisabled(0) & 0x100) == 0
        && *(int *)(self + 0xF8) == 0
        && ObjTrigger_IsSet(self) != 0) {
      ObjHits_DisableObject(self);
      gotHit = 1;
    }
    state[0x2C9] = (u8)gotHit;
    if (state[0x2C9] != 0) {
      state[0x2C8] = 0;
      state[0x2C9] = 0;
      state[0x274] = 0;
    }
    break;
  case 3:
    state[0x274] = fn_80179A2C(self);
    return;
  case 5:
    *(f32 *)(state + 0x26C) = *(f32 *)(state + 0x26C) + timeDelta;
    if (*(f32 *)(state + 0x26C) > lbl_803E36A4) {
      Obj_FreeObject(self);
      return;
    }
    {
      f32 v = lbl_803E36AC * *(f32 *)(state + 0x26C) / lbl_803E36A4;
      self[0x36] = (u8)(0xFF - (int)v);
    }
    break;
  default:
    break;
  }

  /* vtable calls at +0x10, +0x14, +0x18 */
  {
    u8 *vt = (u8 *)*(int *)lbl_803DCAA8;
    ((void (*)(u8 *, u8 *, f32))*(void **)(vt + 0x10))(self, state, timeDelta);
    ((void (*)(u8 *, u8 *))*(void **)(vt + 0x14))(self, state);
    ((void (*)(u8 *, u8 *, f32))*(void **)(vt + 0x18))(self, state, timeDelta);
  }
}
