#include "ghidra_import.h"
#include "main/dll/dll_13E.h"

extern f32 timeDelta;
extern f32 lbl_803E369C;
extern f32 lbl_803E36A4;
extern f32 lbl_803E36A8;
extern f32 lbl_803E36AC;
extern u8 *gPathControlInterface;

extern int __cntlzw(unsigned int value);
extern u8 *Obj_GetPlayerObject(void);
extern u8 *getTrickyObject(void);
extern u32 GameBit_Get(int bit);
extern void Obj_FreeObject(u8 *obj);
extern u8 trickyBallMove(u8 *obj);
extern int buttonGetDisabled(int unused);
extern int ObjTrigger_IsSet(u8 *obj);
extern void ObjHits_DisableObject(u8 *obj);
extern void trickyBallFn_801793b8(u8 *obj, u8 *state);

enum SidekickBallMode {
  SIDEKICK_BALL_IDLE = 0,
  SIDEKICK_BALL_MOVING = 1,
  SIDEKICK_BALL_HELD = 2,
  SIDEKICK_BALL_THROWN = 3,
  SIDEKICK_BALL_FADING = 5,
};

#define SIDEKICK_BALL_TIMER 0x26C
#define SIDEKICK_BALL_MODE 0x274
#define SIDEKICK_BALL_ON_PATH_POINT 0x275
#define SIDEKICK_BALL_TRIGGER_ARMED 0x2C8
#define SIDEKICK_BALL_TRIGGER_HIT 0x2C9

/*
 * --INFO--
 *
 * Function: sidekickball_update
 * EN v1.0 Address: 0x801797A4
 * EN v1.0 Size: 648b
 */
#pragma scheduling off
#pragma peephole off
void sidekickball_update(u8 *self)
{
  u8 *state;
  u8 *player;
  u8 *other;
  int gotHit;

  state = (u8 *)*(int *)(self + 0xB8);
  self[0xAF] = (u8)(self[0xAF] | 0x8);
  state[SIDEKICK_BALL_ON_PATH_POINT] = 0;

  player = Obj_GetPlayerObject();
  other = getTrickyObject();
  if (player == NULL
      || (*(u16 *)(player + 0xB0) & 0x1000) != 0
      || other == NULL
      || (((u32)__cntlzw((u32)*(u16 *)(other + 0xB0)) >> 5 & 0x1000) != 0)
      || GameBit_Get(0xD00) != 0) {
    Obj_FreeObject(self);
    return;
  }

  if (state[SIDEKICK_BALL_MODE] == SIDEKICK_BALL_THROWN ||
      state[SIDEKICK_BALL_MODE] == SIDEKICK_BALL_HELD ||
      state[SIDEKICK_BALL_MODE] == SIDEKICK_BALL_MOVING) {
    *(f32 *)(state + SIDEKICK_BALL_TIMER) = *(f32 *)(state + SIDEKICK_BALL_TIMER) + timeDelta;
    if (*(f32 *)(state + SIDEKICK_BALL_TIMER) >= lbl_803E36A8) {
      *(f32 *)(state + SIDEKICK_BALL_TIMER) = lbl_803E369C;
      state[SIDEKICK_BALL_MODE] = SIDEKICK_BALL_FADING;
    }
  }

  switch (state[SIDEKICK_BALL_MODE]) {
  case SIDEKICK_BALL_THROWN:
    state[SIDEKICK_BALL_MODE] = trickyBallMove(self);
    return;
  case SIDEKICK_BALL_MOVING:
    trickyBallMove(self);
    /* fallthrough */
  case SIDEKICK_BALL_HELD:
    self[0xAF] = (u8)(self[0xAF] & ~0x8);
    gotHit = 0;
    if ((buttonGetDisabled(0) & 0x100) == 0
        && *(int *)(self + 0xF8) == 0
        && ObjTrigger_IsSet(self) != 0) {
      ObjHits_DisableObject(self);
      gotHit = 1;
    }
    state[SIDEKICK_BALL_TRIGGER_HIT] = (u8)gotHit;
    if (state[SIDEKICK_BALL_TRIGGER_HIT] != 0) {
      state[SIDEKICK_BALL_TRIGGER_ARMED] = 0;
      state[SIDEKICK_BALL_TRIGGER_HIT] = 0;
      state[SIDEKICK_BALL_MODE] = SIDEKICK_BALL_IDLE;
    }
    break;
  case SIDEKICK_BALL_FADING:
    *(f32 *)(state + SIDEKICK_BALL_TIMER) = *(f32 *)(state + SIDEKICK_BALL_TIMER) + timeDelta;
    if (*(f32 *)(state + SIDEKICK_BALL_TIMER) >= lbl_803E36A4) {
      Obj_FreeObject(self);
      return;
    }
    {
      f32 v = lbl_803E36AC * *(f32 *)(state + SIDEKICK_BALL_TIMER) / lbl_803E36A4;
      self[0x36] = (u8)(0xFF - (int)v);
    }
    break;
  case SIDEKICK_BALL_IDLE:
    trickyBallFn_801793b8(self, state);
    break;
  default:
    break;
  }

  /* vtable calls at +0x10, +0x14, +0x18 */
  {
    ((void (*)(u8 *, u8 *, f32))*(void **)(*(int *)gPathControlInterface + 0x10))(self, state, timeDelta);
    ((void (*)(u8 *, u8 *))*(void **)(*(int *)gPathControlInterface + 0x14))(self, state);
    ((void (*)(u8 *, u8 *, f32))*(void **)(*(int *)gPathControlInterface + 0x18))(self, state, timeDelta);
  }
}
#pragma peephole reset
#pragma scheduling reset
