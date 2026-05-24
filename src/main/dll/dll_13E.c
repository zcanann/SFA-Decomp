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

typedef struct SidekickBallState {
  u8 unk0[0x26C];
  f32 timer;
  u8 unk270[4];
  u8 mode;
  u8 onPathPoint;
  u8 unk276[0x52];
  u8 triggerArmed;
  u8 triggerHit;
} SidekickBallState;

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
  SidekickBallState *state;
  u8 *player;
  u8 *other;
  u32 otherStatusZeroWord;
  u32 otherStatusMask;
  int gotHit;

  state = (SidekickBallState *)*(int *)(self + 0xB8);
  self[0xAF] = (u8)(self[0xAF] | 0x8);
  state->onPathPoint = 0;

  player = Obj_GetPlayerObject();
  other = getTrickyObject();
  if (player == NULL
      || (*(u16 *)(player + 0xB0) & 0x1000) != 0
      || other == NULL
      || (otherStatusZeroWord = (u32)__cntlzw((u32)*(u16 *)(other + 0xB0)),
          otherStatusMask = otherStatusZeroWord >> 5,
          (otherStatusMask & 0x1000) != 0)
      || GameBit_Get(0xD00) != 0) {
    Obj_FreeObject(self);
    return;
  }

  if (state->mode == SIDEKICK_BALL_THROWN ||
      state->mode == SIDEKICK_BALL_HELD ||
      state->mode == SIDEKICK_BALL_MOVING) {
    state->timer = state->timer + timeDelta;
    if (state->timer >= lbl_803E36A8) {
      state->timer = lbl_803E369C;
      state->mode = SIDEKICK_BALL_FADING;
    }
  }

  switch (state->mode) {
  case SIDEKICK_BALL_THROWN:
    state->mode = trickyBallMove(self);
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
    state->triggerHit = (u8)gotHit;
    if (state->triggerHit != 0) {
      state->triggerArmed = 0;
      state->triggerHit = 0;
      state->mode = SIDEKICK_BALL_IDLE;
    }
    break;
  case SIDEKICK_BALL_FADING:
    state->timer = state->timer + timeDelta;
    if (state->timer >= lbl_803E36A4) {
      Obj_FreeObject(self);
      return;
    }
    {
      f32 v = lbl_803E36AC * state->timer / lbl_803E36A4;
      self[0x36] = (u8)(0xFF - (int)v);
    }
    break;
  case SIDEKICK_BALL_IDLE:
    trickyBallFn_801793b8(self, (u8 *)state);
    break;
  default:
    break;
  }

  /* vtable calls at +0x10, +0x14, +0x18 */
  {
    ((void (*)(u8 *, u8 *, f32))*(void **)(*(int *)gPathControlInterface + 0x10))(self, (u8 *)state, timeDelta);
    ((void (*)(u8 *, u8 *))*(void **)(*(int *)gPathControlInterface + 0x14))(self, (u8 *)state);
    ((void (*)(u8 *, u8 *, f32))*(void **)(*(int *)gPathControlInterface + 0x18))(self, (u8 *)state, timeDelta);
  }
}
#pragma peephole reset
#pragma scheduling reset
