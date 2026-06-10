#include "main/dll/sidekickball.h"
#include "main/game_object.h"
#include "main/dll/path_control_interface.h"

extern f32 timeDelta;
extern f32 lbl_803E369C;
extern f32 lbl_803E36A4;
extern f32 lbl_803E36A8;
extern f32 lbl_803E36AC;

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

#include "main/dll/sidekickball_state.h"

/*
 * --INFO--
 *
 * Function: sidekickball_update
 * EN v1.0 Address: 0x801797A4
 * EN v1.0 Size: 648b
 */
void sidekickball_update(u8 *self)
{
  SidekickBallState *state;
  u8 *player;
  u8 *other;
  u32 otherStatusZeroWord;
  int otherStatusMask;
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

  if (state->ballMode == SIDEKICK_BALL_THROWN ||
      state->ballMode == SIDEKICK_BALL_HELD ||
      state->ballMode == SIDEKICK_BALL_MOVING) {
    state->fadeTimer = state->fadeTimer + timeDelta;
    if (state->fadeTimer >= lbl_803E36A8) {
      state->fadeTimer = lbl_803E369C;
      state->ballMode = SIDEKICK_BALL_FADING;
    }
  }

  switch (state->ballMode) {
  case SIDEKICK_BALL_THROWN:
    state->ballMode = trickyBallMove(self);
    return;
  case SIDEKICK_BALL_MOVING:
    trickyBallMove(self);
    /* fallthrough */
  case SIDEKICK_BALL_HELD:
    self[0xAF] = (u8)(self[0xAF] & ~0x8);
    gotHit = 0;
    if ((buttonGetDisabled(0) & 0x100) == 0u
        && *(int *)(self + 0xF8) == 0
        && ObjTrigger_IsSet(self) != 0) {
      ObjHits_DisableObject(self);
      gotHit = 1;
    }
    state->triggerHit = (u8)gotHit;
    if (state->triggerHit != 0) {
      state->triggerArmed = 0;
      state->triggerHit = 0;
      state->ballMode = SIDEKICK_BALL_IDLE;
    }
    break;
  case SIDEKICK_BALL_FADING:
    state->fadeTimer = state->fadeTimer + timeDelta;
    if (state->fadeTimer >= *(f32 *)&lbl_803E36A4) {
      Obj_FreeObject(self);
      return;
    }
    {
      f32 v = lbl_803E36AC * state->fadeTimer / lbl_803E36A4;
      ((GameObject *)self)->anim.alpha = (u8)(0xFF - (int)v);
    }
    break;
  case SIDEKICK_BALL_IDLE:
    trickyBallFn_801793b8(self, (u8 *)state);
    break;
  default:
    break;
  }

  (*gPathControlInterface)->update(self, state, timeDelta);
  (*gPathControlInterface)->apply(self, state);
  (*gPathControlInterface)->advance(self, state, timeDelta);
}
