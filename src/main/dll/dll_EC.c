#include "ghidra_import.h"
#include "main/dll/dll_EC.h"

extern void *Obj_GetPlayerObject(void);
extern int randomGetRange(int min,int max);
extern void fn_802960E4(int obj, f32 xVelocity, f32 zVelocity);

extern f32 lbl_803E6438;
extern f32 lbl_803E644C;

typedef struct TrickyCurveObject {
  u8 pad0[0xc];
  f32 x;
  f32 y;
  f32 z;
  u8 pad18[0xa0];
  struct TrickyCurveState *state;
} TrickyCurveObject;

typedef struct TrickyCurveState {
  s16 halfWidthX;
  s16 halfWidthZ;
  s16 halfHeightY;
} TrickyCurveState;

/*
 * --INFO--
 *
 * Function: TrickyCurve_updateCooldownTrigger
 * EN v1.0 Address: 0x80206F30
 * EN v1.0 Size: 604b
 * EN v1.1 Address: 0x80206FA0
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void TrickyCurve_updateCooldownTrigger(int obj)
{
  TrickyCurveObject *curve;
  TrickyCurveState *state;
  TrickyCurveObject *player;
  int axisCount;
  f32 deltaX;
  f32 deltaY;
  f32 deltaZ;
  f32 bound;
  f32 randomX;
  f32 randomZ;

  curve = (TrickyCurveObject *)obj;
  state = curve->state;
  player = (TrickyCurveObject *)Obj_GetPlayerObject();
  axisCount = 0;
  deltaX = player->x - curve->x;
  deltaY = player->y - curve->y;
  deltaZ = player->z - curve->z;

  if (deltaX <= lbl_803E6438) {
    bound = (f32)state->halfWidthX;
    if (-bound < deltaX) {
      axisCount = 1;
    }
  }
  if (lbl_803E6438 < deltaX) {
    bound = (f32)state->halfWidthX;
    if (deltaX < bound) {
      axisCount = axisCount + 1;
    }
  }

  if (deltaZ <= lbl_803E6438) {
    bound = (f32)state->halfWidthZ;
    if (-bound < deltaZ) {
      axisCount = axisCount + 1;
    }
  }
  if (lbl_803E6438 < deltaZ) {
    bound = (f32)state->halfWidthZ;
    if (deltaZ < bound) {
      axisCount = axisCount + 1;
    }
  }

  if (deltaY <= lbl_803E6438) {
    bound = (f32)state->halfHeightY;
    if (-bound < deltaY) {
      axisCount = axisCount + 1;
    }
  }
  if (lbl_803E6438 < deltaY) {
    bound = (f32)state->halfHeightY;
    if (deltaY < bound) {
      axisCount = axisCount + 1;
    }
  }

  if ((u8)axisCount == 3) {
    randomX = lbl_803E644C * (f32)randomGetRange(-0x17, 0x17);
    randomZ = lbl_803E644C * (f32)randomGetRange(-0x17, 0x17);
    fn_802960E4((int)player, randomX, randomZ);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset
