#include "ghidra_import.h"
#include "main/dll/mmsh_waterspike.h"

extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E4D00;
extern f32 lbl_803E4D04;
extern f32 lbl_803E4D08;
extern f32 lbl_803E4D0C;
extern f32 lbl_803E4D10;

extern int cos16(s16 angle);

/*
 * --INFO--
 *
 * Function: fn_801BEEA0
 * EN v1.0 Address: 0x801BEEA0
 * EN v1.0 Size: 424b
 */
#pragma scheduling off
#pragma peephole off
void fn_801BEEA0(s16 *obj, u8 *state)
{
  u8 *motion;
  f32 heightDelta;
  s16 turnDelta;

  motion = (u8 *)*(int *)(state + 0x40C);
  heightDelta = *(f32 *)(motion + 0xC) - *(f32 *)((u8 *)obj + 0x10);

  *(s16 *)(motion + 0x14) = (s16)(*(s16 *)(motion + 0x14) + 0x400);
  heightDelta = heightDelta + (f32)(int)cos16(*(s16 *)(motion + 0x14)) / lbl_803E4D00;

  *(f32 *)(motion + 0x0) = timeDelta * (heightDelta / lbl_803E4D04 - *(f32 *)(motion + 0x8))
                       + *(f32 *)(motion + 0x0);

  *(f32 *)((u8 *)obj + 0x10) = *(f32 *)((u8 *)obj + 0x10) + *(f32 *)(motion + 0x0);

  {
    f32 pitch = lbl_803E4D08 * *(f32 *)(motion + 0x0);
    obj[1] = (s16)(int)pitch;
  }

  turnDelta = (s16)-(u16)obj[2];
  if (turnDelta > 0x8000) {
    turnDelta = (s16)((turnDelta - 0x10000) + 1);
  }
  if ((s16)turnDelta < (s16)-0x8000) {
    turnDelta = (s16)((turnDelta + 0x10000) - 1);
  }

  *(f32 *)(motion + 0x4) = *(f32 *)(motion + 0x4) + (f32)((int)((s16)turnDelta / 16) * (int)framesThisStep);

  obj[2] = (s16)(int)(*(f32 *)(motion + 0x4) + (f32)(int)obj[2]);

  *(f32 *)(motion + 0x0) = *(f32 *)(motion + 0x0) / lbl_803E4D0C;
  *(f32 *)(motion + 0x4) = *(f32 *)(motion + 0x4) / lbl_803E4D10;
}
#pragma peephole reset
#pragma scheduling reset
