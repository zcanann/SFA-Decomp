#include "ghidra_import.h"
#include "main/dll/dll_18E.h"

extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E4D00;
extern f32 lbl_803E4D04;
extern f32 lbl_803E4D08;
extern f32 lbl_803E4D0C;
extern f32 lbl_803E4D10;

extern int fn_80021754(s16 angle);

/*
 * --INFO--
 *
 * Function: fn_801BEEA0
 * EN v1.0 Address: 0x801BEEA0
 * EN v1.0 Size: 424b
 */
void fn_801BEEA0(s16 *out, u8 *arg2)
{
  u8 *st;
  f32 dt;
  s16 angle;

  st = (u8 *)*(int *)(arg2 + 0x40C);
  dt = *(f32 *)(st + 0xC) - *(f32 *)((u8 *)out + 0x10);

  *(s16 *)(st + 0x14) = (s16)(*(s16 *)(st + 0x14) + 0x400);
  dt = dt + (f32)(int)fn_80021754(*(s16 *)(st + 0x14)) / lbl_803E4D00;

  *(f32 *)(st + 0x0) = timeDelta * (dt / lbl_803E4D04 - *(f32 *)(st + 0x8))
                       + *(f32 *)(st + 0x0);

  *(f32 *)((u8 *)out + 0x10) = *(f32 *)((u8 *)out + 0x10) + *(f32 *)(st + 0x0);

  {
    f32 v = lbl_803E4D08 * *(f32 *)(st + 0x0);
    out[1] = (s16)(int)v;
  }

  angle = (s16)-(s16)out[2];
  if (angle > 0x8000) {
    angle = (s16)((angle - 0x10000) + 1);
  }
  if ((s16)angle < (s16)-0x8000) {
    angle = (s16)((angle + 0x10000) - 1);
  }

  *(f32 *)(st + 0x4) = *(f32 *)(st + 0x4) + (f32)((int)((s16)angle >> 4) * (int)framesThisStep);

  out[2] = (s16)(int)(*(f32 *)(st + 0x4) + (f32)(int)out[2]);

  *(f32 *)(st + 0x0) = *(f32 *)(st + 0x0) / lbl_803E4D0C;
  *(f32 *)(st + 0x4) = *(f32 *)(st + 0x4) / lbl_803E4D10;
}
