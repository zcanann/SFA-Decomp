#include "ghidra_import.h"
#include "main/dll/dll_B8.h"

extern void *Camera_GetCurrentViewSlot(void);
extern float Camera_GetFovY(void);
extern f32 lbl_803E162C;
extern u8 *pCamera;

#pragma scheduling off
#pragma peephole off
void fn_801018A8(byte param_1, byte param_2)
{
  void *vs;

  float fov_const;

  Camera_GetCurrentViewSlot();
  fov_const = lbl_803E162C;
  *(float *)(pCamera + 0xf4) = fov_const;
  *(float *)(pCamera + 0xf8) = fov_const / (float)param_1;
  pCamera[0x13f] = param_2;

  vs = Camera_GetCurrentViewSlot();
  *(float *)(pCamera + 0x10c) = *(float *)((int)vs + 0xc);
  *(float *)(pCamera + 0x110) = *(float *)((int)vs + 0x10);
  *(float *)(pCamera + 0x114) = *(float *)((int)vs + 0x14);
  *(short *)(pCamera + 0x106) = *(short *)((int)vs + 0);
  *(short *)(pCamera + 0x108) = *(short *)((int)vs + 2);
  *(short *)(pCamera + 0x10a) = *(short *)((int)vs + 4);

  *(float *)(pCamera + 0x118) = Camera_GetFovY();
}
#pragma peephole reset
#pragma scheduling reset

void fn_80101974(u8 v) { pCamera[0x139] = v; }
