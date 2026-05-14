#include "ghidra_import.h"
#include "main/dll/dll_145.h"

extern void ObjHitbox_SetSphereRadius(int obj, int radius);
extern int GameBit_Get(int bitId);

extern f32 lbl_803E3750;

/*
 * --INFO--
 *
 * Function: InvisibleHitSwitch_init
 * EN v1.0 Address: 0x8017AB20
 * EN v1.0 Size: 268b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void InvisibleHitSwitch_init(int param_1, u8 *param_2)
{
  u8 *info;

  info = (u8 *)*(int *)(param_1 + 0xb8);
  *(u16 *)(param_1 + 0xb0) = (u16)(*(u16 *)(param_1 + 0xb0) | 0x6000);
  if (param_2[0x1d] == 0) {
    *(f32 *)(param_1 + 0x8) = *(f32 *)(*(int *)(param_1 + 0x50) + 4);
  } else {
    {
      f32 v = (f32)(u32)param_2[0x1d] * *(f32 *)(*(int *)(param_1 + 0x50) + 4);
      *(f32 *)(param_1 + 0x8) = v * lbl_803E3750;
    }
  }
  ObjHitbox_SetSphereRadius(
      param_1,
      (s16)((param_2[0x1d] * (int)*(u8 *)(*(int *)(param_1 + 0x50) + 0x62)) / 64));
  info[0] = (u8)GameBit_Get(*(s16 *)(param_2 + 0x18));
  switch ((param_2[0x23] & 0xe) >> 1) {
  case 0:
  default:
    info[1] = 5;
    break;
  case 1:
    info[1] = 0x10;
    break;
  case 2:
    info[1] = 0x15;
    break;
  }
}
#pragma peephole reset
#pragma scheduling reset
