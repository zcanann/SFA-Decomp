#include "ghidra_import.h"
#include "main/dll/boulder.h"

extern u32 randomGetRange(int min, int max);

extern f32 lbl_803E5ED8;

/*
 * --INFO--
 *
 * Function: fn_801F4ECC
 * EN v1.0 Address: 0x801F4ECC
 * EN v1.0 Size: 188b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void fn_801F4ECC(int param_1, u8 *param_2)
{
  *(f32 *)(param_2 + 0x04) = *(f32 *)(param_2 + 0x08);
  *(f32 *)(param_2 + 0x14) = *(f32 *)(param_2 + 0x18);
  *(f32 *)(param_2 + 0x24) = *(f32 *)(param_2 + 0x28);
  *(f32 *)(param_2 + 0x08) = *(f32 *)(param_2 + 0x0c);
  *(f32 *)(param_2 + 0x18) = *(f32 *)(param_2 + 0x1c);
  *(f32 *)(param_2 + 0x28) = *(f32 *)(param_2 + 0x2c);
  *(f32 *)(param_2 + 0x0c) = *(f32 *)(param_2 + 0x10);
  *(f32 *)(param_2 + 0x1c) = *(f32 *)(param_2 + 0x20);
  *(f32 *)(param_2 + 0x2c) = *(f32 *)(param_2 + 0x30);
  *(f32 *)(param_2 + 0x44) =
      lbl_803E5ED8 * (f32)(s32)randomGetRange(0xa0, 0xb4);
  *(f32 *)(param_2 + 0x10) = *(f32 *)(param_2 + 0x34);
  *(f32 *)(param_2 + 0x20) = *(f32 *)(param_2 + 0x38);
  *(f32 *)(param_2 + 0x30) = *(f32 *)(param_2 + 0x3c);
}
#pragma peephole reset
#pragma scheduling reset
