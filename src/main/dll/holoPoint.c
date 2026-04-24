#include "ghidra_import.h"
#include "main/dll/holoPoint.h"

extern undefined4 FUN_8003b9ec();

extern f64 DOUBLE_803e4b90;
extern f32 FLOAT_803e4b80;
extern f32 FLOAT_803e4b84;
extern f32 FLOAT_803e4b88;

/*
 * --INFO--
 *
 * Function: FUN_80192000
 * EN v1.0 Address: 0x80191F54
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80192000
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192000(int param_1)
{
  FUN_8003b9ec(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019202c
 * EN v1.0 Address: 0x80191F74
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x8019202C
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019202c(short *param_1,int param_2)
{
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  if (*(byte *)(param_2 + 0x1b) != 0) {
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1b)) - DOUBLE_803e4b90) /
         FLOAT_803e4b84;
    if (*(float *)(param_1 + 4) == FLOAT_803e4b88) {
      *(float *)(param_1 + 4) = FLOAT_803e4b80;
    }
    *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  }
  param_1[0x58] = param_1[0x58] | 0xa000;
  return;
}
