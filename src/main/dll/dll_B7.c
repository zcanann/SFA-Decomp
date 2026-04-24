#include "ghidra_import.h"
#include "main/dll/dll_B7.h"

extern double FUN_80247f54();
extern double FUN_80293900();

extern f32 FLOAT_803e22b0;
extern f32 FLOAT_803e22d8;

/*
 * --INFO--
 *
 * Function: camcontrol_updateMoveAverage
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80101844
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_updateMoveAverage(int param_1,int param_2)
{
  float fVar1;
  double dVar2;
  
  *(undefined4 *)(param_1 + 200) = *(undefined4 *)(param_1 + 0xcc);
  *(undefined4 *)(param_1 + 0xcc) = *(undefined4 *)(param_1 + 0xd0);
  *(undefined4 *)(param_1 + 0xd0) = *(undefined4 *)(param_1 + 0xd4);
  *(undefined4 *)(param_1 + 0xd4) = *(undefined4 *)(param_1 + 0xd8);
  dVar2 = FUN_80247f54((float *)(param_2 + 0x24));
  if ((double)FLOAT_803e22b0 < dVar2) {
    dVar2 = FUN_80293900(dVar2);
  }
  *(float *)(param_1 + 0xd8) = (float)dVar2;
  fVar1 = FLOAT_803e22b0;
  *(float *)(param_1 + 0xc4) = FLOAT_803e22b0;
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 200);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xcc);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xd0);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xd4);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xd8);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) * FLOAT_803e22d8;
  if (*(float *)(param_1 + 0xc4) < fVar1) {
    *(float *)(param_1 + 0xc4) = -*(float *)(param_1 + 0xc4);
  }
  return;
}
