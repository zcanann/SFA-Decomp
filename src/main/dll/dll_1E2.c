#include "ghidra_import.h"
#include "main/dll/dll_1E2.h"

extern undefined4 FUN_800372f8();
extern undefined4 FUN_801d21ec();

extern f32 FLOAT_803e5f94;
extern f32 FLOAT_803e5fe8;

/*
 * --INFO--
 *
 * Function: FUN_801d2da8
 * EN v1.0 Address: 0x801D2C54
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x801D2DA8
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d2da8(undefined2 *param_1,int param_2,int param_3)
{
  float fVar1;
  int iVar2;
  float *pfVar3;
  
  fVar1 = FLOAT_803e5f94;
  pfVar3 = *(float **)(param_1 + 0x5c);
  *pfVar3 = FLOAT_803e5f94;
  pfVar3[0xb] = fVar1;
  pfVar3[3] = *(float *)(param_1 + 4);
  *(undefined2 *)(pfVar3 + 0xd) = *(undefined2 *)(param_2 + 0x1a);
  if (*(short *)(pfVar3 + 0xd) < 0x708) {
    *(undefined2 *)(pfVar3 + 0xd) = 0x708;
  }
  *(float *)(param_1 + 8) = *(float *)(param_2 + 0xc) - FLOAT_803e5fe8;
  iVar2 = *(int *)(param_1 + 0x32);
  if (iVar2 != 0) {
    *(uint *)(iVar2 + 0x30) = *(uint *)(iVar2 + 0x30) | 0x810;
  }
  if (param_3 == 0) {
    FUN_801d21ec(param_1,pfVar3,0);
  }
  FUN_800372f8((int)param_1,3);
  return;
}
