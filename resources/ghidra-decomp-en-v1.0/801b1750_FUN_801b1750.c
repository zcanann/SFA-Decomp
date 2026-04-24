// Function: FUN_801b1750
// Entry: 801b1750
// Size: 156 bytes

void FUN_801b1750(undefined2 *param_1)

{
  int iVar1;
  int iVar2;
  undefined *puVar3;
  
  iVar2 = *(int *)(param_1 + 0x26);
  puVar3 = *(undefined **)(param_1 + 0x5c);
  iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x1e));
  if (iVar1 == 0) {
    *puVar3 = 0;
  }
  else {
    *puVar3 = 2;
    *(float *)(param_1 + 0x4c) = FLOAT_803e4878;
  }
  *(undefined **)(param_1 + 0x5e) = &LAB_801b15d8;
  *param_1 = (short)((int)*(char *)(iVar2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

