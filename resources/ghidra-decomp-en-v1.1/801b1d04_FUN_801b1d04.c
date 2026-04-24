// Function: FUN_801b1d04
// Entry: 801b1d04
// Size: 156 bytes

void FUN_801b1d04(undefined2 *param_1)

{
  uint uVar1;
  int iVar2;
  undefined *puVar3;
  
  iVar2 = *(int *)(param_1 + 0x26);
  puVar3 = *(undefined **)(param_1 + 0x5c);
  uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x1e));
  if (uVar1 == 0) {
    *puVar3 = 0;
  }
  else {
    *puVar3 = 2;
    *(float *)(param_1 + 0x4c) = FLOAT_803e5510;
  }
  *(undefined **)(param_1 + 0x5e) = &LAB_801b1b8c;
  *param_1 = (short)((int)*(char *)(iVar2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

