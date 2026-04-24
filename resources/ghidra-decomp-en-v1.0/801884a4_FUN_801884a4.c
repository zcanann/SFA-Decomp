// Function: FUN_801884a4
// Entry: 801884a4
// Size: 216 bytes

void FUN_801884a4(short *param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  *(undefined **)(param_1 + 0x5e) = &LAB_80188398;
  if (DAT_803219a0 == 0) {
    DAT_803219a0 = FUN_80054d54(0x268);
  }
  piVar2[2] = (int)&DAT_80321990;
  iVar1 = FUN_80019570(*(undefined2 *)(param_2 + 0x18));
  piVar2[1] = **(int **)(iVar1 + 8);
  piVar2[3] = 100;
  *piVar2 = iVar1;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1c) << 8;
  piVar2[6] = 2;
  *(undefined *)(piVar2 + 4) = *(undefined *)(param_2 + 0x1b);
  *(undefined2 *)((int)piVar2 + 0x16) = 0;
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

