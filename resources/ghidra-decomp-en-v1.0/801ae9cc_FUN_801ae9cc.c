// Function: FUN_801ae9cc
// Entry: 801ae9cc
// Size: 196 bytes

void FUN_801ae9cc(short *param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x26);
  if (*(int *)(param_1 + 0x7a) == 0) {
    param_1[1] = param_1[1] + *(short *)(iVar1 + 0x1a) * (ushort)DAT_803db410;
  }
  else {
    *param_1 = *param_1 + *(short *)(iVar1 + 0x1a) * (ushort)DAT_803db410;
  }
  param_1[2] = param_1[2] + *(short *)(iVar1 + 0x1c) * (ushort)DAT_803db410;
  if (DAT_803ddb48 != 0) {
    *(undefined *)(param_1 + 0x1b) = *(undefined *)(DAT_803ddb48 + 0x36);
    FUN_8002b95c((double)(*(float *)(DAT_803ddb48 + 0xc) - *(float *)(param_1 + 6)),
                 (double)(*(float *)(DAT_803ddb48 + 0x10) - *(float *)(param_1 + 8)),
                 (double)(*(float *)(DAT_803ddb48 + 0x14) - *(float *)(param_1 + 10)));
  }
  return;
}

