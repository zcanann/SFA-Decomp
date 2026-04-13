// Function: FUN_801aef80
// Entry: 801aef80
// Size: 196 bytes

void FUN_801aef80(short *param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x26);
  if (*(int *)(param_1 + 0x7a) == 0) {
    param_1[1] = param_1[1] + *(short *)(iVar1 + 0x1a) * (ushort)DAT_803dc070;
  }
  else {
    *param_1 = *param_1 + *(short *)(iVar1 + 0x1a) * (ushort)DAT_803dc070;
  }
  param_1[2] = param_1[2] + *(short *)(iVar1 + 0x1c) * (ushort)DAT_803dc070;
  if (DAT_803de7c8 != 0) {
    *(undefined *)(param_1 + 0x1b) = *(undefined *)(DAT_803de7c8 + 0x36);
    FUN_8002ba34((double)(*(float *)(DAT_803de7c8 + 0xc) - *(float *)(param_1 + 6)),
                 (double)(*(float *)(DAT_803de7c8 + 0x10) - *(float *)(param_1 + 8)),
                 (double)(*(float *)(DAT_803de7c8 + 0x14) - *(float *)(param_1 + 10)),(int)param_1);
  }
  return;
}

