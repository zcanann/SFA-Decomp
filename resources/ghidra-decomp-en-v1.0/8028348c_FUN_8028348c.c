// Function: FUN_8028348c
// Entry: 8028348c
// Size: 432 bytes

void FUN_8028348c(int param_1,uint *param_2,byte param_3)

{
  uint uVar1;
  int iVar2;
  
  if (param_3 == 0) {
    iVar2 = param_1 * 0xf4;
    *(undefined *)(DAT_803de344 + iVar2 + 0xa4) = 0;
    *(uint *)(DAT_803de344 + iVar2 + 0xb8) = (uint)*(ushort *)param_2;
    *(uint *)(DAT_803de344 + iVar2 + 0xbc) = (uint)*(ushort *)((int)param_2 + 2);
    uVar1 = (uint)*(ushort *)(param_2 + 1) << 3;
    if (0x7fff < uVar1) {
      uVar1 = 0x7fff;
    }
    *(short *)(DAT_803de344 + iVar2 + 0xc0) = (short)uVar1;
    *(uint *)(DAT_803de344 + iVar2 + 0xc4) = (uint)*(ushort *)((int)param_2 + 6);
  }
  else if (param_3 < 3) {
    iVar2 = param_1 * 0xf4;
    *(undefined *)(DAT_803de344 + iVar2 + 0xa4) = 1;
    *(undefined *)(DAT_803de344 + iVar2 + 0xca) = 0;
    if (param_3 == 1) {
      uVar1 = FUN_8027a60c(*param_2);
      *(uint *)(DAT_803de344 + iVar2 + 0xb8) = uVar1 & 0xffff;
      uVar1 = FUN_8027a60c(param_2[1]);
      *(uint *)(DAT_803de344 + iVar2 + 0xbc) = uVar1 & 0xffff;
      uVar1 = (int)(uint)*(ushort *)(param_2 + 2) >> 2;
      if (0x3ff < uVar1) {
        uVar1 = 0x3ff;
      }
      *(ushort *)(DAT_803de344 + iVar2 + 0xc0) = 0xc1 - (ushort)(byte)(&DAT_8032f79c)[uVar1];
    }
    else {
      *(uint *)(DAT_803de344 + iVar2 + 0xb8) = *param_2 & 0xffff;
      *(uint *)(DAT_803de344 + iVar2 + 0xbc) = param_2[1] & 0xffff;
      *(ushort *)(DAT_803de344 + iVar2 + 0xc0) = *(ushort *)(param_2 + 2);
    }
    *(uint *)(DAT_803de344 + iVar2 + 0xc4) = (uint)*(ushort *)((int)param_2 + 10);
  }
  iVar2 = DAT_803de344 + param_1 * 0xf4;
  *(uint *)(iVar2 + 0x24) = *(uint *)(iVar2 + 0x24) | 0x10;
  return;
}

