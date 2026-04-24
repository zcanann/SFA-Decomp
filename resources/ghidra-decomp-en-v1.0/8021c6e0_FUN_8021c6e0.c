// Function: FUN_8021c6e0
// Entry: 8021c6e0
// Size: 348 bytes

void FUN_8021c6e0(int param_1)

{
  uint uVar1;
  char in_r8;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e6a48);
    *(ushort *)(iVar2 + 0x176) = *(short *)(iVar2 + 0x176) + (ushort)DAT_803db410;
    if ((*(short *)(iVar2 + 0x176) == 0) || (10 < *(short *)(iVar2 + 0x176))) {
      *(undefined2 *)(iVar2 + 0x176) = 0;
      uVar1 = FUN_800221a0(0xffffffe2,0x1e);
      *(float *)(iVar2 + 0x154) =
           *(float *)(param_1 + 0xc) +
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e6a60);
      *(undefined4 *)(iVar2 + 0x158) = *(undefined4 *)(param_1 + 0x10);
      uVar1 = FUN_800221a0(0xffffffe2,0x1e);
      *(float *)(iVar2 + 0x15c) =
           *(float *)(param_1 + 0x14) +
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e6a60);
      uVar1 = FUN_800221a0(0xffffff88,0x78);
      *(float *)(iVar2 + 0x160) =
           *(float *)(param_1 + 0xc) +
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e6a60);
      *(float *)(iVar2 + 0x164) = *(float *)(param_1 + 0x10) - FLOAT_803e6a88;
      uVar1 = FUN_800221a0(0xffffff88,0x78);
      *(float *)(iVar2 + 0x168) =
           *(float *)(param_1 + 0x14) +
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e6a60);
    }
  }
  return;
}

