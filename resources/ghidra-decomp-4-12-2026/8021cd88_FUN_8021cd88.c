// Function: FUN_8021cd88
// Entry: 8021cd88
// Size: 348 bytes

void FUN_8021cd88(int param_1)

{
  uint uVar1;
  char in_r8;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
    *(ushort *)(iVar2 + 0x176) = *(short *)(iVar2 + 0x176) + (ushort)DAT_803dc070;
    if ((*(short *)(iVar2 + 0x176) == 0) || (10 < *(short *)(iVar2 + 0x176))) {
      *(undefined2 *)(iVar2 + 0x176) = 0;
      uVar1 = FUN_80022264(0xffffffe2,0x1e);
      *(float *)(iVar2 + 0x154) =
           *(float *)(param_1 + 0xc) +
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e76f8);
      *(undefined4 *)(iVar2 + 0x158) = *(undefined4 *)(param_1 + 0x10);
      uVar1 = FUN_80022264(0xffffffe2,0x1e);
      *(float *)(iVar2 + 0x15c) =
           *(float *)(param_1 + 0x14) +
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e76f8);
      uVar1 = FUN_80022264(0xffffff88,0x78);
      *(float *)(iVar2 + 0x160) =
           *(float *)(param_1 + 0xc) +
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e76f8);
      *(float *)(iVar2 + 0x164) = *(float *)(param_1 + 0x10) - FLOAT_803e7720;
      uVar1 = FUN_80022264(0xffffff88,0x78);
      *(float *)(iVar2 + 0x168) =
           *(float *)(param_1 + 0x14) +
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e76f8);
    }
  }
  return;
}

