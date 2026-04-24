// Function: FUN_801a79e0
// Entry: 801a79e0
// Size: 304 bytes

void FUN_801a79e0(int param_1)

{
  int iVar1;
  int iVar2;
  undefined auStack96 [4];
  undefined auStack92 [84];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8003687c(param_1,auStack96,0,0);
  if (iVar1 == 0) {
    iVar1 = FUN_800640cc((double)FLOAT_803e454c,param_1 + 0x80,param_1 + 0xc,1,auStack92,param_1,1,
                         0xffffffff,0xff,0);
  }
  if ((iVar1 != 0) ||
     (((*(char *)(*(int *)(param_1 + 0x54) + 0xad) != '\0' &&
       ((*(ushort *)(iVar2 + 0x24) & 0x40) != 0)) || ((*(ushort *)(iVar2 + 0x24) & 0x100) != 0)))) {
    *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803e4550;
    FUN_8009ab70((double)FLOAT_803e4554,param_1,1,1,0,0,0,1,0);
    *(ushort *)(iVar2 + 0x24) = *(ushort *)(iVar2 + 0x24) | 0x200;
    *(float *)(iVar2 + 0x14) = FLOAT_803e4558;
    *(undefined *)(param_1 + 0x36) = 0;
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar2 + 0x18);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar2 + 0x1c);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar2 + 0x20);
    FUN_800e8370(param_1);
  }
  return;
}

