// Function: FUN_80264100
// Entry: 80264100
// Size: 300 bytes

int FUN_80264100(undefined4 param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int local_14 [2];
  
  if ((param_2 < 0) || (0x7e < param_2)) {
    iVar1 = -0x80;
  }
  else {
    iVar1 = FUN_8025edc8(param_1,local_14);
    if (-1 < iVar1) {
      iVar1 = FUN_802608b0(local_14[0]);
      iVar1 = iVar1 + param_2 * 0x40;
      iVar2 = FUN_80262d94(local_14[0],iVar1);
      if (iVar2 == -10) {
        iVar2 = FUN_80262e2c(iVar1);
      }
      if (-1 < iVar2) {
        FUN_80003494(param_3 + 0x28,iVar1,4);
        FUN_80003494(param_3 + 0x2c,iVar1 + 4,2);
        *(uint *)(param_3 + 0x20) = (uint)*(ushort *)(iVar1 + 0x38) * *(int *)(local_14[0] + 0xc);
        FUN_80003494(param_3,iVar1 + 8,0x20);
        *(undefined4 *)(param_3 + 0x24) = *(undefined4 *)(iVar1 + 0x28);
        *(undefined *)(param_3 + 0x2e) = *(undefined *)(iVar1 + 7);
        *(undefined4 *)(param_3 + 0x30) = *(undefined4 *)(iVar1 + 0x2c);
        *(undefined2 *)(param_3 + 0x34) = *(undefined2 *)(iVar1 + 0x30);
        *(undefined2 *)(param_3 + 0x36) = *(undefined2 *)(iVar1 + 0x32);
        *(undefined4 *)(param_3 + 0x38) = *(undefined4 *)(iVar1 + 0x3c);
        FUN_80263f08(iVar1,param_3);
      }
      iVar1 = FUN_8025ee80(local_14[0],iVar2);
    }
  }
  return iVar1;
}

