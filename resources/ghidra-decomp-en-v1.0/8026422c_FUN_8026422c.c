// Function: FUN_8026422c
// Entry: 8026422c
// Size: 372 bytes

int FUN_8026422c(undefined4 param_1,int param_2,int param_3,undefined4 param_4)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 extraout_r4;
  undefined8 uVar4;
  undefined4 local_18 [2];
  
  if ((((param_2 < 0) || (0x7e < param_2)) ||
      ((*(uint *)(param_3 + 0x30) != 0xffffffff && (0x1ff < *(uint *)(param_3 + 0x30))))) ||
     ((*(uint *)(param_3 + 0x38) != 0xffffffff && (0x1fc0 < (*(uint *)(param_3 + 0x38) & 0x1fff)))))
  {
    iVar2 = -0x80;
  }
  else {
    iVar2 = FUN_8025edc8(param_1,local_18);
    if (-1 < iVar2) {
      iVar2 = FUN_802608b0(local_18[0]);
      iVar2 = iVar2 + param_2 * 0x40;
      iVar3 = FUN_80262d94(local_18[0],iVar2);
      if (iVar3 < 0) {
        iVar2 = FUN_8025ee80(local_18[0]);
      }
      else {
        *(undefined *)(iVar2 + 7) = *(undefined *)(param_3 + 0x2e);
        *(undefined4 *)(iVar2 + 0x2c) = *(undefined4 *)(param_3 + 0x30);
        *(undefined2 *)(iVar2 + 0x30) = *(undefined2 *)(param_3 + 0x34);
        *(undefined2 *)(iVar2 + 0x32) = *(undefined2 *)(param_3 + 0x36);
        *(undefined4 *)(iVar2 + 0x3c) = *(undefined4 *)(param_3 + 0x38);
        FUN_80263f08(iVar2,param_3);
        if (*(int *)(iVar2 + 0x2c) == -1) {
          *(ushort *)(iVar2 + 0x32) = *(ushort *)(iVar2 + 0x32) & 0xfffc | 1;
        }
        uVar1 = DAT_800000f8 >> 2;
        uVar4 = FUN_80246c50();
        FUN_8028622c((int)((ulonglong)uVar4 >> 0x20),(int)uVar4,0,uVar1);
        *(undefined4 *)(iVar2 + 0x28) = extraout_r4;
        iVar2 = FUN_80260a50(param_1,param_4);
        if (iVar2 < 0) {
          FUN_8025ee80(local_18[0],iVar2);
        }
      }
    }
  }
  return iVar2;
}

