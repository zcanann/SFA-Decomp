// Function: FUN_80264990
// Entry: 80264990
// Size: 372 bytes

int FUN_80264990(int param_1,int param_2,int param_3,undefined4 param_4)

{
  uint uVar1;
  int iVar2;
  char *pcVar3;
  undefined8 uVar4;
  int *local_18 [2];
  
  if ((((param_2 < 0) || (0x7e < param_2)) ||
      ((*(uint *)(param_3 + 0x30) != 0xffffffff && (0x1ff < *(uint *)(param_3 + 0x30))))) ||
     ((*(uint *)(param_3 + 0x38) != 0xffffffff && (0x1fc0 < (*(uint *)(param_3 + 0x38) & 0x1fff)))))
  {
    iVar2 = -0x80;
  }
  else {
    iVar2 = FUN_8025f52c(param_1,local_18);
    if (-1 < iVar2) {
      iVar2 = FUN_80261014((int)local_18[0]);
      pcVar3 = (char *)(iVar2 + param_2 * 0x40);
      iVar2 = FUN_802634f8((int)local_18[0],pcVar3);
      if (iVar2 < 0) {
        iVar2 = FUN_8025f5e4(local_18[0],iVar2);
      }
      else {
        pcVar3[7] = *(char *)(param_3 + 0x2e);
        *(undefined4 *)(pcVar3 + 0x2c) = *(undefined4 *)(param_3 + 0x30);
        *(undefined2 *)(pcVar3 + 0x30) = *(undefined2 *)(param_3 + 0x34);
        *(undefined2 *)(pcVar3 + 0x32) = *(undefined2 *)(param_3 + 0x36);
        *(undefined4 *)(pcVar3 + 0x3c) = *(undefined4 *)(param_3 + 0x38);
        FUN_8026466c((int)pcVar3,param_3);
        if (*(int *)(pcVar3 + 0x2c) == -1) {
          *(ushort *)(pcVar3 + 0x32) = *(ushort *)(pcVar3 + 0x32) & 0xfffc | 1;
        }
        uVar1 = DAT_800000f8 >> 2;
        uVar4 = FUN_802473b4();
        uVar4 = FUN_80286990((uint)((ulonglong)uVar4 >> 0x20),(uint)uVar4,0,uVar1);
        *(int *)(pcVar3 + 0x28) = (int)uVar4;
        iVar2 = FUN_802611b4(param_1,param_4);
        if (iVar2 < 0) {
          FUN_8025f5e4(local_18[0],iVar2);
        }
      }
    }
  }
  return iVar2;
}

