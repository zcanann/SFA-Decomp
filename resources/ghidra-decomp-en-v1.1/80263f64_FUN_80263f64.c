// Function: FUN_80263f64
// Entry: 80263f64
// Size: 328 bytes

int FUN_80263f64(int *param_1,uint param_2,uint param_3,uint param_4,undefined *param_5)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  char *pcVar4;
  int *local_1c [2];
  
  if (((param_4 & 0x1ff) == 0) && ((param_3 & 0x1ff) == 0)) {
    iVar1 = FUN_80263c7c(param_1,param_3,param_4,local_1c);
    if (-1 < iVar1) {
      iVar1 = FUN_80261014((int)local_1c[0]);
      pcVar4 = (char *)(iVar1 + param_1[1] * 0x40);
      iVar1 = FUN_802634f8((int)local_1c[0],pcVar4);
      if (iVar1 == -10) {
        iVar1 = FUN_80263590(pcVar4);
      }
      if (iVar1 < 0) {
        iVar1 = FUN_8025f5e4(local_1c[0],iVar1);
      }
      else {
        FUN_802420b0(param_2,param_3);
        if (param_5 == (undefined *)0x0) {
          param_5 = &DAT_8025e5e4;
        }
        local_1c[0][0x34] = (int)param_5;
        iVar1 = local_1c[0][3];
        uVar3 = param_1[2] & iVar1 - 1U;
        uVar2 = iVar1 - uVar3;
        if ((int)param_3 < (int)uVar2) {
          uVar2 = param_3;
        }
        iVar1 = FUN_80260a6c(*param_1,uVar3 + iVar1 * (uint)*(ushort *)(param_1 + 4),uVar2,param_2,
                             &LAB_80263e34);
        if (iVar1 < 0) {
          FUN_8025f5e4(local_1c[0],iVar1);
        }
      }
    }
  }
  else {
    iVar1 = -0x80;
  }
  return iVar1;
}

