// Function: FUN_80263800
// Entry: 80263800
// Size: 328 bytes

int FUN_80263800(undefined4 *param_1,undefined4 param_2,uint param_3,uint param_4,undefined *param_5
                )

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int local_1c [2];
  
  if (((param_4 & 0x1ff) == 0) && ((param_3 & 0x1ff) == 0)) {
    iVar1 = FUN_80263518(param_1,param_3,param_4,local_1c);
    if (-1 < iVar1) {
      iVar1 = FUN_802608b0(local_1c[0]);
      iVar1 = iVar1 + param_1[1] * 0x40;
      iVar2 = FUN_80262d94(local_1c[0],iVar1);
      if (iVar2 == -10) {
        iVar2 = FUN_80262e2c(iVar1);
      }
      if (iVar2 < 0) {
        iVar1 = FUN_8025ee80(local_1c[0]);
      }
      else {
        FUN_802419b8(param_2,param_3);
        if (param_5 == (undefined *)0x0) {
          param_5 = &DAT_8025de80;
        }
        *(undefined **)(local_1c[0] + 0xd0) = param_5;
        iVar1 = *(int *)(local_1c[0] + 0xc);
        uVar4 = param_1[2] & iVar1 - 1U;
        uVar3 = iVar1 - uVar4;
        if ((int)param_3 < (int)uVar3) {
          uVar3 = param_3;
        }
        iVar1 = FUN_80260308(*param_1,uVar4 + iVar1 * (uint)*(ushort *)(param_1 + 4),uVar3,param_2,
                             &LAB_802636d0);
        if (iVar1 < 0) {
          FUN_8025ee80(local_1c[0],iVar1);
        }
      }
    }
  }
  else {
    iVar1 = -0x80;
  }
  return iVar1;
}

