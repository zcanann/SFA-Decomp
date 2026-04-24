// Function: FUN_80264314
// Entry: 80264314
// Size: 276 bytes

int FUN_80264314(int *param_1,uint param_2,uint param_3,uint param_4,undefined *param_5)

{
  int iVar1;
  int *local_1c [2];
  
  iVar1 = FUN_80263c7c(param_1,param_3,param_4,local_1c);
  if (-1 < iVar1) {
    if (((param_4 & local_1c[0][3] - 1U) == 0) && ((param_3 & local_1c[0][3] - 1U) == 0)) {
      iVar1 = FUN_80261014((int)local_1c[0]);
      iVar1 = FUN_802634f8((int)local_1c[0],(char *)(iVar1 + param_1[1] * 0x40));
      if (iVar1 < 0) {
        iVar1 = FUN_8025f5e4(local_1c[0],iVar1);
      }
      else {
        FUN_80242114(param_2,param_3);
        if (param_5 == (undefined *)0x0) {
          param_5 = &DAT_8025e5e4;
        }
        local_1c[0][0x34] = (int)param_5;
        local_1c[0][0x2d] = param_2;
        iVar1 = FUN_8025f378(*param_1,local_1c[0][3] * (uint)*(ushort *)(param_1 + 4),-0x7fd9bd9c);
        if (iVar1 < 0) {
          FUN_8025f5e4(local_1c[0],iVar1);
        }
      }
    }
    else {
      iVar1 = FUN_8025f5e4(local_1c[0],-0x80);
    }
  }
  return iVar1;
}

