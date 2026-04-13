// Function: FUN_80264514
// Entry: 80264514
// Size: 272 bytes

int FUN_80264514(int param_1,char *param_2,undefined *param_3)

{
  int iVar1;
  int local_1c;
  int *local_18 [3];
  
  iVar1 = FUN_8025f52c(param_1,local_18);
  if (-1 < iVar1) {
    iVar1 = FUN_802635c0(local_18[0],param_2,&local_1c);
    if (iVar1 < 0) {
      iVar1 = FUN_8025f5e4(local_18[0],iVar1);
    }
    else {
      iVar1 = FUN_802638dc();
      if (iVar1 == 0) {
        iVar1 = FUN_80261014((int)local_18[0]);
        iVar1 = iVar1 + local_1c * 0x40;
        *(undefined2 *)((int)local_18[0] + 0xbe) = *(undefined2 *)(iVar1 + 0x36);
        FUN_800033a8(iVar1,0xff,0x40);
        if (param_3 == (undefined *)0x0) {
          param_3 = &DAT_8025e5e4;
        }
        local_18[0][0x34] = (int)param_3;
        iVar1 = FUN_802611b4(param_1,&LAB_80264470);
        if (iVar1 < 0) {
          FUN_8025f5e4(local_18[0],iVar1);
        }
      }
      else {
        iVar1 = FUN_8025f5e4(local_18[0],-1);
      }
    }
  }
  return iVar1;
}

