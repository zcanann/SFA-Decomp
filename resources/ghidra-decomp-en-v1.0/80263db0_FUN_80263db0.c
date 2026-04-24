// Function: FUN_80263db0
// Entry: 80263db0
// Size: 272 bytes

int FUN_80263db0(undefined4 param_1,undefined4 param_2,undefined *param_3)

{
  int iVar1;
  int local_1c;
  int local_18 [3];
  
  iVar1 = FUN_8025edc8(param_1,local_18);
  if (-1 < iVar1) {
    iVar1 = FUN_80262e5c(local_18[0],param_2,&local_1c);
    if (iVar1 < 0) {
      iVar1 = FUN_8025ee80(local_18[0]);
    }
    else {
      iVar1 = FUN_80263178(local_18[0],local_1c);
      if (iVar1 == 0) {
        iVar1 = FUN_802608b0(local_18[0]);
        iVar1 = iVar1 + local_1c * 0x40;
        *(undefined2 *)(local_18[0] + 0xbe) = *(undefined2 *)(iVar1 + 0x36);
        FUN_800033a8(iVar1,0xff,0x40);
        if (param_3 == (undefined *)0x0) {
          param_3 = &DAT_8025de80;
        }
        *(undefined **)(local_18[0] + 0xd0) = param_3;
        iVar1 = FUN_80260a50(param_1,&LAB_80263d0c);
        if (iVar1 < 0) {
          FUN_8025ee80(local_18[0],iVar1);
        }
      }
      else {
        iVar1 = FUN_8025ee80(local_18[0],0xffffffff);
      }
    }
  }
  return iVar1;
}

