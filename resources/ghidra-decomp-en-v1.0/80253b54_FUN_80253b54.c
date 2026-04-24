// Function: FUN_80253b54
// Entry: 80253b54
// Size: 180 bytes

undefined4 FUN_80253b54(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined auStack12 [4];
  
  iVar1 = FUN_80253960(param_1);
  if ((iVar1 != 0) && ((&DAT_803ae420)[param_1 * 0x10] == 0)) {
    iVar1 = FUN_802546e0(param_1,0,auStack12);
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else {
      iVar1 = 1;
    }
  }
  if (iVar1 == 0) {
    if ((&DAT_800030c0)[param_1] == 0) {
      uVar2 = 0xffffffff;
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}

