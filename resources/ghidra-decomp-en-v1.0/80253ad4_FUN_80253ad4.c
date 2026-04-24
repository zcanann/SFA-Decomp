// Function: FUN_80253ad4
// Entry: 80253ad4
// Size: 128 bytes

int FUN_80253ad4(int param_1)

{
  int iVar1;
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
  return iVar1;
}

