// Function: FUN_8028f0e4
// Entry: 8028f0e4
// Size: 160 bytes

uint FUN_8028f0e4(int param_1,short *param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  undefined auStack40 [20];
  
  uVar2 = 0;
  if ((param_1 == 0) || (param_2 == (short *)0x0)) {
    uVar2 = 0;
  }
  else {
    for (; uVar2 <= param_3; uVar2 = uVar2 + iVar1) {
      if (*param_2 == 0) {
        *(undefined *)(param_1 + uVar2) = 0;
        return uVar2;
      }
      param_2 = param_2 + 1;
      iVar1 = FUN_8028f184(auStack40);
      if (param_3 < uVar2 + iVar1) {
        return uVar2;
      }
      FUN_802917a8(param_1 + uVar2,auStack40,iVar1);
    }
  }
  return uVar2;
}

