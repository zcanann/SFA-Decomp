// Function: FUN_80060a38
// Entry: 80060a38
// Size: 264 bytes

int FUN_80060a38(int param_1)

{
  int iVar1;
  int iVar2;
  int local_18;
  int local_14 [3];
  
  if (DAT_803dceb0 < param_1) {
    iVar1 = 0;
  }
  else {
    iVar2 = 0;
    if (DAT_803dcde4 != 0) {
      iVar1 = *(int *)(DAT_803dcde4 + param_1 * 4);
      if (iVar1 != -1) {
        if ((iVar1 == 0) && (*(int *)(DAT_803dcde4 + param_1 * 4 + 4) == 0)) {
          return 0;
        }
        FUN_80048bfc(iVar1,local_14,&local_18);
        iVar2 = iVar1;
      }
    }
    if (local_14[0] < 1) {
      iVar1 = 0;
    }
    else if (local_18 < 0x32001) {
      iVar1 = FUN_80023cc8(local_18,5,0);
      if (iVar1 == 0) {
        iVar1 = 0;
      }
      else {
        FUN_800464c8(0x25,iVar1,iVar2,local_14[0],0,0,0);
      }
    }
    else {
      iVar1 = 0;
    }
  }
  return iVar1;
}

