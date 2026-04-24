// Function: FUN_8026140c
// Entry: 8026140c
// Size: 140 bytes

int FUN_8026140c(undefined4 param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_80260cc4();
  if (-1 < iVar1) {
    iVar1 = FUN_80260f48(param_1,0);
    iVar2 = FUN_80261188(param_1,0);
    iVar1 = iVar1 + iVar2;
    if (iVar1 == 1) {
      iVar1 = -6;
    }
    else if ((iVar1 < 1) && (-1 < iVar1)) {
      iVar1 = 0;
    }
    else {
      iVar1 = -6;
    }
  }
  return iVar1;
}

