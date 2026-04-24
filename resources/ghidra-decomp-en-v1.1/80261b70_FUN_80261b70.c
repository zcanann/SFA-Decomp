// Function: FUN_80261b70
// Entry: 80261b70
// Size: 140 bytes

int FUN_80261b70(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_80261428(param_1);
  if (-1 < iVar1) {
    iVar1 = FUN_802616ac(param_1,(uint *)0x0);
    iVar2 = FUN_802618ec(param_1,(uint *)0x0);
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

