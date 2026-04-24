// Function: FUN_8001fee8
// Entry: 8001fee8
// Size: 84 bytes

int FUN_8001fee8(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = FUN_8001ffb4();
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = iVar1 + -1;
    FUN_800200e8(param_1,iVar1);
  }
  return iVar1;
}

