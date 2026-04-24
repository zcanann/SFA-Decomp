// Function: FUN_8024b320
// Entry: 8024b320
// Size: 76 bytes

int FUN_8024b320(int param_1)

{
  int iVar1;
  
  FUN_8024377c();
  iVar1 = *(int *)(param_1 + 0xc);
  if (iVar1 == 3) {
    iVar1 = 1;
  }
  FUN_802437a4();
  return iVar1;
}

