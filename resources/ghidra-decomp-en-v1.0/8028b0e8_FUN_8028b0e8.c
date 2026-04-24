// Function: FUN_8028b0e8
// Entry: 8028b0e8
// Size: 60 bytes

void FUN_8028b0e8(int param_1,int param_2,int param_3)

{
  int iVar1;
  
  for (iVar1 = 0; iVar1 != param_3; iVar1 = iVar1 + 1) {
    sync(0);
    sync(0);
    *(undefined *)(iVar1 + param_1) = *(undefined *)(iVar1 + param_2);
  }
  sync(0);
  return;
}

