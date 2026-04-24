// Function: FUN_8016efa0
// Entry: 8016efa0
// Size: 84 bytes

void FUN_8016efa0(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_8016e48c();
  iVar1 = FUN_80020800();
  if (iVar1 == 0) {
    *(undefined *)(iVar2 + 0xbc) = 0;
  }
  else {
    *(undefined *)(iVar2 + 0xbc) = 1;
  }
  return;
}

