// Function: FUN_8016d9ec
// Entry: 8016d9ec
// Size: 16 bytes

void FUN_8016d9ec(int param_1,undefined param_2,undefined param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar1 + 0xbb) = param_2;
  *(undefined *)(iVar1 + 0xba) = param_3;
  return;
}

