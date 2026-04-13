// Function: FUN_8016de98
// Entry: 8016de98
// Size: 16 bytes

void FUN_8016de98(int param_1,undefined param_2,undefined param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar1 + 0xbb) = param_2;
  *(undefined *)(iVar1 + 0xba) = param_3;
  return;
}

