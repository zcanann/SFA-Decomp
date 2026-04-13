// Function: FUN_8018a764
// Entry: 8018a764
// Size: 20 bytes

void FUN_8018a764(int param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined4 *)(iVar1 + 0x14) = param_2;
  *(undefined *)(iVar1 + 0x1c) = 1;
  return;
}

