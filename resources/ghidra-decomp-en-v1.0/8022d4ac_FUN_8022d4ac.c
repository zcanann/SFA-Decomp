// Function: FUN_8022d4ac
// Entry: 8022d4ac
// Size: 32 bytes

void FUN_8022d4ac(int param_1,undefined4 *param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined4 *)(iVar1 + 0x48) = *param_2;
  *(undefined4 *)(iVar1 + 0x4c) = param_2[1];
  *(undefined4 *)(iVar1 + 0x50) = param_2[2];
  return;
}

