// Function: FUN_80206ac4
// Entry: 80206ac4
// Size: 68 bytes

void FUN_80206ac4(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  *(undefined4 *)(iVar1 + 8) = 0;
  return;
}

