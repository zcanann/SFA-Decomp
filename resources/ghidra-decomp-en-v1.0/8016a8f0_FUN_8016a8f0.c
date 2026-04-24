// Function: FUN_8016a8f0
// Entry: 8016a8f0
// Size: 100 bytes

void FUN_8016a8f0(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar1 + 0x18) != 0) {
    FUN_8001f384();
    *(undefined4 *)(iVar1 + 0x18) = 0;
  }
  (**(code **)(*DAT_803dca78 + 0x18))(param_1);
  return;
}

