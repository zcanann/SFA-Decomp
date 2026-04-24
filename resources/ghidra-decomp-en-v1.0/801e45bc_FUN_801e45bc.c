// Function: FUN_801e45bc
// Entry: 801e45bc
// Size: 84 bytes

void FUN_801e45bc(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dca78 + 0x18))();
  if (*(int *)(iVar1 + 0x18) != 0) {
    FUN_8001f384();
    *(undefined4 *)(iVar1 + 0x18) = 0;
  }
  return;
}

