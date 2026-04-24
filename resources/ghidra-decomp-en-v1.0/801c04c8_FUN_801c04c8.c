// Function: FUN_801c04c8
// Entry: 801c04c8
// Size: 100 bytes

void FUN_801c04c8(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar1 + 0x10) != 0) {
    FUN_8001f384();
    *(undefined4 *)(iVar1 + 0x10) = 0;
  }
  (**(code **)(*DAT_803dca78 + 0x18))(param_1);
  return;
}

