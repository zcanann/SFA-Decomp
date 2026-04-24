// Function: FUN_801e3d40
// Entry: 801e3d40
// Size: 84 bytes

void FUN_801e3d40(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dca78 + 0x18))();
  if (*(int *)(iVar1 + 0x20) != 0) {
    FUN_8001f384();
    *(undefined4 *)(iVar1 + 0x20) = 0;
  }
  return;
}

