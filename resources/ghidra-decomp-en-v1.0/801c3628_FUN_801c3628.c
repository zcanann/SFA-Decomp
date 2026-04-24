// Function: FUN_801c3628
// Entry: 801c3628
// Size: 92 bytes

void FUN_801c3628(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar1 + 0x140) != 0) {
    FUN_8001f384();
    *(undefined4 *)(iVar1 + 0x140) = 0;
    *(undefined *)(iVar1 + 0x144) = 0;
  }
  (**(code **)(*DAT_803dca54 + 0x24))(iVar1);
  return;
}

