// Function: FUN_801e55c8
// Entry: 801e55c8
// Size: 124 bytes

void FUN_801e55c8(int param_1)

{
  (**(code **)(*DAT_803dca54 + 0x24))(*(undefined4 *)(param_1 + 0xb8));
  (**(code **)(*DAT_803dca74 + 8))(param_1,0xffff,0,0,0);
  if (*(int *)(param_1 + 0xf8) != 0) {
    FUN_8001f384();
  }
  return;
}

