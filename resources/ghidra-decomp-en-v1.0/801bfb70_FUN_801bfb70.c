// Function: FUN_801bfb70
// Entry: 801bfb70
// Size: 84 bytes

void FUN_801bfb70(int param_1)

{
  if (*(int *)(*(int *)(param_1 + 0xb8) + 4) != 0) {
    FUN_8001f384();
  }
  (**(code **)(*DAT_803dca78 + 0x18))(param_1);
  return;
}

