// Function: FUN_801ad550
// Entry: 801ad550
// Size: 124 bytes

void FUN_801ad550(int param_1)

{
  if (*(short *)(param_1 + 0x46) != 0x172) {
    if (*(char *)(*(int *)(param_1 + 0xb8) + 0xb) != '\0') {
      FUN_800066e0(param_1,param_1,*(undefined2 *)(*(int *)(param_1 + 0xb8) + 8),0,0,0);
    }
    (**(code **)(*DAT_803dca78 + 0x18))(param_1);
  }
  return;
}

