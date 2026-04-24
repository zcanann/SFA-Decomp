// Function: FUN_8016be78
// Entry: 8016be78
// Size: 196 bytes

void FUN_8016be78(int param_1,int param_2)

{
  (**(code **)(*DAT_803dca54 + 0x24))(*(undefined4 *)(param_1 + 0xb8));
  (**(code **)(*DAT_803dca74 + 8))(param_1,0xffff,0,0,0);
  FUN_8000da7c(param_1);
  FUN_8000b7bc(param_1,0x7f);
  if ((*(short *)(param_1 + 0x46) == 0x774) && (*(char *)(param_1 + 0xeb) != '\0')) {
    FUN_8002cbc4(*(undefined4 *)(param_1 + 200));
    FUN_80037cb0(param_1,*(undefined4 *)(param_1 + 200));
  }
  if (param_2 != 0) {
    FUN_800801f8();
  }
  return;
}

