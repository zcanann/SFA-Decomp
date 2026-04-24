// Function: FUN_8010c304
// Entry: 8010c304
// Size: 112 bytes

void FUN_8010c304(int param_1)

{
  if (*(int *)(param_1 + 0x11c) != 0) {
    (**(code **)(*DAT_803dd6d0 + 0x48))(0);
  }
  FUN_800238c4(DAT_803de1e0);
  DAT_803de1e0 = 0;
  FUN_800551ec();
  *(byte *)(param_1 + 0x143) = *(byte *)(param_1 + 0x143) & 0x7f;
  return;
}

