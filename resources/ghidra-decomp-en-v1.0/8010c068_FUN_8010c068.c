// Function: FUN_8010c068
// Entry: 8010c068
// Size: 112 bytes

void FUN_8010c068(int param_1)

{
  if (*(int *)(param_1 + 0x11c) != 0) {
    (**(code **)(*DAT_803dca50 + 0x48))(0);
  }
  FUN_80023800(DAT_803dd568);
  DAT_803dd568 = 0;
  FUN_80055070();
  *(byte *)(param_1 + 0x143) = *(byte *)(param_1 + 0x143) & 0x7f;
  return;
}

