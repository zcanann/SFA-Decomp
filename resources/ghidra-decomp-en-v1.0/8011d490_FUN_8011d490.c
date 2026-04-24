// Function: FUN_8011d490
// Entry: 8011d490
// Size: 140 bytes

void FUN_8011d490(void)

{
  (**(code **)(*DAT_803dca4c + 0xc))(0x14,5);
  FUN_80019970(0x15);
  DAT_803dd70c = 0;
  DAT_803dd708 = FUN_800e7f38();
  if (DAT_803dd6f8 == '\0') {
    FUN_8011ca74();
  }
  else if (DAT_803dd6f8 == '\x01') {
    FUN_8011c7b4();
  }
  else {
    FUN_8011c5cc();
  }
  DAT_803dd6f9 = 0;
  DAT_803dd705 = 0;
  DAT_803dd706 = 2;
  return;
}

