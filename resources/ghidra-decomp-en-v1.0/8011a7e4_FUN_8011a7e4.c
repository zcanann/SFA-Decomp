// Function: FUN_8011a7e4
// Entry: 8011a7e4
// Size: 304 bytes

void FUN_8011a7e4(void)

{
  bool bVar1;
  
  if (DAT_803db9fb != -1) {
    (**(code **)(*DAT_803dcaa0 + 8))();
  }
  DAT_803db9fb = 0;
  DAT_803dd6a4 = 0;
  FUN_8011a70c();
  FUN_8011a410(&PTR_DAT_8031a7bc);
  bVar1 = false;
  while (!bVar1) {
    if (DAT_803db9fc == 3) {
      PTR_DAT_8031a7bc[0x1a] = 0xff;
    }
    else {
      PTR_DAT_8031a7bc[0x1a] = 3;
    }
    bVar1 = true;
  }
  (**(code **)(*DAT_803dcaa0 + 4))
            (PTR_DAT_8031a7bc,DAT_8031a7c0,0,0,5,4,0x14,200,0xff,0xff,0xff,0xff);
  (**(code **)(*DAT_803dcaa0 + 0x18))(0);
  DAT_803dd6ce = 2;
  if (DAT_803db424 == '\0') {
    FUN_8011a4e8();
  }
  return;
}

