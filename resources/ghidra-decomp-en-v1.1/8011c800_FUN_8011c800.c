// Function: FUN_8011c800
// Entry: 8011c800
// Size: 176 bytes

undefined4 FUN_8011c800(int param_1,int param_2)

{
  if (param_1 == 1) {
    if (param_2 == 2) {
      FUN_8011ca98();
      return 1;
    }
    if (param_2 < 2) {
      if (param_2 == 0) {
        FUN_8011cd58();
        return 1;
      }
    }
    else if (param_2 < 4) {
      FUN_8011c8b0();
      return 1;
    }
  }
  else if (param_1 == 0) {
    FUN_8000bb38(0,0x100);
    (**(code **)(*DAT_803dd6cc + 8))(0x14,5);
    DAT_803de384 = 0x23;
    DAT_803de385 = 1;
  }
  return 0;
}

