// Function: FUN_8011611c
// Entry: 8011611c
// Size: 264 bytes

void FUN_8011611c(void)

{
  undefined4 uVar1;
  
  if (DAT_803dd610 == 2) {
    FUN_8011881c();
    FUN_80118fac();
    FUN_801192ec();
    uVar1 = FUN_80023834(0);
    if (DAT_803dd634 != 0) {
      FUN_80023800();
      DAT_803dd634 = 0;
    }
    if (DAT_803dd630 != 0) {
      FUN_80023800();
      DAT_803dd630 = 0;
    }
    if (DAT_803dd62c != 0) {
      FUN_80023800();
      DAT_803dd62c = 0;
    }
    if (DAT_803dd628 != 0) {
      FUN_80023800();
      DAT_803dd628 = 0;
    }
    if (DAT_803dd624 != 0) {
      FUN_80023800();
      DAT_803dd624 = 0;
    }
    if (DAT_803dd620 != 0) {
      FUN_80023800();
      DAT_803dd620 = 0;
    }
    if (DAT_803dd61c != 0) {
      FUN_80023800();
      DAT_803dd61c = 0;
    }
    FUN_80023834(uVar1);
    DAT_803dd610 = 4;
    DAT_803dd619 = 1;
  }
  return;
}

