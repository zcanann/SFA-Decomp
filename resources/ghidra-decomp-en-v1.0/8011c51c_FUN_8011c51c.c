// Function: FUN_8011c51c
// Entry: 8011c51c
// Size: 176 bytes

undefined4 FUN_8011c51c(int param_1,int param_2)

{
  if (param_1 == 1) {
    if (param_2 == 2) {
      FUN_8011c7b4();
      return 1;
    }
    if (param_2 < 2) {
      if (param_2 == 0) {
        FUN_8011ca74();
        return 1;
      }
    }
    else if (param_2 < 4) {
      FUN_8011c5cc();
      return 1;
    }
  }
  else if (param_1 == 0) {
    FUN_8000bb18(0,0x100);
    (**(code **)(*DAT_803dca4c + 8))(0x14,5);
    DAT_803dd704 = 0x23;
    DAT_803dd705 = 1;
  }
  return 0;
}

