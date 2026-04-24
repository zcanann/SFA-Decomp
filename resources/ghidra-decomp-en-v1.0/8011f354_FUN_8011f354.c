// Function: FUN_8011f354
// Entry: 8011f354
// Size: 56 bytes

void FUN_8011f354(byte param_1)

{
  DAT_803dd7cc = param_1 & 1;
  if (param_1 == 3) {
    DAT_803dd838 = 0xff;
    return;
  }
  if (2 < param_1) {
    return;
  }
  if (param_1 < 2) {
    return;
  }
  DAT_803dd838 = 0;
  return;
}

