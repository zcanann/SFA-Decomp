// Function: FUN_8011f638
// Entry: 8011f638
// Size: 56 bytes

void FUN_8011f638(byte param_1)

{
  DAT_803de44c = param_1 & 1;
  if (param_1 == 3) {
    DAT_803de4b8 = 0xff;
    return;
  }
  if (2 < param_1) {
    return;
  }
  if (param_1 < 2) {
    return;
  }
  DAT_803de4b8 = 0;
  return;
}

