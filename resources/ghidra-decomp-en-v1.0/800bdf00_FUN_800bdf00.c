// Function: FUN_800bdf00
// Entry: 800bdf00
// Size: 296 bytes

void FUN_800bdf00(void)

{
  double dVar1;
  
  FLOAT_803db7f8 = FLOAT_803db7f8 + FLOAT_803dfc80 * FLOAT_803db414;
  if (FLOAT_803dfc88 < FLOAT_803db7f8) {
    FLOAT_803db7f8 = FLOAT_803dfc84;
  }
  FLOAT_803db7fc = FLOAT_803db7fc + FLOAT_803dfc80 * FLOAT_803db414;
  if (FLOAT_803dfc88 < FLOAT_803db7fc) {
    FLOAT_803db7fc = FLOAT_803dfc90;
  }
  DAT_803dd370 = DAT_803dd370 + (uint)DAT_803db410 * 100;
  if (0x7fff < DAT_803dd370) {
    DAT_803dd370 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803dfcd0 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd370 ^
                                                                 0x80000000) - DOUBLE_803dfcc8)) /
                                       FLOAT_803dfcd4));
  FLOAT_803dd37c = (float)dVar1;
  DAT_803dd374 = DAT_803dd374 + (uint)DAT_803db410 * 0x32;
  if (0x7fff < DAT_803dd374) {
    DAT_803dd374 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803dfcd0 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd374 ^
                                                                 0x80000000) - DOUBLE_803dfcc8)) /
                                       FLOAT_803dfcd4));
  FLOAT_803dd378 = (float)dVar1;
  return;
}

