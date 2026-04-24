// Function: FUN_800bc110
// Entry: 800bc110
// Size: 296 bytes

void FUN_800bc110(void)

{
  double dVar1;
  
  FLOAT_803db7d8 = FLOAT_803db7d8 + FLOAT_803dfa88 * FLOAT_803db414;
  if (FLOAT_803dfa90 < FLOAT_803db7d8) {
    FLOAT_803db7d8 = FLOAT_803dfa8c;
  }
  FLOAT_803db7dc = FLOAT_803db7dc + FLOAT_803dfa88 * FLOAT_803db414;
  if (FLOAT_803dfa90 < FLOAT_803db7dc) {
    FLOAT_803db7dc = FLOAT_803dfa98;
  }
  DAT_803dd350 = DAT_803dd350 + (uint)DAT_803db410 * 100;
  if (0x7fff < DAT_803dd350) {
    DAT_803dd350 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803dfbd8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd350 ^
                                                                 0x80000000) - DOUBLE_803dfbd0)) /
                                       FLOAT_803dfbdc));
  FLOAT_803dd35c = (float)dVar1;
  DAT_803dd354 = DAT_803dd354 + (uint)DAT_803db410 * 0x32;
  if (0x7fff < DAT_803dd354) {
    DAT_803dd354 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803dfbd8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd354 ^
                                                                 0x80000000) - DOUBLE_803dfbd0)) /
                                       FLOAT_803dfbdc));
  FLOAT_803dd358 = (float)dVar1;
  return;
}

