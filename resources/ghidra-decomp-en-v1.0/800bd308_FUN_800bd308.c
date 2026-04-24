// Function: FUN_800bd308
// Entry: 800bd308
// Size: 296 bytes

void FUN_800bd308(void)

{
  double dVar1;
  
  FLOAT_803db7e8 = FLOAT_803db7e8 + FLOAT_803dfbe0 * FLOAT_803db414;
  if (FLOAT_803dfbe8 < FLOAT_803db7e8) {
    FLOAT_803db7e8 = FLOAT_803dfbe4;
  }
  FLOAT_803db7ec = FLOAT_803db7ec + FLOAT_803dfbe0 * FLOAT_803db414;
  if (FLOAT_803dfbe8 < FLOAT_803db7ec) {
    FLOAT_803db7ec = FLOAT_803dfbf0;
  }
  DAT_803dd360 = DAT_803dd360 + (uint)DAT_803db410 * 100;
  if (0x7fff < DAT_803dd360) {
    DAT_803dd360 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803dfc78 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd360 ^
                                                                 0x80000000) - DOUBLE_803dfc70)) /
                                       FLOAT_803dfc7c));
  FLOAT_803dd36c = (float)dVar1;
  DAT_803dd364 = DAT_803dd364 + (uint)DAT_803db410 * 0x32;
  if (0x7fff < DAT_803dd364) {
    DAT_803dd364 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803dfc78 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd364 ^
                                                                 0x80000000) - DOUBLE_803dfc70)) /
                                       FLOAT_803dfc7c));
  FLOAT_803dd368 = (float)dVar1;
  return;
}

