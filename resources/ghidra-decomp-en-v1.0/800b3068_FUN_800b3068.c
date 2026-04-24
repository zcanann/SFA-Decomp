// Function: FUN_800b3068
// Entry: 800b3068
// Size: 296 bytes

void FUN_800b3068(void)

{
  double dVar1;
  
  FLOAT_803db7b8 = FLOAT_803db7b8 + FLOAT_803df720 * FLOAT_803db414;
  if (FLOAT_803df728 < FLOAT_803db7b8) {
    FLOAT_803db7b8 = FLOAT_803df724;
  }
  FLOAT_803db7bc = FLOAT_803db7bc + FLOAT_803df720 * FLOAT_803db414;
  if (FLOAT_803df728 < FLOAT_803db7bc) {
    FLOAT_803db7bc = FLOAT_803df730;
  }
  DAT_803dd328 = DAT_803dd328 + (uint)DAT_803db410 * 100;
  if (0x7fff < DAT_803dd328) {
    DAT_803dd328 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803df868 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd328 ^
                                                                 0x80000000) - DOUBLE_803df860)) /
                                       FLOAT_803df86c));
  FLOAT_803dd334 = (float)dVar1;
  DAT_803dd32c = DAT_803dd32c + (uint)DAT_803db410 * 0x32;
  if (0x7fff < DAT_803dd32c) {
    DAT_803dd32c = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803df868 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd32c ^
                                                                 0x80000000) - DOUBLE_803df860)) /
                                       FLOAT_803df86c));
  FLOAT_803dd330 = (float)dVar1;
  return;
}

