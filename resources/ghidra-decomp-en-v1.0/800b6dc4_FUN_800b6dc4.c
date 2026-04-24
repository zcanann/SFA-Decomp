// Function: FUN_800b6dc4
// Entry: 800b6dc4
// Size: 296 bytes

void FUN_800b6dc4(void)

{
  double dVar1;
  
  FLOAT_803db7c8 = FLOAT_803db7c8 + FLOAT_803df870 * FLOAT_803db414;
  if (FLOAT_803df878 < FLOAT_803db7c8) {
    FLOAT_803db7c8 = FLOAT_803df874;
  }
  FLOAT_803db7cc = FLOAT_803db7cc + FLOAT_803df870 * FLOAT_803db414;
  if (FLOAT_803df878 < FLOAT_803db7cc) {
    FLOAT_803db7cc = FLOAT_803df880;
  }
  DAT_803dd338 = DAT_803dd338 + (uint)DAT_803db410 * 100;
  if (0x7fff < DAT_803dd338) {
    DAT_803dd338 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803df9c8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd338 ^
                                                                 0x80000000) - DOUBLE_803df9c0)) /
                                       FLOAT_803df9cc));
  FLOAT_803dd344 = (float)dVar1;
  DAT_803dd33c = DAT_803dd33c + (uint)DAT_803db410 * 0x32;
  if (0x7fff < DAT_803dd33c) {
    DAT_803dd33c = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803df9c8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd33c ^
                                                                 0x80000000) - DOUBLE_803df9c0)) /
                                       FLOAT_803df9cc));
  FLOAT_803dd340 = (float)dVar1;
  return;
}

