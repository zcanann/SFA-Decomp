// Function: FUN_800cd2fc
// Entry: 800cd2fc
// Size: 296 bytes

void FUN_800cd2fc(void)

{
  double dVar1;
  
  FLOAT_803db878 = FLOAT_803db878 + FLOAT_803e02d8 * FLOAT_803db414;
  if (FLOAT_803e02e0 < FLOAT_803db878) {
    FLOAT_803db878 = FLOAT_803e02dc;
  }
  FLOAT_803db87c = FLOAT_803db87c + FLOAT_803e02d8 * FLOAT_803db414;
  if (FLOAT_803e02e0 < FLOAT_803db87c) {
    FLOAT_803db87c = FLOAT_803e02e8;
  }
  DAT_803dd3f0 = DAT_803dd3f0 + (uint)DAT_803db410 * 100;
  if (0x7fff < DAT_803dd3f0) {
    DAT_803dd3f0 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803e0308 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd3f0 ^
                                                                 0x80000000) - DOUBLE_803e0300)) /
                                       FLOAT_803e030c));
  FLOAT_803dd3fc = (float)dVar1;
  DAT_803dd3f4 = DAT_803dd3f4 + (uint)DAT_803db410 * 0x32;
  if (0x7fff < DAT_803dd3f4) {
    DAT_803dd3f4 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803e0308 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd3f4 ^
                                                                 0x80000000) - DOUBLE_803e0300)) /
                                       FLOAT_803e030c));
  FLOAT_803dd3f8 = (float)dVar1;
  return;
}

