// Function: FUN_800c27e8
// Entry: 800c27e8
// Size: 296 bytes

void FUN_800c27e8(void)

{
  double dVar1;
  
  FLOAT_803db828 = FLOAT_803db828 + FLOAT_803dfe28 * FLOAT_803db414;
  if (FLOAT_803dfe30 < FLOAT_803db828) {
    FLOAT_803db828 = FLOAT_803dfe2c;
  }
  FLOAT_803db82c = FLOAT_803db82c + FLOAT_803dfe28 * FLOAT_803db414;
  if (FLOAT_803dfe30 < FLOAT_803db82c) {
    FLOAT_803db82c = FLOAT_803dfe38;
  }
  DAT_803dd3a0 = DAT_803dd3a0 + (uint)DAT_803db410 * 100;
  if (0x7fff < DAT_803dd3a0) {
    DAT_803dd3a0 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803dfeb0 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd3a0 ^
                                                                 0x80000000) - DOUBLE_803dfea8)) /
                                       FLOAT_803dfeb4));
  FLOAT_803dd3ac = (float)dVar1;
  DAT_803dd3a4 = DAT_803dd3a4 + (uint)DAT_803db410 * 0x32;
  if (0x7fff < DAT_803dd3a4) {
    DAT_803dd3a4 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803dfeb0 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd3a4 ^
                                                                 0x80000000) - DOUBLE_803dfea8)) /
                                       FLOAT_803dfeb4));
  FLOAT_803dd3a8 = (float)dVar1;
  return;
}

