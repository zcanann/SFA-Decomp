// Function: FUN_800bf844
// Entry: 800bf844
// Size: 296 bytes

void FUN_800bf844(void)

{
  double dVar1;
  
  FLOAT_803db808 = FLOAT_803db808 + FLOAT_803dfcd8 * FLOAT_803db414;
  if (FLOAT_803dfce0 < FLOAT_803db808) {
    FLOAT_803db808 = FLOAT_803dfcdc;
  }
  FLOAT_803db80c = FLOAT_803db80c + FLOAT_803dfcd8 * FLOAT_803db414;
  if (FLOAT_803dfce0 < FLOAT_803db80c) {
    FLOAT_803db80c = FLOAT_803dfce8;
  }
  DAT_803dd380 = DAT_803dd380 + (uint)DAT_803db410 * 100;
  if (0x7fff < DAT_803dd380) {
    DAT_803dd380 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803dfd90 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd380 ^
                                                                 0x80000000) - DOUBLE_803dfd88)) /
                                       FLOAT_803dfd94));
  FLOAT_803dd38c = (float)dVar1;
  DAT_803dd384 = DAT_803dd384 + (uint)DAT_803db410 * 0x32;
  if (0x7fff < DAT_803dd384) {
    DAT_803dd384 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803dfd90 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd384 ^
                                                                 0x80000000) - DOUBLE_803dfd88)) /
                                       FLOAT_803dfd94));
  FLOAT_803dd388 = (float)dVar1;
  return;
}

