// Function: FUN_800c1098
// Entry: 800c1098
// Size: 296 bytes

void FUN_800c1098(void)

{
  double dVar1;
  
  FLOAT_803db818 = FLOAT_803db818 + FLOAT_803dfd98 * FLOAT_803db414;
  if (FLOAT_803dfda0 < FLOAT_803db818) {
    FLOAT_803db818 = FLOAT_803dfd9c;
  }
  FLOAT_803db81c = FLOAT_803db81c + FLOAT_803dfd98 * FLOAT_803db414;
  if (FLOAT_803dfda0 < FLOAT_803db81c) {
    FLOAT_803db81c = FLOAT_803dfda8;
  }
  DAT_803dd390 = DAT_803dd390 + (uint)DAT_803db410 * 100;
  if (0x7fff < DAT_803dd390) {
    DAT_803dd390 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803dfe20 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd390 ^
                                                                 0x80000000) - DOUBLE_803dfe18)) /
                                       FLOAT_803dfe24));
  FLOAT_803dd39c = (float)dVar1;
  DAT_803dd394 = DAT_803dd394 + (uint)DAT_803db410 * 0x32;
  if (0x7fff < DAT_803dd394) {
    DAT_803dd394 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803dfe20 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd394 ^
                                                                 0x80000000) - DOUBLE_803dfe18)) /
                                       FLOAT_803dfe24));
  FLOAT_803dd398 = (float)dVar1;
  return;
}

