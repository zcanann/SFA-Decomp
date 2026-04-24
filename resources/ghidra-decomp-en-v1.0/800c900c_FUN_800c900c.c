// Function: FUN_800c900c
// Entry: 800c900c
// Size: 296 bytes

void FUN_800c900c(void)

{
  double dVar1;
  
  FLOAT_803db848 = FLOAT_803db848 + FLOAT_803e00a8 * FLOAT_803db414;
  if (FLOAT_803e00b0 < FLOAT_803db848) {
    FLOAT_803db848 = FLOAT_803e00ac;
  }
  FLOAT_803db84c = FLOAT_803db84c + FLOAT_803e00a8 * FLOAT_803db414;
  if (FLOAT_803e00b0 < FLOAT_803db84c) {
    FLOAT_803db84c = FLOAT_803e00b8;
  }
  DAT_803dd3c0 = DAT_803dd3c0 + (uint)DAT_803db410 * 100;
  if (0x7fff < DAT_803dd3c0) {
    DAT_803dd3c0 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803e0108 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd3c0 ^
                                                                 0x80000000) - DOUBLE_803e0100)) /
                                       FLOAT_803e010c));
  FLOAT_803dd3cc = (float)dVar1;
  DAT_803dd3c4 = DAT_803dd3c4 + (uint)DAT_803db410 * 0x32;
  if (0x7fff < DAT_803dd3c4) {
    DAT_803dd3c4 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803e0108 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd3c4 ^
                                                                 0x80000000) - DOUBLE_803e0100)) /
                                       FLOAT_803e010c));
  FLOAT_803dd3c8 = (float)dVar1;
  return;
}

