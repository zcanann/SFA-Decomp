// Function: FUN_800c4730
// Entry: 800c4730
// Size: 296 bytes

void FUN_800c4730(void)

{
  double dVar1;
  
  FLOAT_803db838 = FLOAT_803db838 + FLOAT_803dfeb8 * FLOAT_803db414;
  if (FLOAT_803dfec0 < FLOAT_803db838) {
    FLOAT_803db838 = FLOAT_803dfebc;
  }
  FLOAT_803db83c = FLOAT_803db83c + FLOAT_803dfeb8 * FLOAT_803db414;
  if (FLOAT_803dfec0 < FLOAT_803db83c) {
    FLOAT_803db83c = FLOAT_803dfec8;
  }
  DAT_803dd3b0 = DAT_803dd3b0 + (uint)DAT_803db410 * 100;
  if (0x7fff < DAT_803dd3b0) {
    DAT_803dd3b0 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803dff30 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd3b0 ^
                                                                 0x80000000) - DOUBLE_803dff28)) /
                                       FLOAT_803dff34));
  FLOAT_803dd3bc = (float)dVar1;
  DAT_803dd3b4 = DAT_803dd3b4 + (uint)DAT_803db410 * 0x32;
  if (0x7fff < DAT_803dd3b4) {
    DAT_803dd3b4 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803dff30 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd3b4 ^
                                                                 0x80000000) - DOUBLE_803dff28)) /
                                       FLOAT_803dff34));
  FLOAT_803dd3b8 = (float)dVar1;
  return;
}

