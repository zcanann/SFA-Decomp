// Function: FUN_800cce28
// Entry: 800cce28
// Size: 296 bytes

void FUN_800cce28(void)

{
  double dVar1;
  
  FLOAT_803db868 = FLOAT_803db868 + FLOAT_803e0220 * FLOAT_803db414;
  if (FLOAT_803e0228 < FLOAT_803db868) {
    FLOAT_803db868 = FLOAT_803e0224;
  }
  FLOAT_803db86c = FLOAT_803db86c + FLOAT_803e0220 * FLOAT_803db414;
  if (FLOAT_803e0228 < FLOAT_803db86c) {
    FLOAT_803db86c = FLOAT_803e0230;
  }
  DAT_803dd3e0 = DAT_803dd3e0 + (uint)DAT_803db410 * 100;
  if (0x7fff < DAT_803dd3e0) {
    DAT_803dd3e0 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803e02d0 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd3e0 ^
                                                                 0x80000000) - DOUBLE_803e02c0)) /
                                       FLOAT_803e02d4));
  FLOAT_803dd3ec = (float)dVar1;
  DAT_803dd3e4 = DAT_803dd3e4 + (uint)DAT_803db410 * 0x32;
  if (0x7fff < DAT_803dd3e4) {
    DAT_803dd3e4 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803e02d0 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd3e4 ^
                                                                 0x80000000) - DOUBLE_803e02c0)) /
                                       FLOAT_803e02d4));
  FLOAT_803dd3e8 = (float)dVar1;
  return;
}

