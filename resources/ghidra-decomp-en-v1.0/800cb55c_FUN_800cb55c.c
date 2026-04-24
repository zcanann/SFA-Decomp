// Function: FUN_800cb55c
// Entry: 800cb55c
// Size: 296 bytes

void FUN_800cb55c(void)

{
  double dVar1;
  
  FLOAT_803db858 = FLOAT_803db858 + FLOAT_803e01b8 * FLOAT_803db414;
  if (FLOAT_803e01c0 < FLOAT_803db858) {
    FLOAT_803db858 = FLOAT_803e01bc;
  }
  FLOAT_803db85c = FLOAT_803db85c + FLOAT_803e01b8 * FLOAT_803db414;
  if (FLOAT_803e01c0 < FLOAT_803db85c) {
    FLOAT_803db85c = FLOAT_803e01c8;
  }
  DAT_803dd3d0 = DAT_803dd3d0 + (uint)DAT_803db410 * 100;
  if (0x7fff < DAT_803dd3d0) {
    DAT_803dd3d0 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803e0218 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd3d0 ^
                                                                 0x80000000) - DOUBLE_803e0210)) /
                                       FLOAT_803e021c));
  FLOAT_803dd3dc = (float)dVar1;
  DAT_803dd3d4 = DAT_803dd3d4 + (uint)DAT_803db410 * 0x32;
  if (0x7fff < DAT_803dd3d4) {
    DAT_803dd3d4 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803e0218 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd3d4 ^
                                                                 0x80000000) - DOUBLE_803e0210)) /
                                       FLOAT_803e021c));
  FLOAT_803dd3d8 = (float)dVar1;
  return;
}

