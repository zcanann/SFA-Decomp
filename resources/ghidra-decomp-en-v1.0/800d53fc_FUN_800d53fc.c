// Function: FUN_800d53fc
// Entry: 800d53fc
// Size: 296 bytes

void FUN_800d53fc(void)

{
  double dVar1;
  
  FLOAT_803db888 = FLOAT_803db888 + FLOAT_803e0310 * FLOAT_803db414;
  if (FLOAT_803e0318 < FLOAT_803db888) {
    FLOAT_803db888 = FLOAT_803e0314;
  }
  FLOAT_803db88c = FLOAT_803db88c + FLOAT_803e0310 * FLOAT_803db414;
  if (FLOAT_803e0318 < FLOAT_803db88c) {
    FLOAT_803db88c = FLOAT_803e0320;
  }
  DAT_803dd400 = DAT_803dd400 + (uint)DAT_803db410 * 100;
  if (0x7fff < DAT_803dd400) {
    DAT_803dd400 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803e0344 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd400 ^
                                                                 0x80000000) - DOUBLE_803e04d0)) /
                                       FLOAT_803e0348));
  FLOAT_803dd40c = (float)dVar1;
  DAT_803dd404 = DAT_803dd404 + (uint)DAT_803db410 * 0x32;
  if (0x7fff < DAT_803dd404) {
    DAT_803dd404 = 0;
  }
  dVar1 = (double)FUN_80293e80((double)((FLOAT_803e0344 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)(short)DAT_803dd404 ^
                                                                 0x80000000) - DOUBLE_803e04d0)) /
                                       FLOAT_803e0348));
  FLOAT_803dd408 = (float)dVar1;
  return;
}

