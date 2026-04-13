// Function: FUN_8020cc64
// Entry: 8020cc64
// Size: 888 bytes

void FUN_8020cc64(void)

{
  FUN_8008999c(7,1,0);
  FLOAT_803de994 = FLOAT_803e7290;
  DAT_803de9a4 = (byte)(int)(FLOAT_803e7290 *
                             (float)((double)CONCAT44(0x43300000,
                                                      (uint)DAT_803dce68 - (uint)DAT_803dce64 ^
                                                      0x80000000) - DOUBLE_803e72a8) +
                            (float)((double)CONCAT44(0x43300000,DAT_803dce64 ^ 0x80000000) -
                                   DOUBLE_803e72a8));
  bRam803de9a5 = (byte)(int)(FLOAT_803e7290 *
                             (float)((double)CONCAT44(0x43300000,
                                                      (uint)bRam803dce69 - (uint)bRam803dce65 ^
                                                      0x80000000) - DOUBLE_803e72a8) +
                            (float)((double)CONCAT44(0x43300000,bRam803dce65 ^ 0x80000000) -
                                   DOUBLE_803e72a8));
  bRam803de9a6 = (byte)(int)(FLOAT_803e7290 *
                             (float)((double)CONCAT44(0x43300000,
                                                      (uint)bRam803dce6a - (uint)bRam803dce66 ^
                                                      0x80000000) - DOUBLE_803e72a8) +
                            (float)((double)CONCAT44(0x43300000,bRam803dce66 ^ 0x80000000) -
                                   DOUBLE_803e72a8));
  FUN_8008986c(7,DAT_803de9a4,bRam803de9a5,bRam803de9a6,0x40,0x40);
  DAT_803de9a0 = (undefined)
                 (int)(FLOAT_803de994 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)DAT_803dce60 - (uint)DAT_803dce5c ^ 0x80000000
                                               ) - DOUBLE_803e72a8) +
                      (float)((double)CONCAT44(0x43300000,DAT_803dce5c ^ 0x80000000) -
                             DOUBLE_803e72a8));
  uRam803de9a1 = (undefined)
                 (int)(FLOAT_803de994 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)bRam803dce61 - (uint)bRam803dce5d ^ 0x80000000
                                               ) - DOUBLE_803e72a8) +
                      (float)((double)CONCAT44(0x43300000,bRam803dce5d ^ 0x80000000) -
                             DOUBLE_803e72a8));
  uRam803de9a2 = (undefined)
                 (int)(FLOAT_803de994 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)bRam803dce62 - (uint)bRam803dce5e ^ 0x80000000
                                               ) - DOUBLE_803e72a8) +
                      (float)((double)CONCAT44(0x43300000,bRam803dce5e ^ 0x80000000) -
                             DOUBLE_803e72a8));
  FUN_8008979c(7,DAT_803de9a0,uRam803de9a1,uRam803de9a2);
  DAT_803de99c = (undefined)
                 (int)(FLOAT_803de994 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)DAT_803dce70 - (uint)DAT_803dce6c ^ 0x80000000
                                               ) - DOUBLE_803e72a8) +
                      (float)((double)CONCAT44(0x43300000,DAT_803dce6c ^ 0x80000000) -
                             DOUBLE_803e72a8));
  uRam803de99d = (undefined)
                 (int)(FLOAT_803de994 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)bRam803dce71 - (uint)bRam803dce6d ^ 0x80000000
                                               ) - DOUBLE_803e72a8) +
                      (float)((double)CONCAT44(0x43300000,bRam803dce6d ^ 0x80000000) -
                             DOUBLE_803e72a8));
  uRam803de99e = (undefined)
                 (int)(FLOAT_803de994 *
                       (float)((double)CONCAT44(0x43300000,
                                                (uint)bRam803dce72 - (uint)bRam803dce6e ^ 0x80000000
                                               ) - DOUBLE_803e72a8) +
                      (float)((double)CONCAT44(0x43300000,bRam803dce6e ^ 0x80000000) -
                             DOUBLE_803e72a8));
  FUN_80089804(7,DAT_803de99c,uRam803de99d,uRam803de99e);
  DAT_803de998 = (undefined)(int)(FLOAT_803de994 * FLOAT_803e7298 + FLOAT_803e7294);
  FUN_80089734((double)FLOAT_803e729c,(double)FLOAT_803e7290,(double)FLOAT_803e72a0,7);
  return;
}

