// Function: FUN_80118900
// Entry: 80118900
// Size: 96 bytes

undefined4 FUN_80118900(void)

{
  if ((DAT_803a5df8 != 0) && ((DAT_803a5dfc == '\x01' || (DAT_803a5dfc == '\x04')))) {
    DAT_803a5dfc = 2;
    DAT_803a5e20 = 0xffffffff;
    DAT_803a5e24 = 0xffffffff;
    DAT_803a5e28 = 0;
    DAT_803a5e2c = 0;
    return 1;
  }
  return 0;
}

