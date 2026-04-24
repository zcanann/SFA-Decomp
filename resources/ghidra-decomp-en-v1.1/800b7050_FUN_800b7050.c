// Function: FUN_800b7050
// Entry: 800b7050
// Size: 296 bytes

void FUN_800b7050(void)

{
  double dVar1;
  
  FLOAT_803dc428 = FLOAT_803dc428 + FLOAT_803e04f0 * FLOAT_803dc074;
  if (FLOAT_803e04f8 < FLOAT_803dc428) {
    FLOAT_803dc428 = FLOAT_803e04f4;
  }
  FLOAT_803dc42c = FLOAT_803dc42c + FLOAT_803e04f0 * FLOAT_803dc074;
  if (FLOAT_803e04f8 < FLOAT_803dc42c) {
    FLOAT_803dc42c = FLOAT_803e0500;
  }
  DAT_803ddfb8 = DAT_803ddfb8 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddfb8) {
    DAT_803ddfb8 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfc4 = (float)dVar1;
  DAT_803ddfbc = DAT_803ddfbc + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddfbc) {
    DAT_803ddfbc = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfc0 = (float)dVar1;
  return;
}

