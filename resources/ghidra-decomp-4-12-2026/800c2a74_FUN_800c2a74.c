// Function: FUN_800c2a74
// Entry: 800c2a74
// Size: 296 bytes

void FUN_800c2a74(void)

{
  double dVar1;
  
  FLOAT_803dc488 = FLOAT_803dc488 + FLOAT_803e0aa8 * FLOAT_803dc074;
  if (FLOAT_803e0ab0 < FLOAT_803dc488) {
    FLOAT_803dc488 = FLOAT_803e0aac;
  }
  FLOAT_803dc48c = FLOAT_803dc48c + FLOAT_803e0aa8 * FLOAT_803dc074;
  if (FLOAT_803e0ab0 < FLOAT_803dc48c) {
    FLOAT_803dc48c = FLOAT_803e0ab8;
  }
  DAT_803de020 = DAT_803de020 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de020) {
    DAT_803de020 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de02c = (float)dVar1;
  DAT_803de024 = DAT_803de024 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de024) {
    DAT_803de024 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de028 = (float)dVar1;
  return;
}

