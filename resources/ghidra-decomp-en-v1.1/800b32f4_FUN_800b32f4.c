// Function: FUN_800b32f4
// Entry: 800b32f4
// Size: 296 bytes

void FUN_800b32f4(void)

{
  double dVar1;
  
  FLOAT_803dc418 = FLOAT_803dc418 + FLOAT_803e03a0 * FLOAT_803dc074;
  if (FLOAT_803e03a8 < FLOAT_803dc418) {
    FLOAT_803dc418 = FLOAT_803e03a4;
  }
  FLOAT_803dc41c = FLOAT_803dc41c + FLOAT_803e03a0 * FLOAT_803dc074;
  if (FLOAT_803e03a8 < FLOAT_803dc41c) {
    FLOAT_803dc41c = FLOAT_803e03b0;
  }
  DAT_803ddfa8 = DAT_803ddfa8 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddfa8) {
    DAT_803ddfa8 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfb4 = (float)dVar1;
  DAT_803ddfac = DAT_803ddfac + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddfac) {
    DAT_803ddfac = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfb0 = (float)dVar1;
  return;
}

