// Function: FUN_800bd594
// Entry: 800bd594
// Size: 296 bytes

void FUN_800bd594(void)

{
  double dVar1;
  
  FLOAT_803dc448 = FLOAT_803dc448 + FLOAT_803e0860 * FLOAT_803dc074;
  if (FLOAT_803e0868 < FLOAT_803dc448) {
    FLOAT_803dc448 = FLOAT_803e0864;
  }
  FLOAT_803dc44c = FLOAT_803dc44c + FLOAT_803e0860 * FLOAT_803dc074;
  if (FLOAT_803e0868 < FLOAT_803dc44c) {
    FLOAT_803dc44c = FLOAT_803e0870;
  }
  DAT_803ddfe0 = DAT_803ddfe0 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddfe0) {
    DAT_803ddfe0 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfec = (float)dVar1;
  DAT_803ddfe4 = DAT_803ddfe4 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddfe4) {
    DAT_803ddfe4 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfe8 = (float)dVar1;
  return;
}

