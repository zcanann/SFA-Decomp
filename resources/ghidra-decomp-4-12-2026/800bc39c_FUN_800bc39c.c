// Function: FUN_800bc39c
// Entry: 800bc39c
// Size: 296 bytes

void FUN_800bc39c(void)

{
  double dVar1;
  
  FLOAT_803dc438 = FLOAT_803dc438 + FLOAT_803e0708 * FLOAT_803dc074;
  if (FLOAT_803e0710 < FLOAT_803dc438) {
    FLOAT_803dc438 = FLOAT_803e070c;
  }
  FLOAT_803dc43c = FLOAT_803dc43c + FLOAT_803e0708 * FLOAT_803dc074;
  if (FLOAT_803e0710 < FLOAT_803dc43c) {
    FLOAT_803dc43c = FLOAT_803e0718;
  }
  DAT_803ddfd0 = DAT_803ddfd0 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddfd0) {
    DAT_803ddfd0 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfdc = (float)dVar1;
  DAT_803ddfd4 = DAT_803ddfd4 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddfd4) {
    DAT_803ddfd4 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfd8 = (float)dVar1;
  return;
}

