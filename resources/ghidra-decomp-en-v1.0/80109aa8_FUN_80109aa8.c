// Function: FUN_80109aa8
// Entry: 80109aa8
// Size: 84 bytes

void FUN_80109aa8(void)

{
  if (DAT_803dd550 == (float *)0x0) {
    DAT_803dd550 = (float *)FUN_80023cc8(8,0xf,0);
  }
  *DAT_803dd550 = FLOAT_803e1870;
  DAT_803dd550[1] = FLOAT_803e1840;
  return;
}

