// Function: FUN_80109d44
// Entry: 80109d44
// Size: 84 bytes

void FUN_80109d44(void)

{
  if (DAT_803de1c8 == (float *)0x0) {
    DAT_803de1c8 = (float *)FUN_80023d8c(8,0xf);
  }
  *DAT_803de1c8 = FLOAT_803e24f0;
  DAT_803de1c8[1] = FLOAT_803e24c0;
  return;
}

