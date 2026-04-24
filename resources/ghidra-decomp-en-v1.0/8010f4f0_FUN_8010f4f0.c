// Function: FUN_8010f4f0
// Entry: 8010f4f0
// Size: 72 bytes

void FUN_8010f4f0(void)

{
  if (DAT_803dd590 == 0) {
    DAT_803dd590 = FUN_80023cc8(8,0xf,0);
  }
  *(float *)(DAT_803dd590 + 4) = FLOAT_803e1a88;
  return;
}

