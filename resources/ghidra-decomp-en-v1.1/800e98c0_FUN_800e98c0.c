// Function: FUN_800e98c0
// Entry: 800e98c0
// Size: 64 bytes

void FUN_800e98c0(uint param_1,int param_2)

{
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a3dac)[param_1];
  }
  (&DAT_803a3c1c)[param_1] = (&DAT_803a3c1c)[param_1] & ~(1 << param_2);
  return;
}

