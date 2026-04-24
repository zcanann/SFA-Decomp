// Function: FUN_800e963c
// Entry: 800e963c
// Size: 64 bytes

void FUN_800e963c(uint param_1,int param_2)

{
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a314c)[param_1];
  }
  (&DAT_803a2fbc)[param_1] = (&DAT_803a2fbc)[param_1] & ~(1 << param_2);
  return;
}

