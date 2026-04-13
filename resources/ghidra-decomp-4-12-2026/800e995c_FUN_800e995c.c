// Function: FUN_800e995c
// Entry: 800e995c
// Size: 108 bytes

void FUN_800e995c(uint param_1)

{
  uint uVar1;
  
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a3dac)[param_1];
  }
  if ((ushort)(&DAT_80312460)[param_1] != 0) {
    uVar1 = FUN_80020078((uint)(ushort)(&DAT_80312460)[param_1]);
    (&DAT_803a3c1c)[param_1] = uVar1;
  }
  return;
}

