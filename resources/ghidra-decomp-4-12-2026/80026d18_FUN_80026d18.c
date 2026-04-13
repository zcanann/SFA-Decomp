// Function: FUN_80026d18
// Entry: 80026d18
// Size: 52 bytes

void FUN_80026d18(int param_1)

{
  *(undefined *)(param_1 + 0x18) = 0;
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + FLOAT_803dc074;
  if (*(float *)(param_1 + 0x14) <= FLOAT_803df4d4) {
    return;
  }
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) - FLOAT_803df4d4;
  return;
}

