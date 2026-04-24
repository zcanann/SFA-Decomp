// Function: FUN_8016b770
// Entry: 8016b770
// Size: 112 bytes

void FUN_8016b770(int param_1)

{
  float fVar1;
  float fVar2;
  
  fVar2 = FLOAT_803e31d8;
  fVar1 = FLOAT_803e31d8 -
          (*(float *)(*(int *)(param_1 + 0xc4) + 0x10) - *(float *)(param_1 + 0x10)) /
          **(float **)(param_1 + 0xb8);
  **(float **)(param_1 + 100) = FLOAT_803e31dc * fVar1 + FLOAT_803e31d8;
  fVar1 = fVar1 * FLOAT_803e31e0;
  if (fVar2 < fVar1) {
    fVar1 = fVar2;
  }
  *(short *)(*(int *)(param_1 + 100) + 0x36) = (short)(int)(FLOAT_803e31e4 * fVar1);
  return;
}

