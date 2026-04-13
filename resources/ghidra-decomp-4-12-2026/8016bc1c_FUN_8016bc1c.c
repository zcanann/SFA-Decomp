// Function: FUN_8016bc1c
// Entry: 8016bc1c
// Size: 112 bytes

void FUN_8016bc1c(int param_1)

{
  float fVar1;
  float fVar2;
  
  fVar2 = FLOAT_803e3e70;
  fVar1 = FLOAT_803e3e70 -
          (*(float *)(*(int *)(param_1 + 0xc4) + 0x10) - *(float *)(param_1 + 0x10)) /
          **(float **)(param_1 + 0xb8);
  **(float **)(param_1 + 100) = FLOAT_803e3e74 * fVar1 + FLOAT_803e3e70;
  fVar1 = fVar1 * FLOAT_803e3e78;
  if (fVar2 < fVar1) {
    fVar1 = fVar2;
  }
  *(short *)(*(int *)(param_1 + 100) + 0x36) = (short)(int)(FLOAT_803e3e7c * fVar1);
  return;
}

