// Function: FUN_80056b8c
// Entry: 80056b8c
// Size: 48 bytes

void FUN_80056b8c(int param_1,float *param_2,float *param_3)

{
  float fVar1;
  
  fVar1 = FLOAT_803debc8;
  *param_2 = *(float *)(DAT_803dce68 + param_1 * 0x10) / FLOAT_803debc8;
  *param_3 = *(float *)(DAT_803dce68 + param_1 * 0x10 + 4) / fVar1;
  return;
}

