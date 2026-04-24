// Function: FUN_80080434
// Entry: 80080434
// Size: 64 bytes

undefined4 FUN_80080434(float *param_1)

{
  float fVar1;
  
  fVar1 = FLOAT_803dfc20;
  if (*param_1 != FLOAT_803dfc20) {
    *param_1 = *param_1 - FLOAT_803dc074;
    if (*param_1 <= fVar1) {
      *param_1 = fVar1;
      return 1;
    }
  }
  return 0;
}

