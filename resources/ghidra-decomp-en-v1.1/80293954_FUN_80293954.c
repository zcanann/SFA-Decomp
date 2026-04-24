// Function: FUN_80293954
// Entry: 80293954
// Size: 64 bytes

double FUN_80293954(double param_1)

{
  float fVar1;
  
  fVar1 = (float)(1.0 / SQRT(param_1));
  return (double)(fVar1 * -(fVar1 * (float)((double)FLOAT_803e890c * param_1) * fVar1 -
                           FLOAT_803e8910));
}

