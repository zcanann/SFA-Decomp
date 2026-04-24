// Function: FUN_80293900
// Entry: 80293900
// Size: 84 bytes

double FUN_80293900(double param_1)

{
  float fVar1;
  
  fVar1 = FLOAT_803e8908;
  if ((double)FLOAT_803e8908 != param_1) {
    fVar1 = (float)(1.0 / SQRT(param_1));
    fVar1 = (float)((double)(fVar1 * -(fVar1 * (float)((double)FLOAT_803e890c * param_1) * fVar1 -
                                      FLOAT_803e8910)) * param_1);
  }
  return (double)fVar1;
}

