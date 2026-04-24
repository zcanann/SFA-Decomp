// Function: FUN_802931f4
// Entry: 802931f4
// Size: 64 bytes

double FUN_802931f4(double param_1)

{
  float fVar1;
  
  fVar1 = (float)(1.0 / SQRT(param_1));
  return (double)(fVar1 * -(fVar1 * (float)((double)FLOAT_803e7c74 * param_1) * fVar1 -
                           FLOAT_803e7c78));
}

