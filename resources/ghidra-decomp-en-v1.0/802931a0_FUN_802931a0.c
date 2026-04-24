// Function: FUN_802931a0
// Entry: 802931a0
// Size: 84 bytes

double FUN_802931a0(double param_1)

{
  float fVar1;
  
  fVar1 = FLOAT_803e7c70;
  if ((double)FLOAT_803e7c70 != param_1) {
    fVar1 = (float)(1.0 / SQRT(param_1));
    fVar1 = (float)((double)(fVar1 * -(fVar1 * (float)((double)FLOAT_803e7c74 * param_1) * fVar1 -
                                      FLOAT_803e7c78)) * param_1);
  }
  return (double)fVar1;
}

