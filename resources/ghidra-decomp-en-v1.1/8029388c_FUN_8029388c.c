// Function: FUN_8029388c
// Entry: 8029388c
// Size: 116 bytes

double FUN_8029388c(double param_1)

{
  float fVar1;
  float fVar2;
  
  fVar1 = FLOAT_803e8908;
  if ((double)FLOAT_803e8908 != param_1) {
    fVar2 = (float)(1.0 / SQRT(param_1));
    fVar1 = (float)((double)FLOAT_803e890c * param_1);
    fVar2 = fVar2 * -(fVar2 * fVar1 * fVar2 - FLOAT_803e8910);
    fVar2 = fVar2 * -(fVar2 * fVar1 * fVar2 - FLOAT_803e8910);
    fVar1 = (float)((double)(fVar2 * -(fVar2 * fVar1 * fVar2 - FLOAT_803e8910)) * param_1);
  }
  return (double)fVar1;
}

