// Function: FUN_8029312c
// Entry: 8029312c
// Size: 116 bytes

double FUN_8029312c(double param_1)

{
  float fVar1;
  float fVar2;
  
  fVar1 = FLOAT_803e7c70;
  if ((double)FLOAT_803e7c70 != param_1) {
    fVar2 = (float)(1.0 / SQRT(param_1));
    fVar1 = (float)((double)FLOAT_803e7c74 * param_1);
    fVar2 = fVar2 * -(fVar2 * fVar1 * fVar2 - FLOAT_803e7c78);
    fVar2 = fVar2 * -(fVar2 * fVar1 * fVar2 - FLOAT_803e7c78);
    fVar1 = (float)((double)(fVar2 * -(fVar2 * fVar1 * fVar2 - FLOAT_803e7c78)) * param_1);
  }
  return (double)fVar1;
}

