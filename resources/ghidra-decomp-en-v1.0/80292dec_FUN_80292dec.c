// Function: FUN_80292dec
// Entry: 80292dec
// Size: 52 bytes

double FUN_80292dec(double param_1)

{
  double dVar1;
  
  dVar1 = (double)(float)((double)(float)(1.0 / param_1) *
                         -(double)(float)(param_1 * (double)(float)(1.0 / param_1) -
                                         (double)FLOAT_803e7c18));
  return (double)(float)(dVar1 * -(double)(float)(param_1 * dVar1 - (double)FLOAT_803e7c18));
}

