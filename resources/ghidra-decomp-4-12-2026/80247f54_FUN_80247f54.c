// Function: FUN_80247f54
// Entry: 80247f54
// Size: 60 bytes

/* WARNING: Removing unreachable block (ram,0x80247f54) */

double FUN_80247f54(float *param_1)

{
  float fVar1;
  float fVar2;
  
  fVar2 = param_1[2] * param_1[2] + *param_1 * *param_1 + param_1[1] * param_1[1];
  fVar1 = 1.0 / SQRT(fVar2);
  fVar1 = -(fVar1 * fVar1 * fVar2 - FLOAT_803e82e4) * fVar1 * FLOAT_803e82e0;
  if (fVar1 < 0.0) {
    fVar1 = fVar2;
  }
  return (double)(fVar2 * fVar1);
}

