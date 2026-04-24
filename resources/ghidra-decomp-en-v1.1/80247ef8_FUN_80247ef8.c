// Function: FUN_80247ef8
// Entry: 80247ef8
// Size: 68 bytes

/* WARNING: Removing unreachable block (ram,0x80247f34) */
/* WARNING: Removing unreachable block (ram,0x80247f2c) */
/* WARNING: Removing unreachable block (ram,0x80247f08) */
/* WARNING: Removing unreachable block (ram,0x80247f00) */

void FUN_80247ef8(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  
  fVar1 = *param_1;
  fVar3 = param_1[1];
  fVar2 = param_1[2];
  fVar5 = fVar2 * fVar2 + fVar1 * fVar1 + fVar3 * fVar3;
  fVar4 = 1.0 / SQRT(fVar5);
  fVar4 = -(fVar4 * fVar4 * fVar5 - FLOAT_803e82e4) * fVar4 * FLOAT_803e82e0;
  *param_2 = fVar1 * fVar4;
  param_2[1] = fVar3 * fVar4;
  param_2[2] = fVar2 * fVar4;
  return;
}

