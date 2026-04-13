// Function: FUN_80247fb0
// Entry: 80247fb0
// Size: 60 bytes

/* WARNING: Removing unreachable block (ram,0x80247fe4) */
/* WARNING: Removing unreachable block (ram,0x80247fdc) */
/* WARNING: Removing unreachable block (ram,0x80247fb8) */
/* WARNING: Removing unreachable block (ram,0x80247fb0) */

void FUN_80247fb0(float *param_1,float *param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  
  fVar3 = *param_2;
  fVar5 = param_2[1];
  fVar1 = param_1[2];
  fVar4 = *param_1;
  fVar6 = param_1[1];
  fVar2 = param_2[2];
  *param_3 = fVar6 * fVar2 - fVar5 * fVar1;
  param_3[1] = -(fVar4 * fVar2 - fVar3 * fVar1);
  param_3[2] = -(fVar6 * fVar3 - fVar5 * fVar4);
  return;
}

