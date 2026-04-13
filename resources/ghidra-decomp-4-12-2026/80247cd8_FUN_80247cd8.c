// Function: FUN_80247cd8
// Entry: 80247cd8
// Size: 84 bytes

/* WARNING: Removing unreachable block (ram,0x80247d24) */
/* WARNING: Removing unreachable block (ram,0x80247d1c) */
/* WARNING: Removing unreachable block (ram,0x80247d14) */
/* WARNING: Removing unreachable block (ram,0x80247d08) */
/* WARNING: Removing unreachable block (ram,0x80247d00) */
/* WARNING: Removing unreachable block (ram,0x80247cf8) */
/* WARNING: Removing unreachable block (ram,0x80247cf0) */
/* WARNING: Removing unreachable block (ram,0x80247ce8) */
/* WARNING: Removing unreachable block (ram,0x80247ce0) */
/* WARNING: Removing unreachable block (ram,0x80247cdc) */
/* WARNING: Removing unreachable block (ram,0x80247cd8) */

void FUN_80247cd8(float *param_1,float *param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  
  fVar1 = *param_2;
  fVar7 = param_2[1];
  fVar2 = param_1[4];
  fVar8 = param_1[5];
  fVar3 = param_1[8];
  fVar9 = param_1[9];
  fVar4 = param_2[2];
  fVar5 = param_1[6];
  fVar6 = param_1[10];
  *param_3 = param_1[2] * fVar4 + *param_1 * fVar1 + param_1[1] * fVar7;
  param_3[1] = fVar5 * fVar4 + fVar2 * fVar1 + fVar8 * fVar7;
  param_3[2] = fVar6 * fVar4 + fVar3 * fVar1 + fVar9 * fVar7;
  return;
}

