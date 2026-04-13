// Function: FUN_80022714
// Entry: 80022714
// Size: 124 bytes

void FUN_80022714(float *param_1,float *param_2,float *param_3)

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
  fVar2 = param_2[1];
  fVar3 = param_2[2];
  fVar4 = param_1[1];
  fVar5 = param_1[5];
  fVar6 = param_1[9];
  *param_3 = fVar1 * *param_1 + fVar2 * param_1[4] + fVar3 * param_1[8];
  fVar7 = param_1[2];
  fVar8 = param_1[6];
  fVar9 = param_1[10];
  param_3[1] = fVar1 * fVar4 + fVar2 * fVar5 + fVar3 * fVar6;
  param_3[2] = fVar1 * fVar7 + fVar2 * fVar8 + fVar3 * fVar9;
  return;
}

