// Function: FUN_80247bf8
// Entry: 80247bf8
// Size: 84 bytes

/* WARNING: Removing unreachable block (ram,0x80247c44) */
/* WARNING: Removing unreachable block (ram,0x80247c38) */
/* WARNING: Removing unreachable block (ram,0x80247c30) */
/* WARNING: Removing unreachable block (ram,0x80247c28) */
/* WARNING: Removing unreachable block (ram,0x80247c20) */
/* WARNING: Removing unreachable block (ram,0x80247c18) */
/* WARNING: Removing unreachable block (ram,0x80247c10) */
/* WARNING: Removing unreachable block (ram,0x80247c08) */
/* WARNING: Removing unreachable block (ram,0x80247c00) */
/* WARNING: Removing unreachable block (ram,0x80247bfc) */
/* WARNING: Removing unreachable block (ram,0x80247bf8) */

void FUN_80247bf8(float *param_1,float *param_2,float *param_3)

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
  float fVar10;
  float fVar11;
  
  fVar1 = *param_2;
  fVar7 = param_2[1];
  fVar2 = param_2[2];
  fVar3 = param_1[4];
  fVar8 = param_1[5];
  fVar4 = param_1[6];
  fVar9 = param_1[7];
  *param_3 = param_1[2] * fVar2 + *param_1 * fVar1 + param_1[3] * 1.0 + param_1[1] * fVar7;
  fVar5 = param_1[8];
  fVar10 = param_1[9];
  fVar6 = param_1[10];
  fVar11 = param_1[0xb];
  param_3[1] = fVar4 * fVar2 + fVar3 * fVar1 + fVar9 * 1.0 + fVar8 * fVar7;
  param_3[2] = fVar6 * fVar2 + fVar5 * fVar1 + fVar11 * 1.0 + fVar10 * fVar7;
  return;
}

