// Function: FUN_8025d7b4
// Entry: 8025d7b4
// Size: 52 bytes

/* WARNING: Removing unreachable block (ram,0x8025d7dc) */
/* WARNING: Removing unreachable block (ram,0x8025d7d4) */
/* WARNING: Removing unreachable block (ram,0x8025d7cc) */
/* WARNING: Removing unreachable block (ram,0x8025d7c4) */
/* WARNING: Removing unreachable block (ram,0x8025d7bc) */
/* WARNING: Removing unreachable block (ram,0x8025d7b4) */

void FUN_8025d7b4(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  
  fVar6 = param_1[1];
  fVar1 = param_1[2];
  fVar4 = param_1[4];
  fVar7 = param_1[5];
  fVar2 = param_1[6];
  fVar5 = param_1[8];
  fVar8 = param_1[9];
  fVar3 = param_1[10];
  *param_2 = *param_1;
  param_2[1] = fVar6;
  *param_2 = fVar1;
  *param_2 = fVar4;
  param_2[1] = fVar7;
  *param_2 = fVar2;
  *param_2 = fVar5;
  param_2[1] = fVar8;
  *param_2 = fVar3;
  return;
}

