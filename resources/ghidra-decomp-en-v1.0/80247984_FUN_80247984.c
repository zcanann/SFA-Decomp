// Function: FUN_80247984
// Entry: 80247984
// Size: 76 bytes

/* WARNING: Removing unreachable block (ram,0x80247990) */
/* WARNING: Removing unreachable block (ram,0x80247984) */
/* WARNING: Removing unreachable block (ram,0x80247988) */
/* WARNING: Removing unreachable block (ram,0x80247994) */

double FUN_80247984(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar7;
  double dVar6;
  
  fVar1 = (float)__psq_l0(param_1 + 4,0);
  fVar3 = (float)__psq_l1(param_1 + 4,0);
  fVar4 = (float)__psq_l0(param_2 + 4,0);
  fVar7 = (float)__psq_l1(param_2 + 4,0);
  fVar2 = (float)__psq_l0(param_1,0);
  __psq_l1(param_1,0);
  fVar5 = (float)__psq_l0(param_2,0);
  __psq_l1(param_2,0);
  fVar3 = (fVar3 - fVar7) * (fVar3 - fVar7);
  fVar1 = (fVar2 - fVar5) * (fVar2 - fVar5) + (fVar1 - fVar4) * (fVar1 - fVar4) + fVar3;
  dVar6 = 1.0 / SQRT((double)CONCAT44(fVar1,fVar3));
  dVar6 = (double)(-(float)((double)(float)(dVar6 * dVar6) * (double)CONCAT44(fVar1,fVar3) -
                           (double)FLOAT_803e764c) * (float)(dVar6 * (double)FLOAT_803e7648));
  if (dVar6 <= 0.0) {
    dVar6 = (double)CONCAT44(fVar1,fVar3);
  }
  return (double)(float)((double)CONCAT44(fVar1,fVar3) * dVar6);
}

