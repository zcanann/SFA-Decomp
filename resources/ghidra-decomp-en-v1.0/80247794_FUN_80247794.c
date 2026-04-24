// Function: FUN_80247794
// Entry: 80247794
// Size: 68 bytes

/* WARNING: Removing unreachable block (ram,0x802477a4) */
/* WARNING: Removing unreachable block (ram,0x8024779c) */
/* WARNING: Removing unreachable block (ram,0x802477d0) */

double FUN_80247794(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  double dVar5;
  
  fVar1 = (float)__psq_l0(param_1,0);
  fVar2 = (float)__psq_l1(param_1,0);
  fVar3 = (float)__psq_l0(param_1 + 8,0);
  fVar4 = fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2;
  dVar5 = 1.0 / SQRT((double)CONCAT44(fVar4,0x3f800000));
  fVar4 = (float)((ulonglong)
                  (double)(-(float)((double)(float)(dVar5 * dVar5) *
                                    (double)CONCAT44(fVar4,0x3f800000) - (double)FLOAT_803e764c) *
                          (float)(dVar5 * (double)FLOAT_803e7648)) >> 0x20);
  __psq_st0(param_2,fVar1 * fVar4,0);
  __psq_st1(param_2,fVar2 * fVar4,0);
  __psq_st0(param_2 + 8,fVar3 * fVar4,0);
  return (double)FLOAT_803e764c;
}

